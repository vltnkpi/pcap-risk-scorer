"""Детектор ARP-spoofing у локальному сегменті.

Будуємо карту IP -> MAC. Якщо одна IP за час спостереження
асоціюється з більш ніж однією MAC-адресою — це або легітимний failover,
або ознака ARP-spoofing.

Виключаються легітимні випадки:
- broadcast/multicast MACs (ff:ff:ff:ff:ff:ff, 00:00:00:00:00:00);
- DHCP gratuitous ARP від адреси 0.0.0.0;
- кластерні віртуальні IP при failover (детектуються за швидким
  переключенням MAC без подальших conflicts протягом >60с).
"""
from collections import defaultdict
from scapy.all import ARP
from .base import BaseDetector, DetectorResult


class ArpAnomalyDetector(BaseDetector):
    name = "ARP-spoofing у локальному сегменті"
    weight = 0.7
    description = "Виявляє дублювання MAC для однієї IP — ознака MITM"

    BROADCAST_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
    FAILOVER_WINDOW_S = 60  # переключення в межах вікна — failover

    def __init__(self):
        super().__init__()
        # ip -> { mac -> [timestamps] }
        self.ip_mac_times = defaultdict(lambda: defaultdict(list))
        # ip -> count reply
        self.reply_count = defaultdict(int)

    def process_packet(self, packet) -> None:
        self.packets_processed += 1
        if not packet.haslayer(ARP):
            return
        arp = packet[ARP]
        if int(arp.op) != 2:
            return
        ip = arp.psrc
        mac = (arp.hwsrc or "").lower()
        # DHCP gratuitous ARP від 0.0.0.0 — легітимний
        if not ip or ip == "0.0.0.0" or ip.startswith("0."):
            return
        if not mac or mac in self.BROADCAST_MACS:
            return
        if ip == "255.255.255.255":
            return
        try:
            ts = float(packet.time)
        except (AttributeError, ValueError):
            ts = 0.0
        self.ip_mac_times[ip][mac].append(ts)
        self.reply_count[ip] += 1

    def finalize(self) -> DetectorResult:
        result = DetectorResult(name=self.name, weight=self.weight)
        conflicts = []
        for ip, macs_times in self.ip_mac_times.items():
            if len(macs_times) < 2:
                continue
            # Перевірка на failover: якщо всі MAC змінюються в межах
            # FAILOVER_WINDOW_S і потім стабільні - це failover, не атака
            all_timestamps = []
            for mac, ts_list in macs_times.items():
                all_timestamps.extend([(ts, mac) for ts in ts_list])
            all_timestamps.sort()

            # Лічимо переключення (зміни MAC у послідовності)
            switches = 0
            prev_mac = None
            for ts, mac in all_timestamps:
                if prev_mac is not None and mac != prev_mac:
                    switches += 1
                prev_mac = mac

            time_span = (
                all_timestamps[-1][0] - all_timestamps[0][0]
                if all_timestamps else 0
            )
            is_failover = switches <= 2 and time_span <= self.FAILOVER_WINDOW_S

            # Деталі MAC-конфлікту
            mac_details = []
            for mac, ts_list in macs_times.items():
                mac_details.append({
                    "mac": mac,
                    "arp_replies": len(ts_list),
                    "first_seen_ts": min(ts_list) if ts_list else 0,
                    "last_seen_ts": max(ts_list) if ts_list else 0,
                })

            if not is_failover:
                conflicts.append({
                    "ip": ip,
                    "mac_count": len(macs_times),
                    "macs": mac_details,
                    "switches": switches,
                    "arp_replies_total": self.reply_count[ip],
                })

        if conflicts:
            conflicts.sort(key=lambda x: x["arp_replies_total"], reverse=True)
            max_replies = max(c["arp_replies_total"] for c in conflicts)
            max_switches = max(c["switches"] for c in conflicts)
            base = 0.6 if len(conflicts) == 1 else 0.8
            if max_replies > 20 and max_switches > 5:
                base = 1.0
            result.suspicion = base
            result.findings = conflicts[:5]
            top = conflicts[0]
            mac_list = ", ".join(m["mac"] for m in top["macs"][:2])
            result.summary = (
                f"Виявлено {len(conflicts)} IP з кількома MAC. "
                f"Цільова IP {top['ip']}: {top['mac_count']} MAC ({mac_list}), "
                f"{top['switches']} переключень, "
                f"{top['arp_replies_total']} ARP-replies"
            )
        else:
            result.summary = "Ознак ARP-spoofing не виявлено"
        return result
