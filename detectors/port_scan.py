"""Детектор сканування портів (TCP SYN scan / Nmap -sS).

Підраховуємо для кожного джерела кількість унікальних TCP-портів,
до яких надсилалися SYN-пакети без ACK. Якщо одне джерело сканує понад
50 портів і генерує понад 100 SYN-пакетів — це сильна ознака сканування.
"""
from collections import defaultdict
from scapy.all import TCP, IP
from .base import BaseDetector, DetectorResult


class PortScanDetector(BaseDetector):
    name = "Сканування портів (TCP SYN scan)"
    weight = 0.4
    description = "Виявляє масове сканування TCP-портів з одного джерела"

    def __init__(self, port_threshold=50, syn_threshold=100):
        super().__init__()
        # src_ip -> { dst_ip -> set(dst_port) }
        self.scan_map = defaultdict(lambda: defaultdict(set))
        # src_ip -> count SYN-без-ACK
        self.syn_count = defaultdict(int)
        # (src, dst) -> найперший і найостанніший timestamp сканування
        self.scan_time = defaultdict(lambda: {"first": None, "last": None})
        self.port_threshold = port_threshold
        self.syn_threshold = syn_threshold

    def process_packet(self, packet) -> None:
        self.packets_processed += 1
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return
        tcp = packet[TCP]
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):
            src = packet[IP].src
            dst = packet[IP].dst
            self.scan_map[src][dst].add(int(tcp.dport))
            self.syn_count[src] += 1
            try:
                ts = float(packet.time)
                t = self.scan_time[(src, dst)]
                if t["first"] is None or ts < t["first"]:
                    t["first"] = ts
                if t["last"] is None or ts > t["last"]:
                    t["last"] = ts
            except (AttributeError, ValueError):
                pass

    def finalize(self) -> DetectorResult:
        result = DetectorResult(name=self.name, weight=self.weight)
        scanners = []
        for src, targets in self.scan_map.items():
            total_ports = sum(len(p) for p in targets.values())
            syn_total = self.syn_count[src]
            if total_ports >= self.port_threshold and syn_total >= self.syn_threshold:
                level = min(1.0, total_ports / 500.0)
                # Деталі по цільових хостах
                target_details = []
                for dst, ports in sorted(targets.items(),
                                         key=lambda x: -len(x[1]))[:5]:
                    ports_sorted = sorted(ports)
                    t = self.scan_time.get((src, dst), {})
                    duration = None
                    if t.get("first") and t.get("last"):
                        duration = round(t["last"] - t["first"], 2)
                    target_details.append({
                        "dst_ip": dst,
                        "ports_count": len(ports),
                        "port_range": f"{ports_sorted[0]}-{ports_sorted[-1]}",
                        "sample_ports": ports_sorted[:10],
                        "duration_s": duration,
                    })
                scanners.append({
                    "src_ip": src,
                    "targets_total": len(targets),
                    "ports_scanned": total_ports,
                    "syn_packets": syn_total,
                    "level": round(level, 2),
                    "target_details": target_details,
                })

        if scanners:
            scanners.sort(key=lambda x: x["level"], reverse=True)
            result.suspicion = max(s["level"] for s in scanners)
            result.findings = scanners[:5]
            top = scanners[0]
            result.summary = (
                f"Виявлено {len(scanners)} потенційних сканерів. "
                f"Найактивніший: {top['src_ip']} → "
                f"{top['targets_total']} ціль(ей), "
                f"{top['ports_scanned']} портів за "
                f"{top['target_details'][0].get('duration_s', '?')}с"
            )
        else:
            result.summary = "Ознак сканування портів не виявлено"
        return result
