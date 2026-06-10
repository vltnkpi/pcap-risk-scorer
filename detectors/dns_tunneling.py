"""Детектор DNS-тунелювання.

Для кожного DNS-запиту обчислюємо:
1) довжину імені піддомена (>50 символів — підозріло);
2) ентропію Шеннона символів (>4.5 біт/символ — кодовані дані);
3) тип запису (TXT/NULL/CNAME замість домінуючих A/AAAA).

Поріг тривоги — понад 20 запитів з довжиною >50 і ентропією >4.5 від
одного хоста, АБО частка TXT/NULL понад 30% від загального DNS-трафіку
хоста.
"""
import math
from collections import Counter, defaultdict
from scapy.all import DNS, DNSQR, IP
from .base import BaseDetector, DetectorResult


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# Імена типів DNS
QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 10: "NULL", 15: "MX",
               16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 65: "HTTPS"}


class DnsTunnelingDetector(BaseDetector):
    name = "DNS-тунелювання"
    weight = 1.0
    description = "Виявляє приховане кодування даних у DNS-запитах"

    TUNNEL_QTYPES = {16, 10, 5}  # TXT, NULL, CNAME
    TUNNEL_QTYPE_RATIO_THRESHOLD = 0.30  # 30%

    def __init__(self, name_len_threshold=50, entropy_threshold=4.5,
                 suspect_request_threshold=20):
        super().__init__()
        self.stats = defaultdict(lambda: {
            "long": 0, "high_entropy": 0, "tunnel_types": 0,
            "total": 0, "examples": [], "domains": Counter(),
        })
        self.name_len_threshold = name_len_threshold
        self.entropy_threshold = entropy_threshold
        self.request_threshold = suspect_request_threshold

    def process_packet(self, packet) -> None:
        self.packets_processed += 1
        if not packet.haslayer(DNS) or not packet.haslayer(IP):
            return
        dns = packet[DNS]
        if int(dns.qr) != 0 or not packet.haslayer(DNSQR):
            return
        try:
            qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
            qtype = int(packet[DNSQR].qtype)
        except (AttributeError, UnicodeDecodeError):
            return

        src = packet[IP].src
        s = self.stats[src]
        s["total"] += 1

        # Базовий домен (останні дві мітки)
        labels = qname.split(".")
        base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else qname
        s["domains"][base_domain] += 1

        # Аналіз найдовшого піддомену
        subdomain = labels[0] if labels else qname
        suspect = False

        if len(subdomain) > self.name_len_threshold:
            s["long"] += 1
            suspect = True

        ent = shannon_entropy(subdomain)
        if ent > self.entropy_threshold:
            s["high_entropy"] += 1
            suspect = True

        if qtype in self.TUNNEL_QTYPES:
            s["tunnel_types"] += 1
            suspect = True

        if suspect and len(s["examples"]) < 5:
            s["examples"].append({
                "qname": qname[:100],
                "length": len(subdomain),
                "entropy": round(ent, 2),
                "qtype": QTYPE_NAMES.get(qtype, str(qtype)),
                "base_domain": base_domain,
            })

    def finalize(self) -> DetectorResult:
        result = DetectorResult(name=self.name, weight=self.weight)
        tunnels = []
        for src, s in self.stats.items():
            suspect_total = s["long"] + s["high_entropy"]
            tunnel_ratio = s["tunnel_types"] / s["total"] if s["total"] else 0
            
            # Поріг: масові підозрілі АБО >30% TXT/NULL
            triggered = (
                suspect_total >= self.request_threshold
                or tunnel_ratio >= self.TUNNEL_QTYPE_RATIO_THRESHOLD
            )
            if not triggered:
                continue
            
            level = min(1.0,
                        suspect_total / 100.0
                        + tunnel_ratio * 1.5)
            tunnels.append({
                "src_ip": src,
                "long_names": s["long"],
                "high_entropy_names": s["high_entropy"],
                "tunnel_qtype_count": s["tunnel_types"],
                "tunnel_qtype_ratio_pct": round(tunnel_ratio * 100, 1),
                "total_dns": s["total"],
                "top_domains": s["domains"].most_common(3),
                "examples": s["examples"],
                "level": round(level, 2),
            })

        if tunnels:
            tunnels.sort(key=lambda x: x["level"], reverse=True)
            result.suspicion = max(t["level"] for t in tunnels)
            result.findings = tunnels[:5]
            top = tunnels[0]
            top_domain = (
                top["top_domains"][0][0]
                if top["top_domains"] else "невідомий домен"
            )
            result.summary = (
                f"Виявлено {len(tunnels)} потенційних DNS-тунелів. "
                f"Джерело: {top['src_ip']} → домен {top_domain} "
                f"({top['long_names']} довгих, "
                f"{top['high_entropy_names']} високої ентропії, "
                f"{top['tunnel_qtype_ratio_pct']}% TXT/NULL)"
            )
        else:
            result.summary = "Ознак DNS-тунелювання не виявлено"
        return result
