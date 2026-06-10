"""Детектор збігів з базою індикаторів компрометації (IoC).

Завантажує JSON-файл з відомими IP, доменами, JA3-хешами з відкритих
фідів (abuse.ch URLhaus, SSLBL, ThreatFox, MISP). Перевіряє всі IP та
DNS-запити у трафіку.

У промисловому впровадженні цей модуль читає API MISP у реальному часі.
"""
import json
import os
from collections import defaultdict
from scapy.all import IP, DNS, DNSQR
from .base import BaseDetector, DetectorResult


class IocDetector(BaseDetector):
    name = "Збіги з індикаторами компрометації (IoC)"
    weight = 1.2
    description = "Перевіряє трафік на відомі шкідливі IP та домени"

    def __init__(self, ioc_path: str = None):
        super().__init__()
        self.bad_ips = set()
        self.bad_domains = set()
        self.tags = {}  # ioc -> [tags]
        self.first_seen = {}  # ioc -> "YYYY-MM-DD"
        # hits per ioc
        self.hits = defaultdict(int)
        # examples: ioc -> [{src, dst, qname, ts}]
        self.contexts = defaultdict(list)
        self.ioc_path = ioc_path
        if ioc_path and os.path.exists(ioc_path):
            self._load(ioc_path)

    def _load(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("indicators", []):
                ioc_type = entry.get("type")
                value = entry.get("value", "").lower()
                tags = entry.get("tags", [])
                first_seen = entry.get("first_seen", "")
                if ioc_type == "ip" and value:
                    self.bad_ips.add(value)
                    self.tags[value] = tags
                    self.first_seen[value] = first_seen
                elif ioc_type == "domain" and value:
                    self.bad_domains.add(value)
                    self.tags[value] = tags
                    self.first_seen[value] = first_seen
        except (json.JSONDecodeError, IOError):
            pass

    def process_packet(self, packet) -> None:
        self.packets_processed += 1
        ts = None
        try:
            ts = float(packet.time)
        except (AttributeError, ValueError):
            pass

        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            for ip_to_check in (src, dst):
                if ip_to_check in self.bad_ips:
                    self.hits[ip_to_check] += 1
                    if len(self.contexts[ip_to_check]) < 5:
                        self.contexts[ip_to_check].append({
                            "type": "ip_traffic",
                            "src": src, "dst": dst, "ts": ts,
                        })
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
                qname_lower = qname.lower()
                for bad in self.bad_domains:
                    if qname_lower == bad or qname_lower.endswith("." + bad):
                        self.hits[bad] += 1
                        if len(self.contexts[bad]) < 5:
                            src = packet[IP].src if packet.haslayer(IP) else "?"
                            self.contexts[bad].append({
                                "type": "dns_query",
                                "src": src,
                                "qname": qname,
                                "ts": ts,
                            })
                        break
            except (AttributeError, UnicodeDecodeError):
                pass

    def finalize(self) -> DetectorResult:
        result = DetectorResult(name=self.name, weight=self.weight)
        if not self.bad_ips and not self.bad_domains:
            result.summary = "База IoC не завантажена"
            return result
        if not self.hits:
            result.summary = (
                f"Збігів з {len(self.bad_ips) + len(self.bad_domains)} IoC "
                f"не виявлено"
            )
            return result

        findings = []
        for ioc, count in sorted(self.hits.items(), key=lambda x: -x[1]):
            ioc_type = "ip" if ioc in self.bad_ips else "domain"
            findings.append({
                "ioc": ioc,
                "type": ioc_type,
                "hits": count,
                "tags": self.tags.get(ioc, []),
                "first_seen": self.first_seen.get(ioc, "невідомо"),
                "contexts": self.contexts[ioc],
            })

        result.suspicion = 1.0
        result.findings = findings[:10]
        total_hits = sum(self.hits.values())
        top = findings[0]
        tags_str = ", ".join(top["tags"]) if top["tags"] else "без тегів"
        result.summary = (
            f"Виявлено {len(findings)} збігів з IoC "
            f"({total_hits} зафіксованих звернень). "
            f"Найактивніший: {top['ioc']} [{tags_str}], "
            f"{top['hits']} хіт(ів)"
        )
        return result
