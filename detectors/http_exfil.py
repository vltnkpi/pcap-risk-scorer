"""Детектор ексфільтрації даних через HTTP та великі вихідні TCP-сесії.

Принцип:
1) HTTP POST з тілом >1 МБ — велике завантаження;
2) сумарний вихідний обсяг >50 МБ від одного хоста до одного зовнішнього;
3) Звіряння домену призначення з whitelist легітимних SaaS — для
   виключення нормальних оновлень Microsoft 365, Google Workspace тощо.
"""
import re
from collections import defaultdict
from scapy.all import TCP, IP, Raw
from .base import BaseDetector, DetectorResult


HOST_RE = re.compile(rb"Host:\s*([^\r\n]+)", re.IGNORECASE)
URI_RE = re.compile(rb"^(POST|PUT)\s+(\S+)", re.IGNORECASE)


class HttpExfilDetector(BaseDetector):
    name = "Ексфільтрація даних через HTTP та великі вихідні TCP-сесії"
    weight = 0.9
    description = "Виявляє великі вихідні передачі до зовнішніх хостів"

    POST_THRESHOLD_BYTES = 1_000_000
    SESSION_THRESHOLD_BYTES = 50_000_000

    # Легітимні SaaS — пропускаємо
    WHITELIST_DOMAINS = (
        "windowsupdate.com", "microsoft.com", "office.com", "office365.com",
        "live.com", "sharepoint.com", "onedrive.com",
        "googleapis.com", "google.com", "gstatic.com", "googleusercontent.com",
        "apple.com", "icloud.com", "mzstatic.com",
        "ubuntu.com", "debian.org", "fedoraproject.org",
        "github.com", "githubusercontent.com",
    )

    def __init__(self):
        super().__init__()
        self.sessions = defaultdict(lambda: {
            "bytes_out": 0,
            "http_posts": [],   # [{size, uri, host}]
            "first_ts": None,
            "last_ts": None,
            "hosts": set(),
        })

    def process_packet(self, packet) -> None:
        self.packets_processed += 1
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return
        src = packet[IP].src
        dst = packet[IP].dst
        if not self._is_internal(src) or self._is_internal(dst):
            return

        key = (src, dst)
        session = self.sessions[key]
        try:
            ts = float(packet.time)
            if session["first_ts"] is None or ts < session["first_ts"]:
                session["first_ts"] = ts
            if session["last_ts"] is None or ts > session["last_ts"]:
                session["last_ts"] = ts
        except (AttributeError, ValueError):
            pass

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            session["bytes_out"] += len(payload)
            # POST detection
            method_match = URI_RE.match(payload[:32])
            if method_match:
                host_match = HOST_RE.search(payload[:1024])
                host = (host_match.group(1).decode(errors="replace").strip()
                        if host_match else "")
                uri = method_match.group(2).decode(errors="replace")
                session["http_posts"].append({
                    "size": len(payload),
                    "uri": uri[:80],
                    "host": host,
                })
                if host:
                    session["hosts"].add(host.lower())

    @staticmethod
    def _is_internal(ip: str) -> bool:
        if ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            try:
                octet = int(ip.split(".")[1])
                if 16 <= octet <= 31:
                    return True
            except ValueError:
                pass
        return False

    def _is_whitelisted(self, hosts: set) -> bool:
        """True, якщо ВСІ хости належать до whitelist легітимних SaaS."""
        if not hosts:
            return False
        for host in hosts:
            if not any(host.endswith(w) or w in host
                       for w in self.WHITELIST_DOMAINS):
                return False
        return True

    def finalize(self) -> DetectorResult:
        result = DetectorResult(name=self.name, weight=self.weight)
        exfil = []
        for (src, dst), data in self.sessions.items():
            if self._is_whitelisted(data["hosts"]):
                continue  # легітимний SaaS

            big_posts = [p for p in data["http_posts"]
                         if p["size"] > self.POST_THRESHOLD_BYTES]
            level = 0.0
            if data["bytes_out"] > self.SESSION_THRESHOLD_BYTES:
                level += min(0.95, data["bytes_out"] / 100_000_000 + 0.05)
            if big_posts:
                level += 0.5
                level = min(level, 1.0)
            if level > 0.3:
                duration = (
                    round(data["last_ts"] - data["first_ts"], 1)
                    if data["last_ts"] and data["first_ts"] else 0
                )
                exfil.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "bytes_out_mb": round(data["bytes_out"] / 1_000_000, 1),
                    "duration_s": duration,
                    "throughput_kbps": (
                        round(data["bytes_out"] * 8 / 1000 / duration, 1)
                        if duration > 0 else 0
                    ),
                    "large_posts_count": len(big_posts),
                    "post_examples": [
                        {"size_mb": round(p["size"] / 1_000_000, 2),
                         "uri": p["uri"],
                         "host": p["host"]}
                        for p in big_posts[:3]
                    ],
                    "hosts": list(data["hosts"])[:5],
                    "level": round(level, 2),
                })

        if exfil:
            exfil.sort(key=lambda x: x["level"], reverse=True)
            result.suspicion = max(e["level"] for e in exfil)
            result.findings = exfil[:5]
            top = exfil[0]
            host_str = top["hosts"][0] if top["hosts"] else top["dst_ip"]
            result.summary = (
                f"Виявлено {len(exfil)} підозрілих вихідних передач. "
                f"Найбільша: {top['src_ip']} → {host_str} "
                f"({top['bytes_out_mb']} МБ за {top['duration_s']}с, "
                f"{top['large_posts_count']} POST > 1 МБ)"
            )
        else:
            result.summary = "Ознак ексфільтрації не виявлено"
        return result
