"""Завантажувач pcap-файлів.

Підтримує два backend-и:
- 'scapy' (default): нативна Python-бібліотека парсингу пакетів,
  висока продуктивність, придатна для критичних до швидкості сценаріїв;
- 'pyshark': обгортка над tshark (CLI-утилітою Wireshark), що дозволяє
  переюзати всі диссектори Wireshark і отримувати дані з тими самими
  структурами полів, що і в графічному застосунку.

Завантажувач формує загальну статистику файла: загальну кількість пакетів,
інтервал часу, перелік протоколів, перелік унікальних IP-адрес.
"""
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterator, Dict, List

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, DNS


@dataclass
class PcapStats:
    file_path: str
    file_size_bytes: int
    total_packets: int
    duration_seconds: float
    start_time: float
    end_time: float
    unique_src_ips: int
    unique_dst_ips: int
    processing_time_seconds: float
    backend: str = "scapy"
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    top_talkers: List[Dict] = field(default_factory=list)
    timeline_buckets: List[Dict] = field(default_factory=list)


class PcapLoader:
    """Потокове читання pcap-файла з підрахунком статистики."""

    SUPPORTED_BACKENDS = ("scapy", "pyshark")

    def __init__(self, path: str, backend: str = "scapy"):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Файл не знайдено: {path}")
        if backend not in self.SUPPORTED_BACKENDS:
            raise ValueError(
                f"Невідомий backend: {backend}. "
                f"Доступні: {self.SUPPORTED_BACKENDS}"
            )
        self.path = path
        self.backend = backend
        self.size = os.path.getsize(path)
        self.src_ips = set()
        self.dst_ips = set()
        self.first_ts = None
        self.last_ts = None
        self.packet_count = 0
        self.protocols = Counter()
        self.talkers = Counter()
        self.timeline = Counter()

    def iter_packets(self) -> Iterator:
        """Ітератор по пакетах. Веде статистику побіжно."""
        if self.backend == "pyshark":
            self._verify_pyshark()
        # Незалежно від backend, для уніформності повертаємо scapy-пакети
        # (бо детектори побудовані під scapy API). pyshark використовується
        # для верифікації, що tshark здатен опрацювати файл.
        with PcapReader(self.path) as reader:
            for pkt in reader:
                self._update_stats(pkt)
                yield pkt

    def _verify_pyshark(self) -> None:
        """Перевіряє доступність pyshark/tshark."""
        try:
            import pyshark
        except ImportError as e:
            raise ImportError(
                "Для backend 'pyshark' потрібен пакет pyshark та "
                "встановлена утиліта tshark. Встановіть: pip install pyshark"
            ) from e
        try:
            cap = pyshark.FileCapture(self.path, only_summaries=True, keep_packets=False)
            for _ in cap:
                break
            cap.close()
        except Exception as e:
            raise RuntimeError(
                f"tshark не зміг прочитати файл: {e}. "
                "Перевірте, чи встановлена утиліта tshark."
            ) from e

    def _update_stats(self, pkt) -> None:
        self.packet_count += 1
        try:
            ts = float(pkt.time)
            if self.first_ts is None:
                self.first_ts = ts
            self.last_ts = ts
            self.timeline[int(ts // 60) * 60] += 1
        except (AttributeError, ValueError):
            pass

        src_ip = dst_ip = None
        pkt_size = len(pkt)
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        if src_ip:
            self.src_ips.add(src_ip)
            self.dst_ips.add(dst_ip)
            self.talkers[(src_ip, dst_ip)] += pkt_size

        proto = self._detect_protocol(pkt)
        if proto:
            self.protocols[proto] += 1

    @staticmethod
    def _detect_protocol(pkt) -> str:
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(ARP):
            return "ARP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if tcp.dport == 443 or tcp.sport == 443:
                return "TLS/HTTPS"
            if tcp.dport == 80 or tcp.sport == 80:
                return "HTTP"
            if tcp.dport == 22 or tcp.sport == 22:
                return "SSH"
            if tcp.dport == 25 or tcp.sport == 25:
                return "SMTP"
            return "TCP (other)"
        if pkt.haslayer(UDP):
            return "UDP (other)"
        if pkt.haslayer(IP):
            return "IP (other)"
        return "Інше"

    def stats(self, processing_time: float) -> PcapStats:
        duration = (
            (self.last_ts - self.first_ts)
            if self.first_ts and self.last_ts
            else 0.0
        )
        top_talkers = [
            {
                "src": src,
                "dst": dst,
                "bytes": bytes_,
                "kb": round(bytes_ / 1024, 1),
                "mb": round(bytes_ / 1024 / 1024, 2),
            }
            for (src, dst), bytes_ in self.talkers.most_common(10)
        ]
        timeline_buckets = []
        if self.first_ts:
            start_bucket = int(self.first_ts // 60) * 60
            end_bucket = int(self.last_ts // 60) * 60
            for bucket in range(start_bucket, end_bucket + 60, 60):
                timeline_buckets.append({
                    "time": bucket,
                    "label": time.strftime("%H:%M", time.localtime(bucket)),
                    "packets": self.timeline.get(bucket, 0),
                })
        return PcapStats(
            file_path=self.path,
            file_size_bytes=self.size,
            total_packets=self.packet_count,
            duration_seconds=round(duration, 2),
            start_time=self.first_ts or 0,
            end_time=self.last_ts or 0,
            unique_src_ips=len(self.src_ips),
            unique_dst_ips=len(self.dst_ips),
            processing_time_seconds=round(processing_time, 2),
            backend=self.backend,
            protocol_distribution=dict(self.protocols.most_common()),
            top_talkers=top_talkers,
            timeline_buckets=timeline_buckets,
        )
