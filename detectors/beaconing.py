"""Детектор C2-біконінгу.

Для пар «src_ip → dst_ip» з 10+ TCP-з'єднаннями обчислюємо
коефіцієнт варіації (CV = σ/μ) інтервалів між з'єднаннями.
CV < 0.3 при 30+ з'єднаннях — висока ймовірність біконінгу.
"""
import statistics
from collections import defaultdict
from scapy.all import TCP, IP
from .base import BaseDetector, DetectorResult


class BeaconingDetector(BaseDetector):
    name = "C2-біконінг командного каналу"
    weight = 1.0
    description = "Виявляє регулярні з'єднання з зовнішнім хостом (CV<0.3)"

    def __init__(self, min_connections=10, cv_threshold=0.3,
                 strong_min_connections=30):
        super().__init__()
        # (src, dst) -> { 'timestamps': [], 'dst_ports': Counter() }
        self.connections = defaultdict(lambda: {
            "timestamps": [], "dst_ports": defaultdict(int)
        })
        self.min_connections = min_connections
        self.cv_threshold = cv_threshold
        self.strong_min = strong_min_connections

    def process_packet(self, packet) -> None:
        self.packets_processed += 1
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return
        tcp = packet[TCP]
        if not (tcp.flags & 0x02 and not (tcp.flags & 0x10)):
            return
        src = packet[IP].src
        dst = packet[IP].dst
        try:
            ts = float(packet.time)
        except (AttributeError, ValueError):
            return
        if self._is_internal(dst):
            return
        key = (src, dst)
        self.connections[key]["timestamps"].append(ts)
        self.connections[key]["dst_ports"][int(tcp.dport)] += 1

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

    def finalize(self) -> DetectorResult:
        result = DetectorResult(name=self.name, weight=self.weight)
        beacons = []
        for (src, dst), data in self.connections.items():
            timestamps = data["timestamps"]
            if len(timestamps) < self.min_connections:
                continue
            timestamps.sort()
            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]
            if not intervals or all(i == 0 for i in intervals):
                continue
            mean = statistics.mean(intervals)
            if mean < 1.0:
                continue
            try:
                stdev = statistics.stdev(intervals)
            except statistics.StatisticsError:
                continue
            cv = stdev / mean if mean > 0 else float("inf")

            if cv < self.cv_threshold:
                level = (1 - cv / self.cv_threshold) * 0.7
                if len(timestamps) >= self.strong_min:
                    level += 0.3
                # Найчастіший цільовий порт
                top_port = max(data["dst_ports"].items(),
                               key=lambda x: x[1])[0]
                beacons.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": top_port,
                    "connections": len(timestamps),
                    "mean_interval_s": round(mean, 2),
                    "min_interval_s": round(min(intervals), 2),
                    "max_interval_s": round(max(intervals), 2),
                    "stdev_interval_s": round(stdev, 2),
                    "cv": round(cv, 3),
                    "duration_s": round(timestamps[-1] - timestamps[0], 0),
                    "first_seen_ts": timestamps[0],
                    "last_seen_ts": timestamps[-1],
                    "level": round(min(level, 1.0), 2),
                })

        if beacons:
            beacons.sort(key=lambda x: x["level"], reverse=True)
            result.suspicion = max(b["level"] for b in beacons)
            result.findings = beacons[:5]
            top = beacons[0]
            result.summary = (
                f"Виявлено {len(beacons)} потенційних C2-каналів. "
                f"Найсильніший: {top['src_ip']} → {top['dst_ip']}:{top['dst_port']} "
                f"({top['connections']} з'єднань, інтервал ~{top['mean_interval_s']}с ± "
                f"{top['stdev_interval_s']}с, CV={top['cv']})"
            )
        else:
            result.summary = "Ознак C2-біконінгу не виявлено"
        return result
