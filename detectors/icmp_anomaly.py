"""Детектор ICMP-аномалій (приховані канали через ping).

Нормальний ping має payload 32-64 байти. ICMP з payload >64 байт ИЛИ
стабільна періодичність ICMP обміну (CV інтервалів < 0.3) — ознака
тунелю (icmpsh, ptunnel, hans).
"""
import statistics
from collections import defaultdict
from scapy.all import ICMP, IP, Raw
from .base import BaseDetector, DetectorResult


class IcmpAnomalyDetector(BaseDetector):
    name = "ICMP-аномалії (приховані канали)"
    weight = 0.5
    description = "Виявляє ICMP з аномально великим payload або періодичним обміном"

    NORMAL_PAYLOAD_MAX = 64
    SUSPICIOUS_PAYLOAD_MIN = 100
    PERIODICITY_CV_THRESHOLD = 0.3
    MIN_PACKETS_FOR_PERIODICITY = 10

    def __init__(self):
        super().__init__()
        self.flows = defaultdict(lambda: {
            "large_count": 0, "total": 0, "sizes": [],
            "timestamps": [],
        })

    def process_packet(self, packet) -> None:
        self.packets_processed += 1
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return
        src = packet[IP].src
        dst = packet[IP].dst
        key = (src, dst)
        flow = self.flows[key]
        flow["total"] += 1
        try:
            flow["timestamps"].append(float(packet.time))
        except (AttributeError, ValueError):
            pass

        if packet.haslayer(Raw):
            size = len(packet[Raw].load)
            flow["sizes"].append(size)
            if size > self.SUSPICIOUS_PAYLOAD_MIN:
                flow["large_count"] += 1

    def finalize(self) -> DetectorResult:
        result = DetectorResult(name=self.name, weight=self.weight)
        anomalies = []
        for (src, dst), flow in self.flows.items():
            if flow["total"] < self.MIN_PACKETS_FOR_PERIODICITY:
                continue
            large_ratio = (flow["large_count"] / flow["total"]
                           if flow["total"] else 0)
            avg_size = (
                round(statistics.mean(flow["sizes"]), 0)
                if flow["sizes"] else 0
            )
            max_size = max(flow["sizes"]) if flow["sizes"] else 0

            # Ознака #1: великий payload
            level = 0.0
            reason = []
            if flow["large_count"] >= 5 and large_ratio > 0.3:
                level = min(1.0, large_ratio * 1.5)
                reason.append(f"{flow['large_count']} пакетів > 100 B")

            # Ознака #2: періодичність
            cv = None
            mean_interval = None
            if len(flow["timestamps"]) >= self.MIN_PACKETS_FOR_PERIODICITY:
                ts_sorted = sorted(flow["timestamps"])
                intervals = [ts_sorted[i + 1] - ts_sorted[i]
                             for i in range(len(ts_sorted) - 1)]
                if intervals and not all(i == 0 for i in intervals):
                    mean_interval = statistics.mean(intervals)
                    if mean_interval > 0.1:
                        try:
                            stdev = statistics.stdev(intervals)
                            cv = stdev / mean_interval
                            if cv < self.PERIODICITY_CV_THRESHOLD:
                                level = max(level, 0.7)
                                reason.append(
                                    f"періодичність CV={cv:.2f}"
                                )
                        except statistics.StatisticsError:
                            pass

            if level > 0:
                anomalies.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "total_icmp": flow["total"],
                    "large_payload_count": flow["large_count"],
                    "avg_size_b": int(avg_size),
                    "max_size_b": max_size,
                    "mean_interval_s": (round(mean_interval, 2)
                                        if mean_interval else None),
                    "cv": round(cv, 3) if cv is not None else None,
                    "reason": "; ".join(reason),
                    "level": round(level, 2),
                })

        if anomalies:
            anomalies.sort(key=lambda x: x["level"], reverse=True)
            result.suspicion = max(a["level"] for a in anomalies)
            result.findings = anomalies[:5]
            top = anomalies[0]
            result.summary = (
                f"Виявлено {len(anomalies)} підозрілих ICMP-потоків. "
                f"Джерело: {top['src_ip']} → {top['dst_ip']} "
                f"(avg {top['avg_size_b']} B, max {top['max_size_b']} B, "
                f"{top['reason']})"
            )
        else:
            result.summary = "ICMP-аномалій не виявлено"
        return result
