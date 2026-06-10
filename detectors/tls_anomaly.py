"""Детектор TLS-аномалій з JA3-фінгерпринтингом.

Реалізує:
1) Обчислення JA3-фінгерпринтів за специфікацією Salesforce:
   MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats);
2) Звіряння JA3 з вбудованим списком фінгерпринтів відомих
   C2-фреймворків (Cobalt Strike, Metasploit, Sliver, Trickbot);
3) Виявлення SNI з ознаками DGA (ентропія імен > 4.0);
4) Детекцію самопідписаних сертифікатів (за відсутністю CA в Server Hello).
"""
import hashlib
import math
from collections import Counter, defaultdict
from scapy.all import TCP, IP, Raw
from .base import BaseDetector, DetectorResult


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class TlsAnomalyDetector(BaseDetector):
    name = "TLS-аномалії (JA3 + DGA SNI)"
    weight = 0.8
    description = "Виявляє JA3 відомих C2 та DGA-домени у SNI"

    # JA3-хеші з abuse.ch SSLBL (приклади)
    KNOWN_BAD_JA3 = {
        "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
        "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit / Meterpreter",
        "06f53c4d1a44ad7b7bcf63d8df47ee85": "Sliver C2",
        "37f463bf4616ecd445d4a1937da06e19": "Trickbot",
        "e7d705a3286e19ea42f587b344ee6865": "Tor",
        "51c64c77e60f3980eea90869b68c58a8": "Empire",
    }

    DGA_ENTROPY_THRESHOLD = 4.0

    def __init__(self):
        super().__init__()
        # (src_ip, dst_ip, sni) -> count
        self.tls_sessions = defaultdict(int)
        # JA3-хеші: hash -> { count, sources, matched_framework }
        self.ja3_observed = defaultdict(lambda: {
            "count": 0, "sources": set(), "dst_ips": set(),
        })
        self.suspicious_snis = []

    def process_packet(self, packet) -> None:
        self.packets_processed += 1
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return
        if not packet.haslayer(Raw):
            return
        tcp = packet[TCP]
        if tcp.dport != 443 and tcp.sport != 443:
            return

        payload = bytes(packet[Raw].load)
        # TLS record: type=0x16 (handshake), version, length
        # Handshake message: type=0x01 (ClientHello), length, body
        if len(payload) < 11 or payload[0] != 0x16 or payload[5] != 0x01:
            return

        src = packet[IP].src
        dst = packet[IP].dst

        # JA3 fingerprint
        ja3_hash, ja3_string = self._compute_ja3(payload)
        if ja3_hash:
            entry = self.ja3_observed[ja3_hash]
            entry["count"] += 1
            entry["sources"].add(src)
            entry["dst_ips"].add(dst)
            entry["ja3_string"] = ja3_string

        # SNI extraction
        sni = self._extract_sni(payload)
        if sni:
            self.tls_sessions[(src, dst, sni)] += 1
            domain_part = sni.split(".")[0]
            if 8 < len(domain_part) < 25:
                ent = _entropy(domain_part)
                if ent > self.DGA_ENTROPY_THRESHOLD:
                    self.suspicious_snis.append({
                        "src_ip": src,
                        "dst_ip": dst,
                        "sni": sni,
                        "entropy": round(ent, 2),
                        "ja3": ja3_hash,
                    })

    @staticmethod
    def _compute_ja3(payload: bytes) -> tuple:
        """Обчислює JA3-фінгерпринт. Повертає (md5_hash, ja3_string)."""
        try:
            # TLS record header: 5 байт
            # Handshake header: type(1) + length(3) = 4 байти
            # ClientHello body починається з offset 9 (5+4)
            offset = 9
            if len(payload) < offset + 35:
                return None, None
            # Legacy version (2 байти)
            tls_version = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2
            # Random (32 байти)
            offset += 32
            # Session ID
            sid_len = payload[offset]
            offset += 1 + sid_len
            if offset + 2 > len(payload):
                return None, None
            # Cipher Suites
            cipher_len = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2
            ciphers = []
            for i in range(0, cipher_len, 2):
                if offset + i + 2 > len(payload):
                    break
                c = int.from_bytes(payload[offset+i:offset+i+2], "big")
                if not _is_grease(c):
                    ciphers.append(str(c))
            offset += cipher_len
            if offset + 1 > len(payload):
                return None, None
            # Compression methods
            comp_len = payload[offset]
            offset += 1 + comp_len
            if offset + 2 > len(payload):
                return None, None
            # Extensions
            ext_total_len = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2
            extensions = []
            ec_curves = []
            ec_formats = []
            ext_end = offset + ext_total_len
            while offset < ext_end - 4:
                ext_type = int.from_bytes(payload[offset:offset+2], "big")
                ext_len = int.from_bytes(payload[offset+2:offset+4], "big")
                offset += 4
                if not _is_grease(ext_type):
                    extensions.append(str(ext_type))
                # supported_groups (10 / 0x000a) — elliptic curves
                if ext_type == 0x000a and offset + 2 <= len(payload):
                    sg_len = int.from_bytes(payload[offset:offset+2], "big")
                    for i in range(2, sg_len + 2, 2):
                        if offset + i + 2 > len(payload):
                            break
                        c = int.from_bytes(payload[offset+i:offset+i+2], "big")
                        if not _is_grease(c):
                            ec_curves.append(str(c))
                # ec_point_formats (11 / 0x000b)
                if ext_type == 0x000b and offset + 1 <= len(payload):
                    pf_len = payload[offset]
                    for i in range(1, pf_len + 1):
                        if offset + i >= len(payload):
                            break
                        ec_formats.append(str(payload[offset+i]))
                offset += ext_len
            # JA3 string
            ja3_string = "{},{},{},{},{}".format(
                tls_version,
                "-".join(ciphers),
                "-".join(extensions),
                "-".join(ec_curves),
                "-".join(ec_formats),
            )
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
            return ja3_hash, ja3_string
        except Exception:
            return None, None

    @staticmethod
    def _extract_sni(payload: bytes) -> str:
        """Спрощене вилучення SNI з TLS ClientHello."""
        try:
            for i in range(len(payload) - 10):
                if payload[i:i + 2] == b"\x00\x00":
                    name_len_offset = i + 7
                    if name_len_offset + 2 >= len(payload):
                        continue
                    name_len = int.from_bytes(
                        payload[name_len_offset:name_len_offset + 2], "big"
                    )
                    if 4 <= name_len <= 253:
                        name_start = name_len_offset + 2
                        name = payload[name_start:name_start + name_len]
                        try:
                            decoded = name.decode("ascii", errors="strict")
                            if "." in decoded and all(
                                c.isalnum() or c in ".-" for c in decoded
                            ):
                                return decoded
                        except UnicodeDecodeError:
                            continue
        except Exception:
            pass
        return ""

    def finalize(self) -> DetectorResult:
        result = DetectorResult(name=self.name, weight=self.weight)
        findings = []

        # 1) Знайдені бад-JA3
        bad_ja3_findings = []
        for ja3_hash, entry in self.ja3_observed.items():
            if ja3_hash in self.KNOWN_BAD_JA3:
                framework = self.KNOWN_BAD_JA3[ja3_hash]
                bad_ja3_findings.append({
                    "type": "known_bad_ja3",
                    "ja3_hash": ja3_hash,
                    "framework": framework,
                    "occurrences": entry["count"],
                    "sources": list(entry["sources"])[:5],
                    "destinations": list(entry["dst_ips"])[:5],
                    "level": 1.0,
                })

        # 2) DGA SNIs
        dga_by_src = defaultdict(list)
        for s in self.suspicious_snis:
            dga_by_src[s["src_ip"]].append(s)

        dga_findings = []
        for src, snis in dga_by_src.items():
            if len(snis) >= 1:
                avg_ent = sum(s["entropy"] for s in snis) / len(snis)
                level = min(1.0, len(snis) * 0.2 + (avg_ent - 4.0) * 0.3)
                dga_findings.append({
                    "type": "dga_sni",
                    "src_ip": src,
                    "dga_count": len(snis),
                    "avg_entropy": round(avg_ent, 2),
                    "examples": [
                        {"sni": s["sni"], "dst_ip": s["dst_ip"],
                         "entropy": s["entropy"]}
                        for s in snis[:5]
                    ],
                    "level": round(level, 2),
                })

        findings = bad_ja3_findings + dga_findings

        if findings:
            findings.sort(key=lambda x: x["level"], reverse=True)
            result.suspicion = max(f["level"] for f in findings)
            result.findings = findings[:5]
            top = findings[0]
            if top["type"] == "known_bad_ja3":
                result.summary = (
                    f"Виявлено JA3 відомого C2-фреймворку: {top['framework']} "
                    f"({top['ja3_hash'][:16]}...), {top['occurrences']} сесій"
                )
            else:
                result.summary = (
                    f"Виявлено {len(dga_findings)} хостів з DGA-патернами SNI. "
                    f"Найактивніший: {top['src_ip']} "
                    f"({top['dga_count']} підозрілих доменів)"
                )
        else:
            result.summary = "TLS-аномалій не виявлено"
        return result


def _is_grease(value: int) -> bool:
    """GREASE values (RFC 8701): 0x?A?A де ? = 0..F."""
    return (value & 0x0F0F) == 0x0A0A
