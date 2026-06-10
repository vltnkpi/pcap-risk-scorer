"""PcapRiskScorer — інструмент автоматизованого оцінювання ризику pcap-файлів.

Author: Kaminskyi Valentyn
Version: 0.1
License: MIT | This project is licensed under the MIT License. See the LICENSE file for details.

Використання:
    python main.py <pcap_file> [-o output.html] [--ioc data/ioc.json]
                                [--backend scapy|pyshark]
"""
import argparse
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pcap_loader import PcapLoader
from aggregator import aggregate
from report import ReportGenerator
from detectors import (
    PortScanDetector,
    ArpAnomalyDetector,
    DnsTunnelingDetector,
    BeaconingDetector,
    HttpExfilDetector,
    IcmpAnomalyDetector,
    TlsAnomalyDetector,
    IocDetector,
)


__author__ = "Kaminskyi Valentyn"
__version__ = "0.1"


def build_detectors(ioc_path: str = None) -> list:
    """Створити стандартний набір з 8 детекторів."""
    return [
        PortScanDetector(),
        ArpAnomalyDetector(),
        DnsTunnelingDetector(),
        BeaconingDetector(),
        HttpExfilDetector(),
        IcmpAnomalyDetector(),
        TlsAnomalyDetector(),
        IocDetector(ioc_path=ioc_path),
    ]


def analyze(pcap_path: str, ioc_path: str = None,
            backend: str = "scapy", verbose: bool = True):
    if verbose:
        print(f"[*] PcapRiskScorer v{__version__} (Author: {__author__})")
        print(f"[*] Завантажую pcap: {pcap_path}")
        print(f"[*] Backend: {backend}")

    loader = PcapLoader(pcap_path, backend=backend)
    detectors = build_detectors(ioc_path)

    start_time = time.time()
    error_shown = set()
    for i, packet in enumerate(loader.iter_packets(), 1):
        for det in detectors:
            try:
                det.process_packet(packet)
            except Exception as e:
                if verbose and det.name not in error_shown:
                    print(f"[!] Помилка в {det.name}: {e}", file=sys.stderr)
                    error_shown.add(det.name)
        if verbose and i % 10000 == 0:
            print(f"    {i} пакетів оброблено...")

    processing_time = time.time() - start_time

    if verbose:
        print(f"[*] Оброблено {loader.packet_count} пакетів "
              f"за {processing_time:.2f} с")
        print("[*] Завершую аналіз детекторів...")

    results = []
    for det in detectors:
        result = det.finalize()
        results.append(result)
        if verbose:
            symbol = "[!]" if result.suspicion >= 0.5 else "[+]"
            print(f"  {symbol} {result.name}: підозра={result.suspicion:.2f}")

    score = aggregate(results)
    pcap_stats = loader.stats(processing_time)
    return pcap_stats, score


def main():
    parser = argparse.ArgumentParser(
        prog="PcapRiskScorer",
        description=(
            "PcapRiskScorer — автоматизоване оцінювання pcap-файлів "
            "за рівнем ризику.\n"
            "Виявляє 8 класів мережевих аномалій, обчислює інтегральний "
            "ризик-скор і генерує HTML-звіт."
        ),
        epilog=(
            f"Author: {__author__}\n"
            f"Version: {__version__}\n"
            "Приклади використання:\n"
            "  python main.py capture.pcap\n"
            "  python main.py capture.pcap -o report.html\n"
            "  python main.py capture.pcap --ioc custom_ioc.json --backend pyshark\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "pcap_file",
        help="Шлях до pcap або pcapng файла",
    )
    parser.add_argument(
        "-o", "--output",
        default="report.html",
        help="Шлях до вихідного HTML-звіту (за замовчуванням: report.html)",
    )
    parser.add_argument(
        "--ioc",
        default="data/ioc.json",
        help="Шлях до JSON-файла з IoC (за замовчуванням: data/ioc.json)",
    )
    parser.add_argument(
        "--backend",
        choices=["scapy", "pyshark"],
        default="scapy",
        help=("Backend парсингу пакетів: 'scapy' (швидко, нативно) або "
              "'pyshark' (перевірка сумісності через tshark, основна "
              "обробка через scapy) [default: scapy]"),
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Тихий режим без прогресу",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__} (Author: {__author__})",
    )
    args = parser.parse_args()

    ioc_path = args.ioc if os.path.exists(args.ioc) else None
    pcap_stats, score = analyze(
        args.pcap_file,
        ioc_path=ioc_path,
        backend=args.backend,
        verbose=not args.quiet,
    )

    if not args.quiet:
        print()
        print("=" * 60)
        print(f"  ІНТЕГРАЛЬНИЙ РИЗИК: {score.risk_score} / 100")
        print(f"  Рівень:             {score.risk_level}")
        print("=" * 60)

    generator = ReportGenerator()
    output = generator.render(pcap_stats, score, args.output)
    print(f"\n[+] Звіт збережено: {output}")
    return 0 if score.risk_score < 60 else 2


if __name__ == "__main__":
    sys.exit(main())
