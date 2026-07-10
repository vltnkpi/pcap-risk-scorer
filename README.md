# PcapRiskScorer

**Author:** vltn
**Version:** 0.1  
**License:** MIT | This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Програмний прототип автоматизованого оцінювання pcap-файлів за рівнем ризику.  
Реалізує 8 модулів-детекторів аномалій з агрегацією за зваженою формулою та генерацією HTML-звіту.

## Можливості

8 модулів-детекторів:

1. **PortScanDetector** — TCP SYN-сканування (`w=0.4`)
2. **ArpAnomalyDetector** — ARP-spoofing у LAN, з виключенням DHCP-failover (`w=0.7`)
3. **DnsTunnelingDetector** — DNS-тунелі, ентропія Шеннона, частка TXT/NULL >30% (`w=1.0`)
4. **BeaconingDetector** — C2-біконінг через `CV=σ/μ < 0.3` (`w=1.0`)
5. **HttpExfilDetector** — ексфільтрація, з whitelist легітимних SaaS (`w=0.9`)
6. **IcmpAnomalyDetector** — ICMP-тунелі + CV періодичності (`w=0.5`)
7. **TlsAnomalyDetector** — JA3-фінгерпринтинг + DGA SNI (`w=0.8`)
8. **IocDetector** — збіги з MISP-сумісним JSON IoC (`w=1.2`)

## Встановлення

```bash
pip install -r requirements.txt
pip3 install -r requirements.txt
```

Для режиму `--backend pyshark` додатково потрібні пакет `pyshark` та встановлена утиліта `tshark`.

## Використання

```bash
python main.py <pcap_file> [-o output.html] [--ioc data/ioc.json] [--backend scapy|pyshark]
python3 main.py <pcap_file> [-o output.html] [--ioc data/ioc.json] [--backend scapy|pyshark]
```

## Параметри

| Параметр | Опис |
|---|---|
| `pcap_file` | pcap або pcapng файл (обов'язковий) |
| `-o, --output` | шлях до HTML-звіту (default: report.html) |
| `--ioc` | JSON з індикаторами компрометації (default: data/ioc.json) |
| `--backend` | backend парсингу: `scapy` (швидко, default) або `pyshark` (через tshark для перевірки сумісності; основна обробка виконується через scapy) |
| `-q, --quiet` | тихий режим |
| `-v, --version` | версія |
| `-h, --help` | довідка |

## Exit codes

| Код | Значення |
|---|---|
| `0` | нормально (ризик < 60) |
| `2` | виявлено високий або критичний ризик |

## Тестування

```bash
# 1) Згенерувати синтетичний pcap з усіма 5 атаками
python tests/generate_test_pcap.py

# 2) Запустити аналіз
python main.py tests/test_attacks.pcap -o test_report.html

# 3) Відкрити звіт
xdg-open test_report.html       # Linux
open test_report.html           # macOS
start test_report.html          # Windows
```

Очікуваний результат: ризик 75-80 ("Високий"), 6 з 8 детекторів спрацьовують.

## Формула інтегрального скору

```text
R = (Σ wᵢ·Sᵢ · 100) / Σwᵢ
```

де R — інтегральний скор у [0; 100], wᵢ — ваговий коефіцієнт, Sᵢ — рівень підозри.

## Класифікація ризику

| Скор | Рівень |
|---|---|
| 0–20 | Нормальний |
| 21–40 | Низький |
| 41–60 | Середній |
| 61–80 | Високий |
| 81–100 | Критичний |

## Архітектура

```text
PcapRiskScorer/
├── main.py                        CLI
├── pcap_loader.py                 PcapLoader з scapy/pyshark backend
├── aggregator.py                  ScoreAggregator (формула)
├── report.py                      ReportGenerator (Jinja2 + SVG)
├── requirements.txt
├── LICENSE
├── README.md
├── detectors/
│   ├── base.py                    інтерфейс BaseDetector
│   ├── port_scan.py
│   ├── arp_anomaly.py
│   ├── dns_tunneling.py
│   ├── beaconing.py
│   ├── http_exfil.py
│   ├── icmp_anomaly.py
│   ├── tls_anomaly.py
│   └── ioc.py
├── templates/
│   └── report.html.j2             шаблон HTML-звіту
├── data/
│   └── ioc.json                   тестова база IoC
└── tests/
    └── generate_test_pcap.py      генератор синтетичних атак
```

## Особливості реалізації

- Графіки в SVG inline — звіт працює офлайн без CDN-залежностей
- Детальна розкривка знахідок — кожен інцидент показує куди стучався хост, які домени запитував, JA3-хеш, обсяги тощо
- JA3-фінгерпринтинг — обчислюється згідно специфікації Salesforce
- Whitelist легітимних SaaS — фільтр нормальних оновлень Microsoft 365, Google, Apple
- Виключення DHCP-failover — щоб не приймати легітимний failover за ARP-spoof

## Обмеження

- Проєкт є програмним прототипом і не замінює повноцінні NDR, IDS, IPS або SIEM-платформи.
- Якість виявлення залежить від повноти та репрезентативності pcap-файлу.
- Для HTTPS без розшифрування аналізуються метадані, обсяги переданих даних та доступні мережеві ознаки.
- Можливі false positive та false negative спрацьовування.

## Legal and Ethical Notice

Не аналізуйте трафік, який вам не належить або на аналіз якого немає дозволу. Не завантажуйте реальні корпоративні, приватні або сторонні pcap-файли у публічні репозиторії.

## Third-party Dependencies

Вихідний код PcapRiskScorer поширюється за ліцензією MIT. Сторонні залежності поширюються за власними ліцензіями.
