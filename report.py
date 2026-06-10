"""Генератор HTML-звіту через Jinja2.

Шаблон використовує вбудовані SVG-графіки (без зовнішніх залежностей):
- doughnut chart розподілу протоколів;
- bar chart активності пакетів у часі.

Кожна знахідка детектора розкривається з повними деталями: куди стучався
хост, які домени запитував, які JA3 спостерігались, тощо.
"""
import json
import math
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape


def _verdict_text(score) -> str:
    if score.risk_score <= 20:
        return ("Трафік не містить значущих ознак шкідливої активності. "
                "Втручання не потрібне.")
    if score.risk_score <= 40:
        return ("Виявлено окремі підозрілі патерни, але без чітких ознак "
                "компрометації. Бажаний рутинний перегляд.")
    if score.risk_score <= 60:
        return ("Виявлено значущі підозрілі патерни. Потрібен ручний аналіз "
                "з боку аналітика SOC.")
    if score.risk_score <= 80:
        return ("Виявлено сильні ознаки компрометації. Рекомендується "
                "негайне розслідування.")
    return ("Виявлено критичні індикатори активної компрометації. "
            "Потрібне термінове втручання.")


def _recommendations(score) -> list:
    recs = []
    if score.risk_score >= 60:
        recs.append("Ізолювати хости, виявлені як джерела підозрілої активності.")
        recs.append("Підняти інцидент у системі управління інцидентами "
                    "(TheHive, IRIS).")
    if score.risk_score >= 40:
        recs.append("Виконати кореляцію з журналами Active Directory та EDR.")
        recs.append("Зробити SHA-256 хеш pcap-файла та зберегти його у "
                    "архіві доказів.")
    for det in score.detector_results:
        if det.suspicion >= 0.5:
            name_lower = det.name.lower()
            if "сканування" in name_lower:
                recs.append("Блокувати джерело сканування на NGFW; "
                            "перевірити логи cron сканера; покрити логами "
                            "Suricata цей сегмент.")
            elif "ARP" in det.name:
                recs.append("Запустити ARP-аудит сегмента; увімкнути Dynamic "
                            "ARP Inspection (Cisco) або equivalent на "
                            "комутаторах; обмежити DHCP snooping.")
            elif "DNS" in det.name:
                recs.append("Блокувати C2-домен у корпоративному DNS-резолвері; "
                            "додати TXT-запити до моніторингу Suricata.")
            elif "біконінг" in name_lower:
                recs.append("Виконати криміналістичне дослідження ураженого "
                            "хоста; перевірити автозавантаження, заплановані "
                            "завдання, persistence механізми.")
            elif "ексфільтрац" in name_lower:
                recs.append("Оцінити обсяг витоку; повідомити DPO для оцінки "
                            "за GDPR (72 години); перевірити цілісність даних "
                            "у джерелі.")
            elif "ICMP" in det.name:
                recs.append("Обмежити ICMP-payload на брандмауері до 64 байт; "
                            "перевірити правила tcp/udp tunneling над ICMP.")
            elif "TLS" in det.name:
                recs.append("Запитати threat intelligence для JA3-хешу; "
                            "розшифрувати TLS-сесію через SSLKEYLOGFILE (де "
                            "можливо); перевірити сертифікати.")
            elif "IoC" in det.name:
                recs.append("Заблокувати IP та домени з IoC на всіх рівнях "
                            "захисту (NGFW, DNS, EDR); пошук інших хостів, "
                            "що зверталися до тих самих IoC за останні 90 діб.")
    seen = set()
    unique = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return unique


def _protocol_chart_data(pcap_stats) -> dict:
    """Готує дані для doughnut chart протоколів."""
    dist = pcap_stats.protocol_distribution
    if not dist:
        return {"labels": [], "values": []}
    items = sorted(dist.items(), key=lambda x: -x[1])
    top = items[:10]
    other_count = sum(v for _, v in items[10:])
    labels = [k for k, _ in top]
    values = [v for _, v in top]
    if other_count > 0:
        labels.append("Інше")
        values.append(other_count)
    return {"labels": labels, "values": values}


def _timeline_chart_data(pcap_stats) -> dict:
    """Готує дані для line chart активності."""
    buckets = pcap_stats.timeline_buckets
    if not buckets:
        return {"labels": [], "values": []}
    return {
        "labels": [b["label"] for b in buckets],
        "values": [b["packets"] for b in buckets],
    }


# Палітра кольорів для графіків
CHART_COLORS = [
    "#0c447c", "#0f6e56", "#854f0b", "#534ab7",
    "#993c1d", "#28a745", "#dc3545", "#6c757d",
    "#17a2b8", "#ffc107", "#e83e8c", "#20c997",
]


def _render_protocol_donut(data: dict) -> str:
    """Генерує SVG donut chart з легендою."""
    labels = data.get("labels", [])
    values = data.get("values", [])
    if not labels or not values or sum(values) == 0:
        return '<div style="color:#999;text-align:center;padding:20px">Немає даних</div>'
    total = sum(values)
    cx, cy = 110, 110
    r_outer, r_inner = 90, 50
    svg = ['<svg width="100%" height="240" viewBox="0 0 480 240" '
           'xmlns="http://www.w3.org/2000/svg" style="font-family:inherit">']
    start_angle = -math.pi / 2  # початок зверху
    for i, (label, value) in enumerate(zip(labels, values)):
        frac = value / total
        end_angle = start_angle + frac * 2 * math.pi
        # Координати дуги
        x1 = cx + r_outer * math.cos(start_angle)
        y1 = cy + r_outer * math.sin(start_angle)
        x2 = cx + r_outer * math.cos(end_angle)
        y2 = cy + r_outer * math.sin(end_angle)
        x3 = cx + r_inner * math.cos(end_angle)
        y3 = cy + r_inner * math.sin(end_angle)
        x4 = cx + r_inner * math.cos(start_angle)
        y4 = cy + r_inner * math.sin(start_angle)
        large_arc = 1 if frac > 0.5 else 0
        color = CHART_COLORS[i % len(CHART_COLORS)]
        path = (
            f'M {x1:.2f} {y1:.2f} '
            f'A {r_outer} {r_outer} 0 {large_arc} 1 {x2:.2f} {y2:.2f} '
            f'L {x3:.2f} {y3:.2f} '
            f'A {r_inner} {r_inner} 0 {large_arc} 0 {x4:.2f} {y4:.2f} Z'
        )
        svg.append(f'<path d="{path}" fill="{color}" />')
        start_angle = end_angle
    # Легенда справа
    legend_x = 240
    for i, (label, value) in enumerate(zip(labels, values)):
        y = 20 + i * 18
        color = CHART_COLORS[i % len(CHART_COLORS)]
        pct = round(100 * value / total, 1)
        svg.append(f'<rect x="{legend_x}" y="{y - 8}" width="11" height="11" '
                   f'fill="{color}" rx="2"/>')
        svg.append(f'<text x="{legend_x + 18}" y="{y + 1}" font-size="11" '
                   f'fill="#212529">{label} — {value} ({pct}%)</text>')
    svg.append('</svg>')
    return "".join(svg)


def _render_timeline_bars(data: dict) -> str:
    """Генерує SVG bar chart активності."""
    labels = data.get("labels", [])
    values = data.get("values", [])
    if not labels or not values or max(values) == 0:
        return '<div style="color:#999;text-align:center;padding:20px">Немає даних</div>'
    width, height = 480, 240
    margin_left, margin_bottom, margin_top, margin_right = 40, 30, 10, 10
    plot_w = width - margin_left - margin_right
    plot_h = height - margin_bottom - margin_top
    max_val = max(values)
    bar_w = plot_w / max(len(values), 1)
    svg = [f'<svg width="100%" height="{height}" viewBox="0 0 {width} {height}" '
           f'xmlns="http://www.w3.org/2000/svg" style="font-family:inherit">']
    # Осі
    svg.append(f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" '
               f'y2="{height - margin_bottom}" stroke="#dee2e6" stroke-width="1"/>')
    svg.append(f'<line x1="{margin_left}" y1="{height - margin_bottom}" '
               f'x2="{width - margin_right}" y2="{height - margin_bottom}" '
               f'stroke="#dee2e6" stroke-width="1"/>')
    # Y-осі позначки
    for i in range(5):
        y = margin_top + (plot_h * i / 4)
        val = int(max_val * (1 - i / 4))
        svg.append(f'<line x1="{margin_left}" y1="{y}" x2="{width - margin_right}" '
                   f'y2="{y}" stroke="#f1efe8" stroke-width="0.5"/>')
        svg.append(f'<text x="{margin_left - 5}" y="{y + 3}" font-size="10" '
                   f'fill="#6c757d" text-anchor="end">{val}</text>')
    # Стовпці
    for i, val in enumerate(values):
        bar_h = (val / max_val * plot_h) if max_val > 0 else 0
        x = margin_left + i * bar_w
        y = height - margin_bottom - bar_h
        w_actual = max(bar_w * 0.85, 1)
        svg.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{w_actual:.2f}" '
                   f'height="{bar_h:.2f}" fill="#0c447c" opacity="0.85"/>')
    # Підписи X (рідко, кожен 5-й або менше якщо мало)
    step = max(1, len(labels) // 8)
    for i in range(0, len(labels), step):
        x = margin_left + i * bar_w + bar_w / 2
        svg.append(f'<text x="{x:.2f}" y="{height - margin_bottom + 15}" '
                   f'font-size="10" fill="#6c757d" text-anchor="middle">'
                   f'{labels[i]}</text>')
    svg.append('</svg>')
    return "".join(svg)


class ReportGenerator:
    def __init__(self, template_dir: str = None):
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def render(self, pcap_stats, score, output_path: str) -> str:
        tpl = self.env.get_template("report.html.j2")
        pcap_name = os.path.basename(pcap_stats.file_path)
        proto_data = _protocol_chart_data(pcap_stats)
        timeline_data = _timeline_chart_data(pcap_stats)
        html = tpl.render(
            pcap_name=pcap_name,
            pcap_stats=pcap_stats,
            score=score,
            verdict_text=_verdict_text(score),
            recommendations=_recommendations(score),
            protocol_svg=_render_protocol_donut(proto_data),
            timeline_svg=_render_timeline_bars(timeline_data),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path
