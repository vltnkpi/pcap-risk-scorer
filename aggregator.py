"""Агрегатор інтегрального ризик-скору.

Формула:
    R = (Σ wᵢ·Sᵢ · 100) / Σwᵢ

де R — інтегральний скор у діапазоні [0; 100],
   wᵢ — ваговий коефіцієнт i-го детектора,
   Sᵢ — рівень підозри i-го детектора в [0; 1].

Класифікація:
    0–20 — нормальний трафік
    21–40 — низький ризик
    41–60 — середній ризик
    61–80 — високий ризик
    81–100 — критичний ризик
"""
from dataclasses import dataclass
from typing import List
from detectors import DetectorResult


@dataclass
class AggregatedScore:
    risk_score: int               # 0..100
    risk_level: str               # "Нормальний"..."Критичний"
    risk_color: str               # CSS-колір для звіту
    sum_weighted: float
    sum_weights: float
    detector_results: List[DetectorResult]


def _classify(score: int) -> tuple:
    """Класифікація рівня ризику за скором."""
    if score <= 20:
        return "Нормальний", "#28a745"   # зелений
    if score <= 40:
        return "Низький", "#85c459"      # світло-зелений
    if score <= 60:
        return "Середній", "#f0b429"     # жовтий
    if score <= 80:
        return "Високий", "#e8590c"      # помаранчевий
    return "Критичний", "#dc3545"        # червоний


def aggregate(results: List[DetectorResult]) -> AggregatedScore:
    """Обчислити інтегральний скор за зваженою формулою."""
    if not results:
        return AggregatedScore(0, "Нормальний", "#28a745", 0, 0, [])

    sum_weighted = sum(r.weight * r.suspicion for r in results)
    sum_weights = sum(r.weight for r in results)
    risk_score = int(round(sum_weighted * 100 / sum_weights)) if sum_weights else 0
    risk_score = max(0, min(100, risk_score))

    level, color = _classify(risk_score)
    return AggregatedScore(
        risk_score=risk_score,
        risk_level=level,
        risk_color=color,
        sum_weighted=round(sum_weighted, 3),
        sum_weights=round(sum_weights, 3),
        detector_results=results,
    )
