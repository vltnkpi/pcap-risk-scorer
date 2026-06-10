"""
Базовий клас для всіх детекторів аномалій PcapRiskScorer.
Кожен детектор отримує пакети по одному та видає фінальну оцінку.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class DetectorResult:
    """Результат роботи одного детектора."""
    name: str                        # людиночитана назва
    weight: float                    # ваговий коефіцієнт у формулі агрегації
    suspicion: float = 0.0           # рівень підозри [0; 1]
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""                # короткий опис для звіту


class BaseDetector(ABC):
    """Інтерфейс детектора. Усі модулі мають його реалізувати."""

    name: str = "BaseDetector"
    weight: float = 1.0
    description: str = ""

    def __init__(self):
        self.packets_processed = 0

    @abstractmethod
    def process_packet(self, packet) -> None:
        """Обробити один пакет (виклик у циклі)."""
        ...

    @abstractmethod
    def finalize(self) -> DetectorResult:
        """Завершити аналіз і повернути результат."""
        ...
