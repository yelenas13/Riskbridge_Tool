from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import math

import pandas as pd
import yaml


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def as_float(value: Any, default: float | None = None) -> float | None:
    try:
        if value is None or pd.isna(value):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def normalize_1_to_5(value: Any, default: float | None = None) -> float | None:
    v = as_float(value, default)
    if v is None:
        return None
    return clamp((v - 1.0) / 4.0 * 100.0)


def load_yaml(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def save_json(path: str | Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")


def load_json(path: str | Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def weighted_average(values: dict[str, float | None], weights: dict[str, float]) -> float | None:
    available = [(key, value) for key, value in values.items() if value is not None]
    if not available:
        return None
    weight_sum = sum(weights[key] for key, _ in available)
    if weight_sum <= 0:
        return None
    return sum(float(value) * weights[key] for key, value in available) / weight_sum
