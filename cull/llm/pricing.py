from __future__ import annotations

import json
import math
import re
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

RateTable = dict[str, dict[str, float]]

_DATE_SUFFIX = re.compile(r"\d{8}|\d{2}-\d{2}|\d{2}-\d{4}")


def estimate_tokens(text: str) -> int:
    return max(1, math.ceil(len(text) / 3.5))


def normalize_model_id(model_id: str) -> str:
    model = model_id.rsplit("/", 1)[-1].split("?", 1)[0]
    parts = model.split("-")
    if (model.startswith("claude-") or model.startswith("gemini-")) and _DATE_SUFFIX.fullmatch(parts[-1]):
        return "-".join(parts[:-1])
    return model


@lru_cache(maxsize=1)
def load_pricing() -> RateTable:
    return _load_models_dev(Path(__file__).with_name("pricing.json"))


def cost_for(
    model_id: str,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float | None:
    rates = load_pricing().get(normalize_model_id(model_id))
    if rates is None:
        return None

    input_rate = rates["input"]
    output_rate = rates["output"]
    # If a provider does not publish cache-specific rates, charge cache tokens
    # at normal input rate rather than undercounting them as free.
    cache_read_rate = rates.get("cache_read", input_rate)
    cache_write_rate = rates.get("cache_write", input_rate)

    return (
        input_tokens * input_rate
        + output_tokens * output_rate
        + cache_read_tokens * cache_read_rate
        + cache_write_tokens * cache_write_rate
    ) / 1_000_000


@dataclass
class RunCost:
    model_id: str
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    total_usd: float = 0.0

    def __post_init__(self) -> None:
        self._lock = threading.Lock()

    def add(
        self,
        *,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> None:
        cost = cost_for(self.model_id, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens) or 0.0
        with self._lock:
            self.calls += 1
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens
            self.cache_read_tokens += cache_read_tokens
            self.cache_write_tokens += cache_write_tokens
            self.total_usd += cost

    def summary(self) -> dict[str, int | float | str]:
        with self._lock:
            return {
                "model": self.model_id,
                "calls": self.calls,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "cache_read_tokens": self.cache_read_tokens,
                "cache_write_tokens": self.cache_write_tokens,
                "total_usd": self.total_usd,
            }


def _load_models_dev(path: Path) -> RateTable:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    pricing: RateTable = {}
    if not isinstance(data, dict):
        return pricing

    for provider in data.values():
        if not isinstance(provider, dict):
            continue
        models = provider.get("models")
        if not isinstance(models, dict):
            continue
        for raw_model, model_info in models.items():
            if not isinstance(raw_model, str) or not isinstance(model_info, dict):
                continue
            cost = model_info.get("cost")
            if not isinstance(cost, dict):
                continue
            input_cost = cost.get("input")
            output_cost = cost.get("output")
            if not isinstance(input_cost, (int, float)) or not isinstance(output_cost, (int, float)):
                continue
            row = {"input": float(input_cost), "output": float(output_cost)}
            if isinstance(cost.get("cache_read"), (int, float)):
                row["cache_read"] = float(cost["cache_read"])
            if isinstance(cost.get("cache_write"), (int, float)):
                row["cache_write"] = float(cost["cache_write"])
            pricing[normalize_model_id(raw_model)] = row
            pricing[raw_model] = row

    return pricing
