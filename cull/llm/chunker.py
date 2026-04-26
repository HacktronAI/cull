from __future__ import annotations

import math
from dataclasses import dataclass


CHARS_PER_TOKEN = 3.5


@dataclass(frozen=True)
class Chunk:
    index: int
    total: int
    text: str


def chunk_text(text: str, *, token_budget: int, overlap_tokens: int) -> list[Chunk]:
    if not text:
        return [Chunk(1, 1, "")]

    window = _chars_for(token_budget)
    overlap = min(_chars_for(overlap_tokens), max(0, window - 1))
    step = max(1, window - overlap)

    pieces: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + window)
        pieces.append(text[start:end])
        if end == len(text):
            break
        start += step

    total = len(pieces)
    return [Chunk(index + 1, total, piece) for index, piece in enumerate(pieces)]


def _chars_for(tokens: int) -> int:
    return max(1, math.ceil(max(0, tokens) * CHARS_PER_TOKEN))
