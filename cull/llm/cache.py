from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .schema import Verdict, validate_verdict


class VerdictCache:
    def __init__(self, *, enabled: bool = True, path: Path | None = None) -> None:
        self.enabled = enabled
        self.path = path or Path.home() / ".cache" / "cull" / "verdicts.json"
        self._lock = threading.Lock()
        self._dirty = False
        self._data = self._load()

    def get(self, key: str) -> Verdict | None:
        if not self.enabled:
            return None
        with self._lock:
            raw = self._data.get(key)
        if raw is None:
            return None
        try:
            return validate_verdict(raw)
        except ValueError:
            return None

    def set(self, key: str, verdict: Verdict) -> None:
        if not self.enabled:
            return
        data = verdict.to_dict()
        with self._lock:
            self._data[key] = data
            self._dirty = True

    def flush(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            if not self._dirty:
                return
            data = dict(self._data)
            self._dirty = False

        # Last writer wins if multiple cull processes flush at once. That is
        # acceptable for v1 because cache misses are safe, only slower.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)

    def _load(self) -> dict[str, object]:
        if not self.enabled or not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}


def cache_key(chunk_text: str, *, model: str, prompt_version: str) -> str:
    import hashlib

    digest = hashlib.sha256(chunk_text.encode("utf-8", errors="replace")).hexdigest()
    return f"{digest}:{model}:{prompt_version}"
