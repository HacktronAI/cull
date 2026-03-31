from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Target:
    name: str
    version: str | None

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name


Status = Literal["found", "pinned", "error"]


@dataclass(frozen=True)
class Finding:
    source: str
    location: str
    status: Status
    version: str = ""


@dataclass(frozen=True)
class RunResult:
    ok: bool
    stdout: str = ""
    detail: str = ""
