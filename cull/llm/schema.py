from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

Level = Literal["clean", "suspicious", "malicious", "error"]
Confidence = Literal["low", "medium", "high"]
Ecosystem = Literal["npm", "python"]

INDICATORS = {
    "obfuscation",
    "eval_dynamic",
    "network_download",
    "network_exfil",
    "install_hook",
    "process_spawn",
    "filesystem_access",
    "credential_theft",
    "crypto_miner",
    "typosquat_behavior",
    "persistence",
    "anti_analysis",
    "suspicious_url",
    "worm_propagation",
    "destructive_payload",
    "other",
}
LEVEL_SEVERITY: dict[Level, int] = {"clean": 0, "error": 1, "suspicious": 2, "malicious": 3}
CONFIDENCE_SEVERITY: dict[Confidence, int] = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class PackageFile:
    ecosystem: Ecosystem
    package: str
    version: str
    package_root: Path
    rel_path: Path
    abs_path: Path
    real_path: Path
    size: int


@dataclass(frozen=True)
class Finding:
    indicator: str
    snippet: str
    explanation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class Verdict:
    level: Level
    confidence: Confidence
    summary: str
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "confidence": self.confidence,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class FileReport:
    file: PackageFile
    verdict: Verdict
    cached: bool
    chunks: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.file.ecosystem,
            "package": self.file.package,
            "version": self.file.version,
            "path": str(self.file.rel_path),
            "size": self.file.size,
            "cached": self.cached,
            "chunks": self.chunks,
            "verdict": self.verdict.to_dict(),
        }


@dataclass(frozen=True)
class PackageReport:
    ecosystem: Ecosystem
    package: str
    version: str
    files: list[FileReport]
    verdict: Verdict

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "verdict": self.verdict.to_dict(),
            "files": [file.to_dict() for file in self.files],
        }


@dataclass(frozen=True)
class Estimate:
    package_count: int
    file_count: int
    skipped_count: int
    chunk_count: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float | None

    def to_dict(self) -> dict[str, int | float | None]:
        return asdict(self)


def clean_verdict() -> Verdict:
    return Verdict("clean", "high", "", [])


def error_verdict(reason: str) -> Verdict:
    return Verdict("error", "low", _trim(reason, 160), [])


def validate_verdict(raw: object) -> Verdict:
    if not isinstance(raw, dict):
        raise ValueError("verdict must be an object")

    level = raw.get("level")
    confidence = raw.get("confidence")
    summary = _trim(str(raw.get("summary", "")), 400)
    findings_raw = raw.get("findings")

    if level not in {"clean", "suspicious", "malicious"}:
        raise ValueError("level must be clean, suspicious, or malicious")
    if confidence not in {"low", "medium", "high"}:
        raise ValueError("confidence must be low, medium, or high")
    if not isinstance(findings_raw, list):
        raise ValueError("findings must be a list")

    if level == "clean":
        if findings_raw:
            raise ValueError("clean verdict must not include findings")
        return Verdict("clean", confidence, "", [])

    if not 1 <= len(findings_raw) <= 5:
        raise ValueError("non-clean verdict must include 1 to 5 findings")
    if not summary:
        raise ValueError("non-clean verdict must include a summary")

    findings: list[Finding] = []
    for item in findings_raw:
        if not isinstance(item, dict):
            raise ValueError("finding must be an object")
        indicator = item.get("indicator")
        if indicator not in INDICATORS:
            raise ValueError(f"unknown indicator: {indicator}")
        explanation = _trim(str(item.get("explanation", "")), 800)
        if not explanation:
            raise ValueError("finding requires explanation")
        findings.append(
            Finding(
                indicator=str(indicator),
                snippet=_trim(str(item.get("snippet", "")), 300),
                explanation=explanation,
            )
        )

    return Verdict(level, confidence, summary, findings)


def merge_verdicts(verdicts: list[Verdict]) -> Verdict:
    if not verdicts:
        return clean_verdict()

    worst_level = max(verdicts, key=lambda verdict: LEVEL_SEVERITY[verdict.level]).level
    matching = [verdict for verdict in verdicts if verdict.level == worst_level]
    confidence = max(matching, key=lambda verdict: CONFIDENCE_SEVERITY[verdict.confidence]).confidence

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    summary = next((verdict.summary for verdict in matching if verdict.summary), "")

    for verdict in sorted(verdicts, key=_verdict_sort_key, reverse=True):
        for finding in verdict.findings:
            key = (finding.indicator, _normalize_snippet(finding.snippet))
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
            if len(findings) >= 10:
                return Verdict(worst_level, confidence, summary, findings)

    return Verdict(worst_level, confidence, summary, findings)


def _verdict_sort_key(verdict: Verdict) -> tuple[int, int]:
    return (LEVEL_SEVERITY[verdict.level], CONFIDENCE_SEVERITY[verdict.confidence])


def _trim(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def _normalize_snippet(snippet: str) -> str:
    # Best-effort dedup only. It should not be treated as semantic equivalence.
    return re.sub(r"\s+", " ", snippet[:120].strip().lower())
