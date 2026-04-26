from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .cache import VerdictCache, cache_key
from .chunker import Chunk, chunk_text
from .client import OpenAICompatClient, Usage
from .discover import discover
from .filter import read_text, should_scan
from .pricing import RunCost, cost_for, estimate_tokens
from .prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_user_prompt
from .schema import Ecosystem, Estimate, FileReport, PackageFile, PackageReport, Verdict, error_verdict, merge_verdicts

# Per-chunk output budget assumed when projecting cost or when a provider does
# not return usage. ~180 tokens covers the JSON envelope plus 1-3 findings.
ESTIMATED_OUTPUT_TOKENS = 180


@dataclass(frozen=True)
class ScanOptions:
    include_tests: bool
    no_cache: bool
    concurrency: int
    max_files_per_pkg: int
    chunk_tokens: int
    chunk_overlap_tokens: int
    budget_usd: float | None = None
    progress: bool = True


@dataclass(frozen=True)
class PreparedFiles:
    files: list[PackageFile]
    skipped_count: int
    errors: list[str]


@dataclass(frozen=True)
class ScanResult:
    estimate: Estimate
    packages: list[PackageReport]
    errors: list[str]
    cost: dict[str, int | float | str]

    def to_dict(self) -> dict[str, object]:
        return {
            "estimate": self.estimate.to_dict(),
            "packages": [package.to_dict() for package in self.packages],
            "errors": self.errors,
            "cost": self.cost,
        }


class BudgetExceeded(RuntimeError):
    pass


def prepare(paths: list[str], options: ScanOptions) -> PreparedFiles:
    discovered, errors = discover(paths)
    files: list[PackageFile] = []
    skipped = 0
    seen_real_paths: set[Path] = set()
    per_package_count: dict[tuple[str, str, str], int] = {}

    for file in discovered:
        if file.real_path in seen_real_paths:
            skipped += 1
            continue

        keep, reason = should_scan(file, include_tests=options.include_tests)
        if not keep:
            skipped += 1
            if reason.startswith("read failed"):
                errors.append(f"{file.abs_path}: {reason}")
            continue

        package_key = (file.ecosystem, file.package, file.version)
        current_count = per_package_count.get(package_key, 0)
        if current_count >= options.max_files_per_pkg:
            skipped += 1
            continue

        seen_real_paths.add(file.real_path)
        per_package_count[package_key] = current_count + 1
        files.append(file)

    return PreparedFiles(files, skipped, errors)


def estimate(files: list[PackageFile], *, model: str, options: ScanOptions, skipped_count: int = 0) -> Estimate:
    input_tokens = 0
    output_tokens = 0
    chunk_count = 0
    packages = {(file.ecosystem, file.package, file.version) for file in files}

    for file in files:
        try:
            text = read_text(file.abs_path)
        except OSError:
            continue
        chunks = _chunks(text, options)
        chunk_count += len(chunks)
        for chunk in chunks:
            user_prompt = _prompt(file, chunk)
            input_tokens += estimate_tokens(SYSTEM_PROMPT) + estimate_tokens(user_prompt)
            output_tokens += ESTIMATED_OUTPUT_TOKENS

    estimated_cost = cost_for(model, input_tokens, output_tokens)
    return Estimate(
        package_count=len(packages),
        file_count=len(files),
        skipped_count=skipped_count,
        chunk_count=chunk_count,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        estimated_cost_usd=estimated_cost,
    )


def scan(
    *,
    files: list[PackageFile],
    estimate_result: Estimate,
    client: OpenAICompatClient,
    options: ScanOptions,
) -> ScanResult:
    cache = VerdictCache(enabled=not options.no_cache)
    cost = RunCost(client.model)
    progress = Progress(total=len(files), enabled=options.progress)
    reports: list[FileReport] = []
    errors: list[str] = []

    try:
        with ThreadPoolExecutor(max_workers=options.concurrency) as pool:
            futures = [pool.submit(_scan_file, file, client, cache, cost, options) for file in files]
            for future in as_completed(futures):
                try:
                    report = future.result()
                except Exception as error:  # keep scanning other files
                    errors.append(str(error))
                    progress.tick(error=True, cost=cost.total_usd)
                    continue

                reports.append(report)
                progress.tick(report=report, cost=cost.total_usd)
                if options.budget_usd is not None and cost.total_usd > options.budget_usd:
                    for pending in futures:
                        pending.cancel()
                    raise BudgetExceeded(f"budget exceeded: ${cost.total_usd:.4f} > ${options.budget_usd:.4f}")
    finally:
        cache.flush()
        progress.finish()

    package_reports = _package_reports(reports)
    return ScanResult(estimate_result, package_reports, errors, cost.summary())


def _scan_file(
    file: PackageFile,
    client: OpenAICompatClient,
    cache: VerdictCache,
    cost: RunCost,
    options: ScanOptions,
) -> FileReport:
    text = read_text(file.abs_path)
    chunks = _chunks(text, options)
    verdicts: list[Verdict] = []
    cached_chunks = 0

    for chunk in chunks:
        key = cache_key(chunk.text, model=client.model, prompt_version=PROMPT_VERSION)
        cached = cache.get(key)
        if cached is not None:
            verdicts.append(cached)
            cached_chunks += 1
            continue

        prompt = _prompt(file, chunk)
        try:
            verdict, usage = client.classify(prompt)
        except Exception as error:
            verdict = error_verdict(str(error))
            usage = Usage(0, 0)

        if verdict.level != "error":
            cache.set(key, verdict)
        _record_cost(cost, prompt, usage)
        verdicts.append(verdict)

    return FileReport(
        file=file,
        verdict=merge_verdicts(verdicts),
        cached=cached_chunks == len(chunks),
        chunks=len(chunks),
    )


def _record_cost(cost: RunCost, prompt: str, usage: Usage) -> None:
    if usage.input_tokens or usage.output_tokens:
        cost.add(
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_tokens,
            cache_write_tokens=usage.cache_write_tokens,
        )
    else:
        cost.add(
            input_tokens=estimate_tokens(SYSTEM_PROMPT) + estimate_tokens(prompt),
            output_tokens=ESTIMATED_OUTPUT_TOKENS,
        )


def _chunks(text: str, options: ScanOptions) -> list[Chunk]:
    return chunk_text(
        text,
        token_budget=options.chunk_tokens,
        overlap_tokens=options.chunk_overlap_tokens,
    )


def _prompt(file: PackageFile, chunk: Chunk) -> str:
    return build_user_prompt(
        package=file.package,
        version=file.version,
        ecosystem=file.ecosystem,
        path=str(file.rel_path),
        chunk_index=chunk.index,
        chunk_count=chunk.total,
        code=chunk.text,
    )


def _package_reports(files: list[FileReport]) -> list[PackageReport]:
    grouped: dict[tuple[str, str, str], list[FileReport]] = {}
    for file in files:
        key = (file.file.ecosystem, file.file.package, file.file.version)
        grouped.setdefault(key, []).append(file)

    reports: list[PackageReport] = []
    for (ecosystem, package, version), file_reports in grouped.items():
        verdict = merge_verdicts([file.verdict for file in file_reports])
        reports.append(
            PackageReport(
                ecosystem=cast("Ecosystem", ecosystem),
                package=package,
                version=version,
                files=file_reports,
                verdict=verdict,
            )
        )
    return sorted(reports, key=lambda report: (report.ecosystem, report.package, report.version))


class Progress:
    def __init__(self, *, total: int, enabled: bool) -> None:
        self.total = total
        self.enabled = enabled and sys.stdout.isatty()
        self.done = 0
        self.cached = 0
        self.clean = 0
        self.suspicious = 0
        self.malicious = 0
        self.errors = 0
        self._lock = threading.Lock()

    def tick(self, *, cost: float, report: FileReport | None = None, error: bool = False) -> None:
        with self._lock:
            self.done += 1
            if error:
                self.errors += 1
            elif report is not None:
                self.cached += int(report.cached)
                self.clean += int(report.verdict.level == "clean")
                self.suspicious += int(report.verdict.level == "suspicious")
                self.malicious += int(report.verdict.level == "malicious")
                self.errors += int(report.verdict.level == "error")
            if self.enabled:
                print(f"\r{self._line(cost)}", end="", flush=True)

    def finish(self) -> None:
        if self.enabled:
            print()

    def _line(self, cost: float) -> str:
        return (
            f"scanning {self.done}/{self.total} files | cached {self.cached} | clean {self.clean} | "
            f"suspicious {self.suspicious} | malicious {self.malicious} | errors {self.errors} | ${cost:.4f}"
        )
