from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import NoReturn

from ..output import bold, dim, green, red, tprint, yellow
from .client import OpenAICompatClient
from .orchestrator import BudgetExceeded, ScanOptions, ScanResult, estimate, prepare, scan
from .schema import Estimate, PackageReport

DEFAULT_MODEL = "gemini-3.1-flash-lite-preview"
DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="+", metavar="PATH", help="node_modules or site-packages paths to scan")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--api-key-env", default="GEMINI_API_KEY")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--max-files-per-pkg", type=int, default=200)
    parser.add_argument("--chunk-tokens", type=int, default=4000)
    parser.add_argument("--chunk-overlap-tokens", type=int, default=600)
    parser.add_argument("--include-tests", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--estimate-only", action="store_true")
    parser.add_argument("--budget-usd", type=float)
    parser.add_argument("--json", action="store_true", help="write JSON to stdout")
    parser.add_argument("-o", "--output", metavar="PATH", help="write full report to a JSON or Markdown file")
    parser.add_argument("--output-format", choices=["json", "md"], help="format for --output (defaults from extension)")
    parser.add_argument("--no-progress", action="store_true", help="disable single-line progress display")


def run(args: argparse.Namespace) -> NoReturn:
    options = ScanOptions(
        include_tests=args.include_tests,
        no_cache=args.no_cache,
        concurrency=max(1, args.concurrency),
        max_files_per_pkg=max(1, args.max_files_per_pkg),
        chunk_tokens=max(1, args.chunk_tokens),
        chunk_overlap_tokens=max(0, args.chunk_overlap_tokens),
        budget_usd=args.budget_usd,
        progress=not args.no_progress and not args.json,
    )

    prepared = prepare(args.paths, options)
    estimate_result = estimate(prepared.files, model=args.model, options=options, skipped_count=prepared.skipped_count)

    if not args.json:
        _print_estimate(args.model, estimate_result, prepared.errors)

    if args.budget_usd is not None and estimate_result.estimated_cost_usd is not None:
        if estimate_result.estimated_cost_usd > args.budget_usd:
            _fail(
                args,
                f"budget exceeded by estimate: ${estimate_result.estimated_cost_usd:.4f} > ${args.budget_usd:.4f}",
                estimate_result,
            )

    if args.estimate_only:
        if args.json:
            print(json.dumps({"estimate": estimate_result.to_dict(), "errors": prepared.errors}, indent=2))
        sys.exit(2 if prepared.errors else 0)

    if not prepared.files:
        if args.json:
            print(json.dumps({"estimate": estimate_result.to_dict(), "packages": [], "errors": prepared.errors}, indent=2))
        elif not prepared.errors:
            tprint(green("no scannable package files found"))
        sys.exit(2 if prepared.errors else 0)

    api_key = _resolve_api_key(args.api_key_env)
    if not api_key:
        _fail(args, f"missing API key: set ${args.api_key_env} in env or .env", estimate_result)

    client = OpenAICompatClient(base_url=args.base_url, api_key=api_key, model=args.model)
    try:
        result = scan(files=prepared.files, estimate_result=estimate_result, client=client, options=options)
    except BudgetExceeded as error:
        _fail(args, str(error), estimate_result)

    all_errors = [*prepared.errors, *result.errors]
    if args.output:
        _write_output(Path(args.output), args.output_format, result, all_errors)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_summary(result.packages, result.cost, all_errors, args.output)

    if any(package.verdict.level == "malicious" for package in result.packages):
        sys.exit(1)
    if all_errors or any(package.verdict.level == "error" for package in result.packages):
        sys.exit(2)
    sys.exit(0)


def _print_estimate(model: str, estimate_result: Estimate, errors: list[str]) -> None:
    cost = "unknown" if estimate_result.estimated_cost_usd is None else f"${estimate_result.estimated_cost_usd:.4f}"
    tprint(bold("━━━ cull scan estimate ━━━"))
    tprint(f"packages: {estimate_result.package_count}")
    tprint(f"files:    {estimate_result.file_count} kept, {estimate_result.skipped_count} skipped")
    tprint(f"chunks:   {estimate_result.chunk_count}")
    tprint(f"tokens:   ~{estimate_result.input_tokens:,} in / ~{estimate_result.output_tokens:,} out")
    tprint(f"model:    {model}")
    tprint(f"cost:     {cost}")
    if errors:
        tprint(yellow(f"errors:   {len(errors)} path/read errors"))


def _print_summary(packages: list[PackageReport], cost: dict[str, int | float | str], errors: list[str], output: str | None) -> None:
    malicious = [package for package in packages if package.verdict.level == "malicious"]
    suspicious = [package for package in packages if package.verdict.level == "suspicious"]
    errored = [package for package in packages if package.verdict.level == "error"]
    clean = [package for package in packages if package.verdict.level == "clean"]

    tprint()
    for package in [*malicious, *suspicious][:10]:
        color = red if package.verdict.level == "malicious" else yellow
        tprint(color(f"▸ {package.package}@{package.version} ({package.ecosystem}) — {package.verdict.level}"))
        for file in [item for item in package.files if item.verdict.level != "clean"][:3]:
            tprint(f"  {file.verdict.level}  {file.file.rel_path} ({file.verdict.confidence})")
            for finding in file.verdict.findings[:2]:
                tprint(f"    {finding.indicator}: {finding.explanation}")
                if finding.snippet:
                    tprint(f"    {dim('> ' + finding.snippet)}")

    total = float(cost.get("total_usd", 0.0))
    tprint()
    malicious_part = red(f"{len(malicious)} malicious") if malicious else green("0 malicious")
    suspicious_part = yellow(f"{len(suspicious)} suspicious") if suspicious else green("0 suspicious")
    error_count = len(errored) + len(errors)
    tprint(
        bold(f"━━━ Result: {malicious_part}, {suspicious_part}, {len(clean)} clean, {error_count} errors — ${total:.4f} actual ━━━")
    )
    if output:
        tprint(dim(f"full report: {output}"))


def _write_output(path: Path, output_format: str | None, result: ScanResult, errors: list[str]) -> None:
    fmt = output_format or ("md" if path.suffix.lower() == ".md" else "json")
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "md":
        path.write_text(_markdown_report(result.packages, result.cost, errors), encoding="utf-8")
        return
    data = result.to_dict()
    data["errors"] = errors
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _fail(args: argparse.Namespace, message: str, estimate_result: Estimate) -> NoReturn:
    if args.json:
        print(json.dumps({"error": message, "estimate": estimate_result.to_dict()}, indent=2))
    else:
        print(yellow(message), file=sys.stderr)
    sys.exit(2)


def _markdown_report(packages: list[PackageReport], cost: dict[str, int | float | str], errors: list[str]) -> str:
    lines = ["# cull scan report", "", f"Cost: ${float(cost.get('total_usd', 0.0)):.4f}", ""]
    for package in packages:
        if package.verdict.level == "clean":
            continue
        lines.append(f"## {package.package}@{package.version} ({package.ecosystem}) — {package.verdict.level}")
        lines.append("")
        for file in package.files:
            if file.verdict.level == "clean":
                continue
            lines.append(f"### `{file.file.rel_path}` — {file.verdict.level} ({file.verdict.confidence})")
            for finding in file.verdict.findings:
                lines.append(f"- `{finding.indicator}`: {finding.explanation}")
                if finding.snippet:
                    lines.append(f"  - `{finding.snippet}`")
            lines.append("")
    if errors:
        lines.extend(["## Errors", "", *[f"- {error}" for error in errors]])
    return "\n".join(lines).rstrip() + "\n"


def _resolve_api_key(name: str) -> str | None:
    return os.environ.get(name) or _read_dotenv(Path(".env")).get(name)


def _read_dotenv(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values
