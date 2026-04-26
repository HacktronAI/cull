from __future__ import annotations

import argparse
import sys

from .check import cli as check_cli
from .llm import cli as scan_cli


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cull",
        description="Find compromised packages and suspicious package code.",
        epilog="Examples:\n"
        "  cull check axios@1.14.1 axios@0.30.4 plain-crypto-js\n"
        "  cull check axios@1.14.1 --dirs ~/projects\n"
        "  cull scan ./node_modules\n"
        "  cull scan ./.venv/lib/python3.12/site-packages --estimate-only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="deterministically search for known compromised packages")
    check_cli.add_arguments(check)
    check.set_defaults(handler=check_cli.run)

    scan = subparsers.add_parser("scan", help="LLM-scan installed package source files")
    scan_cli.add_arguments(scan)
    scan.set_defaults(handler=scan_cli.run)

    return parser


def _argv_with_default_command(argv: list[str]) -> list[str]:
    if len(argv) < 2:
        return argv
    if argv[1] in {"check", "scan", "-h", "--help"}:
        return argv
    if argv[1].startswith("-"):
        return argv
    print("warning: bare `cull PKG` is deprecated; use `cull check PKG`", file=sys.stderr)
    return [argv[0], "check", *argv[1:]]


def main() -> None:
    parser = build_parser()
    args = parser.parse_args(_argv_with_default_command(sys.argv)[1:])
    args.handler(args)
