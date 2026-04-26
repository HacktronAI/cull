from __future__ import annotations

from pathlib import Path

from .schema import PackageFile

INCLUDE_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".pth", ".sh", ".bash"}
INCLUDE_NAMES = {"package.json", "setup.py", "pyproject.toml", "MANIFEST.in"}
TEST_DIRS = {"__tests__", "test", "tests", "spec"}
SKIP_EXTENSIONS = {
    ".map",
    ".d.ts",
    ".lock",
    ".so",
    ".dll",
    ".dylib",
    ".node",
    ".wasm",
    ".exe",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".zip",
    ".tar",
    ".gz",
}


def should_scan(file: PackageFile, *, include_tests: bool) -> tuple[bool, str]:
    path = file.rel_path
    name = path.name

    if file.size < 1:
        return False, "empty"
    if not include_tests and any(part in TEST_DIRS for part in path.parts):
        return False, "test file"
    if _is_doc_name(name):
        return False, "docs"
    if name.endswith(".d.ts") or path.suffix in SKIP_EXTENSIONS:
        return False, "unsupported extension"
    if name in INCLUDE_NAMES:
        return _text_file_ok(file.abs_path)
    if path.suffix not in INCLUDE_EXTENSIONS:
        return False, "unsupported extension"
    return _text_file_ok(file.abs_path)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _text_file_ok(path: Path) -> tuple[bool, str]:
    try:
        with path.open("rb") as handle:
            sample = handle.read(8192)
    except OSError as error:
        return False, f"read failed: {error}"
    if b"\x00" in sample:
        return False, "binary"
    return True, ""


def _is_doc_name(name: str) -> bool:
    lower = name.lower()
    if lower.startswith(("readme", "license", "changelog")):
        return True
    return lower.endswith((".md", ".markdown", ".rst", ".txt"))
