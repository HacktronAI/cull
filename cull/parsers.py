from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding, Target
from .output import print_error, print_found, print_pinned


def clean_version(v: str) -> str | None:
    cleaned = v.lstrip("^~>=<v")
    return cleaned or None


def parse_pkg_arg(raw: str) -> Target:
    if raw.startswith("@"):
        parts = raw[1:].split("/", 1)
        if len(parts) < 2:
            return Target(raw, None)

        scope, rest = parts
        if "@" not in rest:
            return Target(raw, None)

        name_part, version = rest.rsplit("@", 1)
        return Target(f"@{scope}/{name_part}", clean_version(version))

    if "@" in raw:
        name, version = raw.rsplit("@", 1)
        return Target(name, clean_version(version))

    return Target(raw, None)


def versions_from_npm_lock(content: str, pkg: str) -> set[str]:
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return set()

    versions: set[str] = set()

    for path, info in data.get("packages", {}).items():
        name = info.get("name", "")
        if not name and "node_modules/" in path:
            name = path.rsplit("node_modules/", 1)[-1]
        if name == pkg:
            version = info.get("version", "")
            if version:
                versions.add(version)

    versions_from_npm_v1(data.get("dependencies", {}), pkg, versions)
    return versions


def versions_from_npm_v1(deps: dict, pkg: str, versions: set[str]) -> None:
    for name, info in deps.items():
        if name == pkg:
            version = info.get("version", "")
            if version:
                versions.add(version)
        nested = info.get("dependencies")
        if nested:
            versions_from_npm_v1(nested, pkg, versions)


def versions_from_pnpm_lock(content: str, pkg: str) -> set[str]:
    escaped = re.escape(pkg)
    version_re = r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)"
    versions: set[str] = set()

    for match in re.finditer(escaped + r"@" + version_re, content):
        pos = match.start()
        if pos > 0:
            prev = content[pos - 1]
            if prev == "/" or prev.isalnum() or prev == "-":
                continue
        versions.add(match.group(1))

    for match in re.finditer(r"/" + escaped + r"/" + version_re, content):
        line_start = content.rfind("\n", 0, match.start()) + 1
        prefix = content[line_start:match.start()]
        if re.search(r"@[\w.-]+$", prefix):
            continue
        versions.add(match.group(1))

    return versions


def versions_from_yarn_lock(content: str, pkg: str) -> set[str]:
    versions: set[str] = set()
    in_pkg_block = False
    pkg_re = re.compile(r'(?:^|[\s",])' + re.escape(pkg) + r"@")

    for line in content.splitlines():
        if not line.startswith(" ") and not line.startswith("\t"):
            in_pkg_block = bool(pkg_re.search(line))
            continue
        if not in_pkg_block:
            continue
        match = re.match(r'\s+version\s+"([^"]+)"', line)
        if match:
            versions.add(match.group(1))
            in_pkg_block = False

    return versions


def strip_jsonc_trailing_commas(text: str) -> str:
    return re.sub(r",\s*([}\]])", r"\1", text)


def versions_from_bun_lock(content: str, pkg: str) -> set[str]:
    try:
        data = json.loads(strip_jsonc_trailing_commas(content))
    except (json.JSONDecodeError, ValueError):
        return set()

    versions: set[str] = set()
    for entry in data.get("packages", {}).values():
        if not isinstance(entry, list) or not entry:
            continue
        ident = entry[0]
        if not isinstance(ident, str) or "@" not in ident:
            continue
        name, version = ident.rsplit("@", 1)
        if name == pkg and version:
            versions.add(version)

    return versions


def extract_versions(content: str, pkg: str, filename: str) -> set[str]:
    if filename == "package-lock.json":
        return versions_from_npm_lock(content, pkg)
    if filename == "pnpm-lock.yaml":
        return versions_from_pnpm_lock(content, pkg)
    if filename == "yarn.lock":
        return versions_from_yarn_lock(content, pkg)
    if filename == "bun.lock":
        return versions_from_bun_lock(content, pkg)
    return set()


def read_nm_version(pkg_dir: Path) -> str | None:
    package_json = pkg_dir / "package.json"
    if not package_json.is_file():
        return None
    try:
        data = json.loads(package_json.read_text(encoding="utf-8", errors="replace"))
        return data.get("version")
    except (json.JSONDecodeError, ValueError, OSError):
        return None


def check_content(
    content: str, pkg: str, bad_version: str | None,
    source: str, location: str, filename: str,
) -> Finding | None:
    if pkg not in content:
        return None

    versions = extract_versions(content, pkg, filename)
    if not versions:
        return None

    if not bad_version:
        version_text = ", ".join(sorted(versions))
        print_found(location, version_text)
        return Finding(source, location, "found", version_text)

    if bad_version in versions:
        print_found(location, f"{pkg}@{bad_version}")
        return Finding(source, location, "found", bad_version)

    version_text = ", ".join(sorted(versions))
    print_pinned(location, version_text)
    return Finding(source, location, "pinned", version_text)


def check_content_or_error(
    content: str, pkg: str, bad_version: str | None,
    source: str, location: str, filename: str,
) -> Finding | None:
    if pkg not in content:
        return None

    result = check_content(content, pkg, bad_version, source, location, filename)
    if result is not None:
        return result

    detail = f"package mentioned but {filename} could not be parsed"
    print_error(location, detail)
    return Finding(source, location, "error", detail)
