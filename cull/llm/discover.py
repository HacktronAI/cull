from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
from typing import cast

from .schema import Ecosystem, PackageFile

SKIP_DIRS = {".git", ".hg", ".svn", ".cache", "__pycache__", ".pytest_cache"}


def discover(paths: list[str]) -> tuple[list[PackageFile], list[str]]:
    files: list[PackageFile] = []
    errors: list[str] = []
    seen_roots: set[Path] = set()

    for raw_path in paths:
        root = Path(raw_path).expanduser().resolve()
        if not root.is_dir():
            errors.append(f"{raw_path}: not a directory")
            continue

        matched = False
        if _looks_like_node_modules(root):
            matched = True
            for node_modules in _node_modules_dirs(root):
                files.extend(_discover_npm(node_modules, seen_roots))

        if _looks_like_site_packages(root):
            matched = True
            files.extend(_discover_python(root))

        if not matched:
            errors.append(f"{raw_path}: does not look like node_modules or site-packages")

    return files, errors


def _looks_like_node_modules(path: Path) -> bool:
    if path.name == "node_modules":
        return True
    return any((child / "package.json").is_file() for child in _safe_iterdir(path))


def _looks_like_site_packages(path: Path) -> bool:
    if path.name == "site-packages":
        return True
    return any(child.name.endswith(".dist-info") and child.is_dir() for child in _safe_iterdir(path))


def _node_modules_dirs(root: Path) -> list[Path]:
    if root.name == "node_modules":
        starts = [root]
    else:
        starts = [root / "node_modules"] if (root / "node_modules").is_dir() else [root]

    found: list[Path] = []
    for start in starts:
        if start.name == "node_modules":
            found.append(start)
        for dirpath, dirnames, _filenames in os.walk(start, followlinks=False):
            dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
            current = Path(dirpath)
            if current.name == "node_modules" and current not in found:
                found.append(current)
    return found


def _discover_npm(node_modules: Path, seen_roots: set[Path]) -> list[PackageFile]:
    files: list[PackageFile] = []
    for package_root in _npm_package_roots(node_modules):
        real_root = package_root.resolve()
        if real_root in seen_roots:
            continue
        seen_roots.add(real_root)

        package, version = _read_package_json(package_root)
        for path in _walk_files(package_root):
            files.append(_package_file("npm", package, version, package_root, path))
    return files


def _npm_package_roots(node_modules: Path) -> list[Path]:
    roots: list[Path] = []
    for child in _safe_iterdir(node_modules):
        if child.name == ".bin" or not child.is_dir() or child.is_symlink():
            continue
        if child.name.startswith("@"):
            for scoped_child in _safe_iterdir(child):
                if scoped_child.is_dir() and not scoped_child.is_symlink() and (scoped_child / "package.json").is_file():
                    roots.append(scoped_child)
            continue
        if (child / "package.json").is_file():
            roots.append(child)
    return roots


def _discover_python(site_packages: Path) -> list[PackageFile]:
    files: list[PackageFile] = []
    seen: set[Path] = set()

    for dist in importlib.metadata.distributions(path=[str(site_packages)]):
        name = dist.metadata.get("Name") or "unknown"
        version = dist.version or "unknown"
        for rel in dist.files or []:
            path = site_packages / rel
            if not path.is_file() or path.is_symlink():
                continue
            real = path.resolve()
            if real in seen:
                continue
            seen.add(real)
            files.append(_package_file("python", name, version, site_packages, path))

    for path in site_packages.glob("*.pth"):
        if path.is_file() and not path.is_symlink():
            files.append(_package_file("python", f"pth:{path.stem}", "unknown", site_packages, path))

    return files


def _walk_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and name != "node_modules"]
        current = Path(dirpath)
        for filename in filenames:
            path = current / filename
            if path.is_file() and not path.is_symlink():
                paths.append(path)
    return paths


def _package_file(ecosystem: str, package: str, version: str, root: Path, path: Path) -> PackageFile:
    return PackageFile(
        ecosystem=cast(Ecosystem, ecosystem),
        package=package,
        version=version,
        package_root=root,
        rel_path=path.relative_to(root),
        abs_path=path,
        real_path=path.resolve(),
        size=path.stat().st_size,
    )


def _read_package_json(package_root: Path) -> tuple[str, str]:
    try:
        data = json.loads((package_root / "package.json").read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return package_root.name, "unknown"
    name = data.get("name") if isinstance(data, dict) else None
    version = data.get("version") if isinstance(data, dict) else None
    return str(name or package_root.name), str(version or "unknown")


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except OSError:
        return []
