#!/usr/bin/env python3
"""cull — find compromised npm packages across your infrastructure.

Scans local directories, GitHub repos, Docker images, and GCP container
registries for specific packages + versions.

Usage:
    python cull.py axios@1.14.1 axios@0.30.4 plain-crypto-js
    python cull.py axios@1.14.1 --dirs ~/projects/iva
    python cull.py plain-crypto-js --github-org ORG
    python cull.py axios@1.14.1 axios@0.30.4 --docker
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOCK_FILES = frozenset({
    "pnpm-lock.yaml",
    "package-lock.json",
    "yarn.lock",
    "bun.lock",
})

SKIP_DIRS = frozenset({
    ".git", ".svn", "__pycache__",
    ".next", ".nuxt", ".output",
    "dist", ".cache", ".turbo",
})

SKIP_IMAGE_ENTRIES = frozenset({
    "manifest.json", "index.json", "oci-layout", "repositories",
})

MAX_IMAGE_WORKERS = 4
MAX_FILE_BYTES = 200 * 1024 * 1024
DOCKER_PULL_TIMEOUT_S = 300


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

_NO_COLOR = os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty()
_print_lock = threading.Lock()


def _c(code: str, text: str) -> str:
    if _NO_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(t: str) -> str:
    return _c("31", t)


def green(t: str) -> str:
    return _c("32", t)


def yellow(t: str) -> str:
    return _c("33", t)


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


def _tprint(*args: object, **kwargs: object) -> None:
    with _print_lock:
        print(*args, **kwargs)


def print_header(title: str) -> None:
    _tprint(f"\n{bold(title)}")


def print_found(location: str, detail: str = "") -> None:
    d = f"  ({detail})" if detail else ""
    _tprint(f"  {red('✗ FOUND')}   {location}{d}")


def print_pinned(location: str, detail: str) -> None:
    _tprint(f"  {green('✓ pinned')}  {dim(location)}  {dim(detail)}")


def print_clean(location: str) -> None:
    _tprint(f"  {green('✓ clean')}   {dim(location)}")


def print_skip(reason: str) -> None:
    _tprint(f"  {yellow('⊘ skip')}    {dim(reason)}")


def print_warn(message: str) -> None:
    _tprint(f"  {yellow('⚠ warn')}    {message}")


# ---------------------------------------------------------------------------
# Package argument parsing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    name: str
    version: str | None

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name


def _clean_version(v: str) -> str | None:
    cleaned = v.lstrip("^~>=<v")
    return cleaned or None


def parse_pkg_arg(raw: str) -> Target:
    """Parse 'axios@1.14.1' or '@nestjs/axios@4.0.0' into Target(name, version)."""
    if raw.startswith("@"):
        parts = raw[1:].split("/", 1)
        if len(parts) < 2:
            return Target(raw, None)

        scope, rest = parts
        if "@" not in rest:
            return Target(raw, None)

        name_part, version = rest.rsplit("@", 1)
        return Target(f"@{scope}/{name_part}", _clean_version(version))

    if "@" in raw:
        name, version = raw.rsplit("@", 1)
        return Target(name, _clean_version(version))

    return Target(raw, None)


# ---------------------------------------------------------------------------
# Version extraction from lock files
# ---------------------------------------------------------------------------

def _versions_from_npm_lock(content: str, pkg: str) -> set[str]:
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
            v = info.get("version", "")
            if v:
                versions.add(v)

    _versions_from_npm_v1(data.get("dependencies", {}), pkg, versions)
    return versions


def _versions_from_npm_v1(deps: dict, pkg: str, versions: set[str]) -> None:
    for name, info in deps.items():
        if name == pkg:
            v = info.get("version", "")
            if v:
                versions.add(v)
        nested = info.get("dependencies")
        if nested:
            _versions_from_npm_v1(nested, pkg, versions)


def _versions_from_pnpm_lock(content: str, pkg: str) -> set[str]:
    escaped = re.escape(pkg)
    ver_re = r"(\d+\.\d+\.\d+(?:-[\w.]+)?)"
    versions: set[str] = set()

    for m in re.finditer(escaped + r"@" + ver_re, content):
        pos = m.start()
        if pos > 0:
            prev = content[pos - 1]
            if prev == "/" or prev.isalnum() or prev == "-":
                continue
        versions.add(m.group(1))

    for m in re.finditer(r"/" + escaped + r"/" + ver_re, content):
        line_start = content.rfind("\n", 0, m.start()) + 1
        prefix = content[line_start:m.start()]
        if re.search(r"@[\w.-]+$", prefix):
            continue
        versions.add(m.group(1))

    return versions


def _versions_from_yarn_lock(content: str, pkg: str) -> set[str]:
    versions: set[str] = set()
    in_pkg_block = False
    pkg_re = re.compile(r'(?:^|[\s",])' + re.escape(pkg) + r"@")

    for line in content.splitlines():
        if not line.startswith(" ") and not line.startswith("\t"):
            in_pkg_block = bool(pkg_re.search(line))
            continue
        if not in_pkg_block:
            continue
        m = re.match(r'\s+version\s+"([^"]+)"', line)
        if m:
            versions.add(m.group(1))
            in_pkg_block = False

    return versions


def _strip_jsonc_trailing_commas(text: str) -> str:
    return re.sub(r",\s*([}\]])", r"\1", text)


def _versions_from_bun_lock(content: str, pkg: str) -> set[str]:
    try:
        data = json.loads(_strip_jsonc_trailing_commas(content))
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
        return _versions_from_npm_lock(content, pkg)
    if filename == "pnpm-lock.yaml":
        return _versions_from_pnpm_lock(content, pkg)
    if filename == "yarn.lock":
        return _versions_from_yarn_lock(content, pkg)
    if filename == "bun.lock":
        return _versions_from_bun_lock(content, pkg)
    return set()


def read_nm_version(pkg_dir: Path) -> str | None:
    pj = pkg_dir / "package.json"
    if not pj.is_file():
        return None
    try:
        data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
        return data.get("version")
    except (json.JSONDecodeError, ValueError, OSError):
        return None


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

Status = Literal["found", "pinned"]


@dataclass(frozen=True)
class Finding:
    source: str
    location: str
    status: Status
    version: str = ""


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def has_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def run(args: list[str], *, timeout: int = 60) -> str | None:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return None
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def http_get(url: str, headers: dict[str, str]) -> dict | list | None:
    req_headers = {**headers, "User-Agent": "cull"}
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 422:
            return {"items": []}
        print_skip(f"HTTP {e.code}: {e.reason}")
        return None
    except urllib.error.URLError as e:
        print_skip(f"request failed: {e.reason}")
        return None
    except (TimeoutError, OSError):
        print_skip("request timed out")
        return None


def _http_get_text(url: str, headers: dict[str, str]) -> str | None:
    req_headers = {**headers, "User-Agent": "cull"}
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode(errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        return None


# ---------------------------------------------------------------------------
# Shared content checker
# ---------------------------------------------------------------------------

def _check_content(
    content: str, pkg: str, bad_version: str | None,
    source: str, location: str, filename: str,
) -> Finding | None:
    """Check file content for a compromised package. Returns None if clean."""
    if pkg not in content:
        return None

    versions = extract_versions(content, pkg, filename)
    if not versions:
        return None

    if not bad_version:
        v = ", ".join(sorted(versions))
        print_found(location, v)
        return Finding(source, location, "found", v)

    if bad_version in versions:
        print_found(location, f"{pkg}@{bad_version}")
        return Finding(source, location, "found", bad_version)

    v = ", ".join(sorted(versions))
    print_pinned(location, v)
    return Finding(source, location, "pinned", v)


# ---------------------------------------------------------------------------
# Scanner: Local
# ---------------------------------------------------------------------------

def _check_lockfile(fpath: Path, pkg: str, bad_version: str | None) -> Finding | None:
    try:
        size = fpath.stat().st_size
        if size > MAX_FILE_BYTES:
            print_skip(f"{fpath} exceeds size limit")
            return None
        content = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    result = _check_content(content, pkg, bad_version, "local", str(fpath), fpath.name)
    if result is None:
        print_clean(str(fpath))
    return result


def _check_node_modules(nm_pkg_dir: Path, pkg: str, bad_version: str | None) -> Finding | None:
    if not nm_pkg_dir.is_dir():
        return None

    location = str(nm_pkg_dir)
    installed = read_nm_version(nm_pkg_dir)

    if not bad_version:
        print_found(location, installed or "")
        return Finding("local", location, "found", installed or "")

    if installed == bad_version:
        print_found(location, f"{pkg}@{installed}")
        return Finding("local", location, "found", installed)

    if installed:
        print_pinned(location, installed)
        return Finding("local", location, "pinned", installed)

    print_found(location, "version unknown")
    print_warn("malware may have replaced package.json — check lock files for ground truth")
    return Finding("local", location, "found")


def scan_local(dirs: list[str], pkg: str, bad_version: str | None) -> list[Finding]:
    findings: list[Finding] = []

    for root_dir in dirs:
        root = Path(root_dir).expanduser().resolve()
        if not root.is_dir():
            print_skip(f"{root_dir} is not a directory")
            continue

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            cur = Path(dirpath)

            if "node_modules" in dirnames:
                result = _check_node_modules(cur / "node_modules" / pkg, pkg, bad_version)
                if result:
                    findings.append(result)
                dirnames.remove("node_modules")

            for fname in filenames:
                if fname not in LOCK_FILES:
                    continue
                result = _check_lockfile(cur / fname, pkg, bad_version)
                if result:
                    findings.append(result)

    return findings


# ---------------------------------------------------------------------------
# Scanner: GitHub
# ---------------------------------------------------------------------------

def scan_github(
    token: str, org: str, pkg: str, bad_version: str | None,
) -> list[Finding]:
    findings: list[Finding] = []
    auth = {"Authorization": f"Bearer {token}"}

    for lock_file in LOCK_FILES:
        _tprint(f"  {dim('searching')} {dim(lock_file)}…")
        q = urllib.request.quote(f"{pkg} filename:{lock_file} org:{org}")
        data = http_get(
            f"https://api.github.com/search/code?q={q}&per_page=100",
            {**auth, "Accept": "application/vnd.github.v3+json"},
        )
        if not data:
            continue

        items = data.get("items", [])
        total = data.get("total_count", len(items))
        if total > len(items):
            print_warn(f"results truncated: {total} matches, showing {len(items)}")

        for item in items:
            repo = item.get("repository", {}).get("full_name", "?")
            path = item.get("path", lock_file)
            location = f"{repo}/{path}"

            if not bad_version:
                print_found(location)
                findings.append(Finding("github", location, "found"))
                continue

            raw_url = item.get("url")
            if not raw_url:
                print_found(location, "could not resolve URL")
                findings.append(Finding("github", location, "found"))
                continue

            content = _http_get_text(
                raw_url, {**auth, "Accept": "application/vnd.github.v3.raw"},
            )
            if not content:
                print_found(location, "could not download — treating as found")
                findings.append(Finding("github", location, "found"))
                continue

            result = _check_content(
                content, pkg, bad_version, "github", location, lock_file,
            )
            if result:
                findings.append(result)
            else:
                print_clean(location)

    if not findings:
        print_clean(f"org:{org}")

    return findings


# ---------------------------------------------------------------------------
# Scanner: Docker images
# ---------------------------------------------------------------------------

def _is_layer_entry(member: tarfile.TarInfo) -> bool:
    return (
        member.name.endswith((".tar", ".tar.gz"))
        or (member.name.startswith("blobs/") and member.isfile() and member.size > 0)
    )


def _scan_layer(
    layer: tarfile.TarFile,
    image: str,
    targets: list[Target],
    findings: list[Finding],
) -> None:
    for entry in layer:
        if not entry.isfile():
            continue
        if entry.size > MAX_FILE_BYTES:
            continue

        name = entry.name
        basename = os.path.basename(name)

        matched_target: Target | None = None
        for t in targets:
            if f"node_modules/{t.name}/package.json" in name:
                matched_target = t
                break

        if matched_target:
            f = layer.extractfile(entry)
            if not f:
                continue
            raw = f.read(MAX_FILE_BYTES).decode(errors="replace")
            try:
                installed = json.loads(raw).get("version", "")
            except (json.JSONDecodeError, ValueError):
                installed = ""

            loc = f"{image} → node_modules/{matched_target.name}"
            bad = matched_target.version
            if not bad:
                print_found(loc, installed)
                findings.append(Finding("docker", loc, "found", installed))
            elif installed == bad:
                print_found(loc, f"{matched_target.name}@{installed}")
                findings.append(Finding("docker", loc, "found", installed))
            elif installed:
                print_pinned(loc, installed)
                findings.append(Finding("docker", loc, "pinned", installed))
            continue

        if basename not in LOCK_FILES:
            continue

        f = layer.extractfile(entry)
        if not f:
            continue
        content = f.read(MAX_FILE_BYTES).decode(errors="replace")
        for t in targets:
            result = _check_content(
                content, t.name, t.version, "docker", f"{image} → {name}", basename,
            )
            if result:
                findings.append(result)


def _ensure_available(image: str, *, auto_pull: bool = True) -> bool:
    result = run(["docker", "image", "inspect", image], timeout=10)
    if result is not None:
        return True
    if not auto_pull or "/" not in image:
        return False
    _tprint(f"  {dim('pulling')} {dim(image)}…")
    return run(["docker", "pull", image], timeout=DOCKER_PULL_TIMEOUT_S) is not None


def _short_image(image: str) -> str:
    parts = image.rsplit("/", 1)
    return parts[-1] if len(parts) > 1 else image


def _scan_single_image(
    image: str, targets: list[Target], *, auto_pull: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    scanned = False

    if not _ensure_available(image, auto_pull=auto_pull):
        reason = "not pulled (use without --no-pull)" if not auto_pull else "not available locally"
        print_skip(f"{reason}: {image}")
        return findings

    _tprint(f"  {dim('scanning')} {dim(_short_image(image))}…")

    proc = subprocess.Popen(
        ["docker", "save", image],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )

    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as image_tar:
            for member in image_tar:
                if member.name in SKIP_IMAGE_ENTRIES:
                    continue
                if not _is_layer_entry(member):
                    continue

                layer_file = image_tar.extractfile(member)
                if not layer_file:
                    continue

                try:
                    with tarfile.open(fileobj=layer_file, mode="r|*") as layer:
                        scanned = True
                        _scan_layer(layer, image, targets, findings)
                except tarfile.TarError:
                    continue
    except tarfile.TarError:
        print_skip(f"failed to read: {image}")
        return findings
    finally:
        proc.stdout.close()
        proc.wait()

    if not scanned:
        print_skip(f"no layers found: {image}")
    elif not findings:
        print_clean(image)

    return findings


def list_docker_images() -> list[str]:
    output = run([
        "docker", "image", "ls",
        "--format", "{{.Repository}}:{{.Tag}}",
        "--filter", "dangling=false",
    ])
    if not output:
        return []
    return [line for line in output.splitlines() if line and "<none>" not in line]


def scan_docker(
    images: list[str], targets: list[Target], *, auto_pull: bool = True,
) -> list[Finding]:
    _tprint(f"  {dim(f'{len(images)} image(s)')}")
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=MAX_IMAGE_WORKERS) as pool:
        futures = {
            pool.submit(_scan_single_image, img, targets, auto_pull=auto_pull): img
            for img in images
        }
        for future in as_completed(futures):
            findings.extend(future.result())
    return findings


# ---------------------------------------------------------------------------
# Cloud registry image listers
# ---------------------------------------------------------------------------

def list_gcr_images(project: str) -> list[str]:
    output = run([
        "gcloud", "container", "images", "list",
        f"--project={project}", "--format=value(name)",
    ], timeout=30)
    if not output:
        return []

    images: list[str] = []
    for repo in output.splitlines():
        tags_out = run([
            "gcloud", "container", "images", "list-tags", repo,
            "--limit=50", "--format=value(tags)",
        ], timeout=60)
        if not tags_out:
            continue
        for line in tags_out.splitlines():
            for tag in line.split(","):
                tag = tag.strip()
                if tag:
                    images.append(f"{repo}:{tag}")
    return images


def list_gar_images(repo: str) -> list[str]:
    output = run([
        "gcloud", "artifacts", "docker", "images", "list", repo,
        "--include-tags", "--format=value(PACKAGE,TAGS)", "--limit=50",
    ], timeout=60)
    if not output:
        return []

    images: list[str] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        package, tag = parts[0].strip(), parts[1].strip()
        if tag:
            images.append(f"{package}:{tag}")
    return images


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cull",
        description="Find compromised npm packages across your infrastructure.",
        epilog="Examples:\n"
               "  cull axios@1.14.1 axios@0.30.4 plain-crypto-js\n"
               "  cull axios@1.14.1 --dirs ~/projects\n"
               "  cull plain-crypto-js --github-org myorg\n"
               "  cull axios@1.14.1 axios@0.30.4 --docker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "packages", nargs="+", metavar="PKG",
        help="packages to search for (e.g. axios@1.14.1 plain-crypto-js)",
    )

    local = p.add_argument_group("local")
    local.add_argument("--dirs", nargs="+", metavar="DIR",
                        help="directories to scan (default: current directory)")

    gh = p.add_argument_group("github")
    gh.add_argument("--github-token", metavar="TOKEN",
                    default=os.environ.get("GITHUB_TOKEN"),
                    help="GitHub PAT (default: $GITHUB_TOKEN)")
    gh.add_argument("--github-org", metavar="ORG")

    dk = p.add_argument_group("docker")
    dk.add_argument("--docker", action="store_true", help="scan all local Docker images")
    dk.add_argument("--images", nargs="+", metavar="IMG", help="specific images to scan")
    dk.add_argument("--no-pull", action="store_true",
                    help="don't auto-pull remote images before scanning")

    cloud = p.add_argument_group("cloud registries")
    cloud.add_argument("--gcr-project", metavar="PROJECT",
                        help="Google Container Registry project")
    cloud.add_argument("--gar-repo", metavar="REPO",
                        help="Artifact Registry repo (e.g. us-central1-docker.pkg.dev/proj/repo)")

    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _collect_images(args: argparse.Namespace) -> list[str]:
    images: list[str] = list(args.images or [])

    if args.docker:
        if not has_cmd("docker"):
            print_skip("docker CLI not found")
        else:
            images.extend(list_docker_images())

    if args.gcr_project:
        if not has_cmd("gcloud"):
            print_skip("gcloud CLI not found — skipping GCR")
        else:
            found = list_gcr_images(args.gcr_project)
            if found:
                images.extend(found)
            else:
                print_skip("no GCR images found")

    if args.gar_repo:
        if not has_cmd("gcloud"):
            print_skip("gcloud CLI not found — skipping GAR")
        else:
            found = list_gar_images(args.gar_repo)
            if found:
                images.extend(found)
            else:
                print_skip("no GAR images found")

    return list(dict.fromkeys(images))


def main() -> None:
    args = build_parser().parse_args()
    targets = [parse_pkg_arg(raw) for raw in args.packages]
    auto_pull = not args.no_pull

    labels = ", ".join(t.label for t in targets)
    _tprint(bold(f"━━━ cull: searching for {labels} ━━━"))

    all_findings: list[Finding] = []
    has_other_source = (
        args.github_org or args.docker or args.images
        or args.gcr_project or args.gar_repo
    )
    scan_dirs = args.dirs or (None if has_other_source else ["."])

    for target in targets:
        pkg, bad_version = target.name, target.version
        print_header(f"▸ {target.label}")

        if scan_dirs:
            print_header("  LOCAL DIRECTORIES")
            all_findings.extend(scan_local(scan_dirs, pkg, bad_version))

        if args.github_token and args.github_org:
            print_header("  GITHUB")
            all_findings.extend(
                scan_github(args.github_token, args.github_org, pkg, bad_version),
            )

    all_images = _collect_images(args)

    if all_images:
        print_header("  IMAGES")
        all_findings.extend(scan_docker(all_images, targets, auto_pull=auto_pull))

    infected = [f for f in all_findings if f.status == "found"]
    pinned = [f for f in all_findings if f.status == "pinned"]

    _tprint()
    parts: list[str] = []
    if infected:
        parts.append(red(f"{len(infected)} infected"))
    if pinned:
        parts.append(green(f"{len(pinned)} pinned (safe)"))
    if not infected and not pinned:
        parts.append(green("clean"))

    _tprint(bold(f"━━━ Result: {', '.join(parts)} ━━━"))
    sys.exit(1 if infected else 0)


if __name__ == "__main__":
    main()
