from __future__ import annotations

import argparse
import json
import os
import subprocess
import tarfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .constants import (
    DOCKER_PULL_TIMEOUT_S,
    LOCK_FILES,
    MAX_FILE_BYTES,
    MAX_IMAGE_WORKERS,
    SKIP_DIRS,
    SKIP_IMAGE_ENTRIES,
)
from .models import Finding, Target
from .output import (
    dim,
    print_clean,
    print_error,
    print_found,
    print_header,
    print_pinned,
    print_skip,
    print_warn,
    tprint,
)
from .parsers import check_content_or_error, read_nm_version
from .runtime import has_cmd, http_get, http_get_text, run


def check_lockfile(fpath: Path, pkg: str, bad_version: str | None) -> Finding | None:
    try:
        size = fpath.stat().st_size
        if size > MAX_FILE_BYTES:
            detail = "exceeds size limit"
            print_error(str(fpath), detail)
            return Finding("local", str(fpath), "error", detail)
        content = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        detail = f"failed to read: {e}"
        print_error(str(fpath), detail)
        return Finding("local", str(fpath), "error", detail)

    result = check_content_or_error(content, pkg, bad_version, "local", str(fpath), fpath.name)
    if result is None:
        print_clean(str(fpath))
    return result


def check_node_modules(nm_pkg_dir: Path, pkg: str, bad_version: str | None) -> Finding | None:
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
            detail = "is not a directory"
            print_error(root_dir, detail)
            findings.append(Finding("local", root_dir, "error", detail))
            continue

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            cur = Path(dirpath)

            if "node_modules" in dirnames:
                result = check_node_modules(cur / "node_modules" / pkg, pkg, bad_version)
                if result:
                    findings.append(result)
                dirnames.remove("node_modules")

            for fname in filenames:
                if fname not in LOCK_FILES:
                    continue
                result = check_lockfile(cur / fname, pkg, bad_version)
                if result:
                    findings.append(result)

    return findings


def scan_github(token: str, org: str, pkg: str, bad_version: str | None) -> list[Finding]:
    findings: list[Finding] = []
    auth = {"Authorization": f"Bearer {token}"}
    per_page = 100
    max_results = 1000

    for lock_file in LOCK_FILES:
        tprint(f"  {dim('searching')} {dim(lock_file)}…")
        query = urllib.request.quote(f"{pkg} filename:{lock_file} org:{org}")
        page = 1
        fetched = 0
        while True:
            data = http_get(
                f"https://api.github.com/search/code?q={query}&per_page={per_page}&page={page}",
                {**auth, "Accept": "application/vnd.github.v3+json"},
            )
            if data is None:
                detail = f"search failed for {lock_file}"
                print_error(f"org:{org}", detail)
                findings.append(Finding("github", f"org:{org}", "error", detail))
                break

            items = data.get("items", [])
            total = data.get("total_count", len(items))
            visible_total = min(total, max_results)
            if total > max_results and page == 1:
                print_warn(
                    f"GitHub search API caps results at {max_results}; "
                    f"showing first {max_results} of {total} matches for {lock_file}",
                )

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
                    detail = "could not resolve URL"
                    print_error(location, detail)
                    findings.append(Finding("github", location, "error", detail))
                    continue

                content = http_get_text(raw_url, {**auth, "Accept": "application/vnd.github.v3.raw"})
                if content is None:
                    detail = "could not download file"
                    print_error(location, detail)
                    findings.append(Finding("github", location, "error", detail))
                    continue

                result = check_content_or_error(content, pkg, bad_version, "github", location, lock_file)
                if result:
                    findings.append(result)
                else:
                    print_clean(location)

            fetched += len(items)
            if not items or fetched >= visible_total or fetched >= max_results:
                break
            page += 1

    if not findings:
        print_clean(f"org:{org}")

    return findings


def is_layer_entry(member: tarfile.TarInfo) -> bool:
    return (member.isfile() and member.name.endswith((".tar", ".tar.gz"))) or (
        member.name.startswith("blobs/") and member.isfile() and member.size > 0
    )


def scan_layer(layer: tarfile.TarFile, image: str, targets: list[Target], findings: list[Finding]) -> None:
    for entry in layer:
        if not entry.isfile():
            continue
        if entry.size > MAX_FILE_BYTES:
            detail = f"entry exceeds size limit: {entry.name}"
            print_error(image, detail)
            findings.append(Finding("docker", f"{image} → {entry.name}", "error", detail))
            continue

        name = entry.name
        basename = os.path.basename(name)

        matched_target: Target | None = None
        for target in targets:
            if f"node_modules/{target.name}/package.json" in name:
                matched_target = target
                break

        if matched_target:
            entry_file = layer.extractfile(entry)
            if not entry_file:
                detail = f"failed to read entry: {entry.name}"
                print_error(image, detail)
                findings.append(Finding("docker", f"{image} → {entry.name}", "error", detail))
                continue
            raw = entry_file.read(MAX_FILE_BYTES).decode(errors="replace")
            try:
                installed = json.loads(raw).get("version", "")
            except (json.JSONDecodeError, ValueError):
                installed = ""

            location = f"{image} → node_modules/{matched_target.name}"
            bad = matched_target.version
            if not bad:
                print_found(location, installed)
                findings.append(Finding("docker", location, "found", installed))
            elif installed == bad:
                print_found(location, f"{matched_target.name}@{installed}")
                findings.append(Finding("docker", location, "found", installed))
            elif installed:
                print_pinned(location, installed)
                findings.append(Finding("docker", location, "pinned", installed))
            continue

        if basename not in LOCK_FILES:
            continue

        entry_file = layer.extractfile(entry)
        if not entry_file:
            detail = f"failed to read entry: {entry.name}"
            print_error(image, detail)
            findings.append(Finding("docker", f"{image} → {entry.name}", "error", detail))
            continue
        content = entry_file.read(MAX_FILE_BYTES).decode(errors="replace")
        for target in targets:
            result = check_content_or_error(content, target.name, target.version, "docker", f"{image} → {name}", basename)
            if result:
                findings.append(result)


def short_image(image: str) -> str:
    parts = image.rsplit("/", 1)
    return parts[-1] if len(parts) > 1 else image


def scan_single_image(image: str, targets: list[Target], *, auto_pull: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    scanned = False
    inspect_result = run(["docker", "image", "inspect", image], timeout=10)
    if not inspect_result.ok:
        if auto_pull and "/" in image:
            tprint(f"  {dim('pulling')} {dim(image)}…")
            pull_result = run(["docker", "pull", image], timeout=DOCKER_PULL_TIMEOUT_S)
            if not pull_result.ok:
                detail = f"docker pull failed: {pull_result.detail}"
                print_error(image, detail)
                return [Finding("docker", image, "error", detail)]
        else:
            detail = (
                "image not available locally (use without --no-pull)"
                if not auto_pull
                else f"docker image inspect failed: {inspect_result.detail}"
            )
            print_error(image, detail)
            return [Finding("docker", image, "error", detail)]

    tprint(f"  {dim('scanning')} {dim(short_image(image))}…")

    try:
        proc = subprocess.Popen(["docker", "save", image], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as e:
        detail = f"failed to start docker save: {e}"
        print_error(image, detail)
        return [Finding("docker", image, "error", detail)]

    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as image_tar:
            for member in image_tar:
                if member.name in SKIP_IMAGE_ENTRIES:
                    continue
                if not is_layer_entry(member):
                    continue

                layer_file = image_tar.extractfile(member)
                if not layer_file:
                    continue

                try:
                    with tarfile.open(fileobj=layer_file, mode="r|*") as layer:
                        scanned = True
                        scan_layer(layer, image, targets, findings)
                except tarfile.TarError:
                    detail = f"failed to read layer archive: {member.name}"
                    print_error(image, detail)
                    findings.append(Finding("docker", image, "error", detail))
    except tarfile.TarError:
        detail = "failed to read image archive"
        print_error(image, detail)
        return [Finding("docker", image, "error", detail)]
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
        proc.wait()

    if proc.returncode != 0:
        detail = f"docker save failed with exit code {proc.returncode}"
        print_error(image, detail)
        findings.append(Finding("docker", image, "error", detail))

    if not scanned:
        detail = "no layers found"
        print_error(image, detail)
        findings.append(Finding("docker", image, "error", detail))
    elif not findings:
        print_clean(image)

    return findings


def list_docker_images() -> tuple[list[str], str | None]:
    result = run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter", "dangling=false"])
    if not result.ok:
        return [], result.detail
    return [line for line in result.stdout.splitlines() if line and "<none>" not in line], None


def scan_docker(images: list[str], targets: list[Target], *, auto_pull: bool = True) -> list[Finding]:
    tprint(f"  {dim(f'{len(images)} image(s)')}")
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=MAX_IMAGE_WORKERS) as pool:
        futures = {pool.submit(scan_single_image, image, targets, auto_pull=auto_pull): image for image in images}
        for future in as_completed(futures):
            findings.extend(future.result())
    return findings


def list_gcr_images(project: str) -> tuple[list[str], str | None]:
    result = run(["gcloud", "container", "images", "list", f"--project={project}", "--format=value(name)"], timeout=30)
    if not result.ok:
        return [], result.detail

    images: list[str] = []
    for repo in result.stdout.splitlines():
        tags_result = run(["gcloud", "container", "images", "list-tags", repo, "--format=value(tags)"], timeout=60)
        if not tags_result.ok:
            return [], f"failed listing tags for {repo}: {tags_result.detail}"
        for line in tags_result.stdout.splitlines():
            for tag in line.split(","):
                tag = tag.strip()
                if tag:
                    images.append(f"{repo}:{tag}")
    return images, None


def list_gar_images(repo: str) -> tuple[list[str], str | None]:
    result = run(
        ["gcloud", "artifacts", "docker", "images", "list", repo, "--include-tags", "--format=value(PACKAGE,TAGS)"],
        timeout=60,
    )
    if not result.ok:
        return [], result.detail

    images: list[str] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            return [], f"unexpected gcloud GAR output: {line}"
        package, tags = parts[0].strip(), parts[1].strip()
        for tag in tags.split(","):
            tag = tag.strip()
            if tag:
                images.append(f"{package}:{tag}")
    return images, None


def collect_images(args: argparse.Namespace) -> tuple[list[str], list[Finding]]:
    images: list[str] = list(args.images or [])
    findings: list[Finding] = []

    if args.docker:
        if not has_cmd("docker"):
            detail = "docker CLI not found"
            print_error("docker", detail)
            findings.append(Finding("docker", "docker", "error", detail))
        else:
            found, error = list_docker_images()
            if error:
                print_error("docker", error)
                findings.append(Finding("docker", "docker", "error", error))
            else:
                images.extend(found)

    if args.gcr_project:
        if not has_cmd("gcloud"):
            detail = "gcloud CLI not found for GCR scan"
            print_error(f"gcr:{args.gcr_project}", detail)
            findings.append(Finding("gcr", f"gcr:{args.gcr_project}", "error", detail))
        else:
            found, error = list_gcr_images(args.gcr_project)
            if error:
                print_error(f"gcr:{args.gcr_project}", error)
                findings.append(Finding("gcr", f"gcr:{args.gcr_project}", "error", error))
            elif found:
                images.extend(found)
            else:
                print_skip("no GCR images found")

    if args.gar_repo:
        if not has_cmd("gcloud"):
            detail = "gcloud CLI not found for GAR scan"
            print_error(f"gar:{args.gar_repo}", detail)
            findings.append(Finding("gar", f"gar:{args.gar_repo}", "error", detail))
        else:
            found, error = list_gar_images(args.gar_repo)
            if error:
                print_error(f"gar:{args.gar_repo}", error)
                findings.append(Finding("gar", f"gar:{args.gar_repo}", "error", error))
            elif found:
                images.extend(found)
            else:
                print_skip("no GAR images found")

    return list(dict.fromkeys(images)), findings
