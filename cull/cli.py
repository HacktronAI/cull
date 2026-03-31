from __future__ import annotations

import argparse
import os
import sys

from .models import Finding
from .output import bold, green, print_error, print_header, red, tprint, yellow
from .parsers import parse_pkg_arg
from .scanners import collect_images, scan_docker, scan_github, scan_local


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cull",
        description="Find compromised npm packages across your infrastructure.",
        epilog="Examples:\n"
        "  cull axios@1.14.1 axios@0.30.4 plain-crypto-js\n"
        "  cull axios@1.14.1 --dirs ~/projects\n"
        "  cull plain-crypto-js --github-org myorg\n"
        "  cull axios@1.14.1 axios@0.30.4 --docker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("packages", nargs="+", metavar="PKG", help="packages to search for (e.g. axios@1.14.1 plain-crypto-js)")

    local = parser.add_argument_group("local")
    local.add_argument("--dirs", nargs="+", metavar="DIR", help="directories to scan (default: current directory)")

    github = parser.add_argument_group("github")
    github.add_argument("--github-token", metavar="TOKEN", default=os.environ.get("GITHUB_TOKEN"), help="GitHub PAT (default: $GITHUB_TOKEN)")
    github.add_argument("--github-org", metavar="ORG")

    docker = parser.add_argument_group("docker")
    docker.add_argument("--docker", action="store_true", help="scan all local Docker images")
    docker.add_argument("--images", nargs="+", metavar="IMG", help="specific images to scan")
    docker.add_argument("--no-pull", action="store_true", help="don't auto-pull remote images before scanning")

    cloud = parser.add_argument_group("cloud registries")
    cloud.add_argument("--gcr-project", metavar="PROJECT", help="Google Container Registry project")
    cloud.add_argument("--gar-repo", metavar="REPO", help="Artifact Registry repo (e.g. us-central1-docker.pkg.dev/proj/repo)")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    targets = [parse_pkg_arg(raw) for raw in args.packages]
    auto_pull = not args.no_pull

    labels = ", ".join(target.label for target in targets)
    tprint(bold(f"━━━ cull: searching for {labels} ━━━"))

    all_findings: list[Finding] = []
    has_other_source = args.github_org or args.docker or args.images or args.gcr_project or args.gar_repo
    scan_dirs = args.dirs or (None if has_other_source else ["."])

    for target in targets:
        print_header(f"▸ {target.label}")

        if scan_dirs:
            print_header("  LOCAL DIRECTORIES")
            all_findings.extend(scan_local(scan_dirs, target.name, target.version))

        if args.github_org and not args.github_token:
            detail = "GitHub token required when --github-org is set"
            print_error(f"org:{args.github_org}", detail)
            all_findings.append(Finding("github", f"org:{args.github_org}", "error", detail))
        elif args.github_token and args.github_org:
            print_header("  GITHUB")
            all_findings.extend(scan_github(args.github_token, args.github_org, target.name, target.version))

    all_images, image_findings = collect_images(args)
    all_findings.extend(image_findings)

    if all_images:
        print_header("  IMAGES")
        all_findings.extend(scan_docker(all_images, targets, auto_pull=auto_pull))

    infected = [finding for finding in all_findings if finding.status == "found"]
    pinned = [finding for finding in all_findings if finding.status == "pinned"]
    errors = [finding for finding in all_findings if finding.status == "error"]

    tprint()
    parts: list[str] = []
    if infected:
        parts.append(red(f"{len(infected)} infected"))
    if pinned:
        parts.append(green(f"{len(pinned)} pinned (safe)"))
    if errors:
        parts.append(yellow(f"{len(errors)} errors"))
    if not infected and not pinned and not errors:
        parts.append(green("clean"))

    tprint(bold(f"━━━ Result: {', '.join(parts)} ━━━"))
    sys.exit(1 if infected else 2 if errors else 0)
