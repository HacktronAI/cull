# cull

Find compromised npm packages across your infrastructure. Only Python stdlib, no dependencies.

## Install

```bash
git clone https://github.com/HacktronAI/cull.git
cd cull
python3 -m pip install .
```

We deliberately do not publish to PyPI to avoid creating another supply-chain distribution point for a security tool. Install from a reviewed git clone instead.

## Usage

```bash
cull axios@1.14.1 axios@0.30.4 plain-crypto-js
```

Checks lock files (`pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`, `bun.lock`), `node_modules`, GitHub code search, and Docker image layers (legacy + OCI). Version-aware — distinguishes compromised versions from safe pins. Exit code `0` when clean, `1` when a compromised package is found, and `2` when the scan could not complete reliably.

## Scan targets

### Local directories

```bash
cull axios@1.14.1 --dirs ~/projects/app1 ~/projects/app2
```

Default: current directory.

### GitHub

```bash
export GITHUB_TOKEN=ghp_...
cull axios@1.14.1 --github-org myorg
```

Searches lock files via [code search API](https://docs.github.com/en/rest/search/search#search-code). Token can also be passed via `--github-token`.

**Creating a PAT** — [github.com/settings/tokens](https://github.com/settings/tokens): classic → `repo` scope, fine-grained → set resource owner to your org, grant `Contents: Read-only`.

### Docker images

```bash
cull axios@1.14.1 --docker            # all local images
cull axios@1.14.1 --images app:latest # specific images
```

Requires `docker` CLI. Remote images are auto-pulled; use `--no-pull` to skip.

### Google Cloud

```bash
cull axios@1.14.1 --gar-repo us-central1-docker.pkg.dev/proj/repo  # Artifact Registry
cull axios@1.14.1 --gcr-project my-project                         # Container Registry (legacy)
```

Requires `gcloud` CLI with `gcloud auth login` and `gcloud auth configure-docker REGION-docker.pkg.dev`.

## Requirements

Python 3.9+. Optional CLIs: `docker`, `gcloud`. If you request a scan target whose CLI is missing or whose backend calls fail, `cull` reports an error and exits non-zero instead of silently treating that target as clean.

## Security

We intentionally do not publish this to PyPI. The goal is to avoid creating another supply-chain distribution point for a security tool. Install from a reviewed git clone instead.

Stdlib only — nothing else to supply-chain. External CLIs invoked only when their flags are used. Images are exported via `docker save` / `docker pull` — never `docker run`.

## Contributing

PRs welcome — GitLab, Bitbucket, AWS ECR, and Azure ACR are natural next targets.
