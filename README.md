# cull

Find compromised npm packages across your infrastructure.

```bash
python3 cull.py axios@1.14.1 axios@0.30.4 plain-crypto-js
```

Checks lock files (`pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`), `node_modules`, GitHub code search, and Docker image layers (legacy + OCI). Version-aware — distinguishes compromised versions from safe pins. Exit code `1` if found, `0` otherwise.

## Scan targets

### Local directories

```bash
python3 cull.py axios@1.14.1 --dirs ~/projects/app1 ~/projects/app2
```

Default: current directory.

### GitHub

```bash
export GITHUB_TOKEN=ghp_...
python3 cull.py axios@1.14.1 --github-org myorg
```

Searches lock files via [code search API](https://docs.github.com/en/rest/search/search#search-code). Token can also be passed via `--github-token`.

**Creating a PAT** — [github.com/settings/tokens](https://github.com/settings/tokens): classic → `repo` scope, fine-grained → set resource owner to your org, grant `Contents: Read-only`.

### Docker images

```bash
python3 cull.py axios@1.14.1 --docker           # all local images
python3 cull.py axios@1.14.1 --images app:latest # specific images
```

Requires `docker` CLI. Remote images are auto-pulled; use `--no-pull` to skip.

### Google Cloud

```bash
python3 cull.py axios@1.14.1 --gar-repo us-central1-docker.pkg.dev/proj/repo  # Artifact Registry
python3 cull.py axios@1.14.1 --gcr-project my-project                         # Container Registry (legacy)
```

Requires `gcloud` CLI with `gcloud auth login` and `gcloud auth configure-docker REGION-docker.pkg.dev`.

## Requirements

Python 3.9+. Optional CLIs: `docker`, `gcloud` — scanners skip gracefully if missing.

## Security

Stdlib only — nothing to supply-chain. External CLIs invoked only when their flags are used. Images are exported via `docker save` / `docker pull` — never `docker run`.

## Contributing

PRs welcome — GitLab, Bitbucket, AWS ECR, and Azure ACR are natural next targets.
