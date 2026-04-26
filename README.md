# cull

Find compromised packages and suspicious package code. Only Python stdlib, no dependencies.

## Install

```bash
git clone https://github.com/HacktronAI/cull.git
cd cull
python3 -m pip install .
```

We deliberately do not publish to PyPI to avoid creating another supply-chain distribution point for a security tool. Install from a reviewed git clone instead.

## Commands

### `cull check`

Deterministically search for known compromised package names/versions across lock files, `node_modules`, GitHub code search, Docker images, GCR, and Artifact Registry.

```bash
cull check axios@1.14.1 axios@0.30.4 plain-crypto-js
cull check axios@1.14.1 --dirs ~/projects/app1 ~/projects/app2
cull check axios@1.14.1 --github-org myorg
cull check axios@1.14.1 --docker
```

Bare usage remains an alias for one release:

```bash
cull axios@1.14.1
```

### `cull scan`

LLM-scan installed package source files for suspicious supply-chain behavior.

```bash
export GEMINI_API_KEY=...
cull scan ./node_modules
cull scan ./.venv/lib/python3.12/site-packages
cull scan ./node_modules ./.venv/lib/python3.12/site-packages -o report.json
```

`PATH` must point at a package install directory: `node_modules`, `site-packages`, or a directory that clearly looks like one.

Every run prints a preflight estimate first:

```text
packages: 342
files:    4,127 kept, 8,901 skipped
chunks:   4,143
tokens:   ~2.1M in / ~0.16M out
cost:     $0.25
```

Then it scans unless you pass:

```bash
cull scan ./node_modules --estimate-only
```

Useful flags:

```bash
--budget-usd 1.00          # abort if estimate or actual cost exceeds budget
--concurrency 4            # default 8
--no-cache                 # disable ~/.cache/cull/verdicts.json
--include-tests            # include test/spec dirs
-o report.json             # full JSON report
-o report.md               # full Markdown report
--json                     # write JSON result to stdout
```

Default model is `gemini-3.1-flash-lite-preview` against `https://generativelanguage.googleapis.com/v1beta/openai`, reading `GEMINI_API_KEY`. Swap any OpenAI-compatible provider with `--model`, `--base-url`, and `--api-key-env`.

See `[examples/ngx-perfect-scrollbar.md](examples/ngx-perfect-scrollbar.md)` for a real report against a known-malicious Shai-Hulud sample.

### Local model

Any local server that speaks the OpenAI `/v1/chat/completions` protocol (Ollama, llama.cpp `llama-server`, vLLM, LM Studio, …) works. Point `cull` at it with `--base-url` and `--model`. Most local servers ignore the API key — set any non-empty value so `cull` proceeds.

```bash
export LOCAL_API_KEY=local
cull scan ./node_modules \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder:7b \
  --api-key-env LOCAL_API_KEY
```

Local providers usually report no token usage, so the cost column will read `$0.0000`. The verdict cache is keyed by model id, so switching providers re-scans every chunk.

## Sandbox

Build a minimal Docker sandbox with `cull` installed:

```bash
docker build -f Dockerfile.sandbox -t cull-sandbox .
docker run --rm cull-sandbox -lc 'cull --help'
```

## Benchmark against Datadog's malicious package dataset

Datadog publishes ~3,000 real-world malicious npm packages as password-protected zips ([dataset](https://github.com/DataDog/malicious-software-packages-dataset)). The password is `infected`

Fetch the npm samples (sparse-checkout, no full repo history):

```bash
scripts/fetch-datadog-npm-samples.sh
```

Extract and scan **inside the sandbox** — the archives are real malware, never `npm install` them on your host. 

```bash
docker run --rm \
  -v "$PWD/samples:/samples:ro" \
  -v "$HOME/.cache/cull:/home/sandbox/.cache/cull" \
  -e GEMINI_API_KEY \
  cull-sandbox -lc '
    set -e
    src=/samples/datadog-malicious-software-packages-dataset/samples/npm
    work=$(mktemp -d)
    python3 -c "
import sys, zipfile, pathlib
with zipfile.ZipFile(sys.argv[1]) as z:
    z.extractall(pathlib.Path(sys.argv[2]), pwd=b\"infected\")
" "$src/2024-01/some-package.zip" "$work/node_modules"
    cull scan "$work/node_modules" --budget-usd 0.50 -o /tmp/report.md
    cat /tmp/report.md
  '
```

## Security

Stdlib only. `cull scan` reads installed package files and sends selected source chunks to the configured LLM provider. It does not execute package code.