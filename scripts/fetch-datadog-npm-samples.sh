#!/usr/bin/env bash
set -euo pipefail

target_dir="${1:-samples/datadog-malicious-software-packages-dataset}"

if [[ -d "$target_dir/.git" ]]; then
  git -C "$target_dir" pull --ff-only
else
  mkdir -p "$(dirname "$target_dir")"
  git clone \
    --depth 1 \
    --filter=blob:none \
    --sparse \
    https://github.com/DataDog/malicious-software-packages-dataset.git \
    "$target_dir"
fi

git -C "$target_dir" sparse-checkout set samples/npm
