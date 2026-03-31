from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.request

from .models import RunResult
from .output import print_skip


def has_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def run(args: list[str], *, timeout: int = 60) -> RunResult:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit code {result.returncode}"
            return RunResult(False, detail=detail)
        return RunResult(True, stdout=result.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return RunResult(False, detail="timed out or command not found")


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


def http_get_text(url: str, headers: dict[str, str]) -> str | None:
    req_headers = {**headers, "User-Agent": "cull"}
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode(errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        return None
