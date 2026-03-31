from __future__ import annotations

import os
import sys
import threading

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


def tprint(*args: object, **kwargs: object) -> None:
    with _print_lock:
        print(*args, **kwargs)


def print_header(title: str) -> None:
    tprint(f"\n{bold(title)}")


def print_found(location: str, detail: str = "") -> None:
    suffix = f"  ({detail})" if detail else ""
    tprint(f"  {red('✗ FOUND')}   {location}{suffix}")


def print_pinned(location: str, detail: str) -> None:
    tprint(f"  {green('✓ pinned')}  {dim(location)}  {dim(detail)}")


def print_clean(location: str) -> None:
    tprint(f"  {green('✓ clean')}   {dim(location)}")


def print_skip(reason: str) -> None:
    tprint(f"  {yellow('⊘ skip')}    {dim(reason)}")


def print_warn(message: str) -> None:
    tprint(f"  {yellow('⚠ warn')}    {message}")


def print_error(location: str, detail: str = "") -> None:
    suffix = f"  ({detail})" if detail else ""
    tprint(f"  {yellow('⚠ error')}   {location}{suffix}")
