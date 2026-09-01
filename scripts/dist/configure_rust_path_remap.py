#!/usr/bin/env python3
"""Hide machine-specific source roots from Rust build artifacts in CI."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PureWindowsPath


def remap_flags(home: str, workspace: str, existing: str = "") -> str:
    roots = ((home, "/build/home"), (workspace, "/build/conman"))
    for source, _ in roots:
        if not source or any(character.isspace() for character in source):
            raise ValueError("Rust path-remap roots must be non-empty and contain no whitespace")

    flags = [existing.strip()] if existing.strip() else []
    flags.extend(f"--remap-path-prefix={source}={target}" for source, target in roots)
    return " ".join(flags)


def neutral_native_cache_root(platform: str, system_root: str = "") -> str:
    """Return a stable builder-neutral path for native compiler intermediates."""

    if platform == "nt":
        root = system_root or r"C:\Windows"
        return str(PureWindowsPath(root) / "Temp" / "conman-zig-cache")
    return "/tmp/conman-zig-cache"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--github-env",
        type=Path,
        default=os.environ.get("GITHUB_ENV"),
        required="GITHUB_ENV" not in os.environ,
    )
    args = parser.parse_args()

    home = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    workspace = os.environ.get("GITHUB_WORKSPACE")
    flags = remap_flags(home or "", workspace or "", os.environ.get("RUSTFLAGS", ""))

    with args.github_env.open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"RUSTFLAGS={flags}\n")
        output.write(
            "LIBGHOSTTY_VT_SYS_CACHE_ROOT="
            f"{neutral_native_cache_root(os.name, os.environ.get('SystemRoot', ''))}\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
