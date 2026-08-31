#!/usr/bin/env python3
"""Hide machine-specific source roots from Rust build artifacts in CI."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def remap_flags(home: str, workspace: str, existing: str = "") -> str:
    roots = ((home, "/build/home"), (workspace, "/build/conman"))
    for source, _ in roots:
        if not source or any(character.isspace() for character in source):
            raise ValueError("Rust path-remap roots must be non-empty and contain no whitespace")

    flags = [existing.strip()] if existing.strip() else []
    flags.extend(f"--remap-path-prefix={source}={target}" for source, target in roots)
    return " ".join(flags)


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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
