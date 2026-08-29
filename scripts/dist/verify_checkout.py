#!/usr/bin/env python3
"""Verify that the working tree is at the exact requested Git revision."""

from __future__ import annotations

import argparse
import subprocess


def resolved_revision(revision: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", f"{revision}^{{commit}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("revision")
    args = parser.parse_args()

    head = resolved_revision("HEAD")
    expected = resolved_revision(args.revision)
    if head != expected:
        raise RuntimeError(f"checkout is at {head}, expected {expected}")
    print(f"Verified exact checkout at {head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
