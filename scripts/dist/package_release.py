#!/usr/bin/env python3
"""Archive an already packed (and eventually signed) ConMan staging tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import zipfile


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage-dir", type=Path, default=Path("dist/stage"))
    parser.add_argument("--output-dir", type=Path, default=Path("dist/packages"))
    parser.add_argument("--github-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metadata_path = args.stage_dir / "release-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    version = metadata["sanitized_version"]
    platform = metadata["platform"]
    base_name = f"conman-{version}-{platform}"

    args.output_dir.mkdir(parents=True, exist_ok=True)
    extension = ".zip" if platform.startswith("windows-") else ".tar.gz"
    archive = args.output_dir / f"{base_name}{extension}"
    archive.unlink(missing_ok=True)

    members = sorted(
        path for path in args.stage_dir.iterdir() if path.name != "release-metadata.json"
    )
    if not members:
        raise RuntimeError(f"no release files found in {args.stage_dir}")

    if extension == ".zip":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for member in members:
                bundle.write(member, f"{base_name}/{member.name}")
    else:
        with tarfile.open(archive, "w:gz") as bundle:
            for member in members:
                bundle.add(member, arcname=f"{base_name}/{member.name}")

    checksum = sha256(archive)
    checksum_file = archive.with_name(f"{archive.name}.sha256")
    checksum_file.write_text(f"{checksum}  {archive.name}\n", encoding="utf-8")

    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write(f"archive={archive}\n")
            output.write(f"checksum={checksum_file}\n")
            output.write(f"asset_base={base_name}\n")
    print(archive)
    print(checksum_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
