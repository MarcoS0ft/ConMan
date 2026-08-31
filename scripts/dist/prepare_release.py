#!/usr/bin/env python3
"""Stage and verify ConMan release executables without touching Cargo outputs.

The staging directory is deliberately separate from ``target/release``.  On
Linux and Windows the staged application executables are compressed with a
pinned, checksum-verified UPX distribution.  macOS is never passed to UPX.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile


UPX_VERSION = "5.2.0"
UPX_RELEASE_BASE = f"https://github.com/upx/upx/releases/download/v{UPX_VERSION}"
UPX_ASSETS = {
    "linux-x86_64": (
        f"upx-{UPX_VERSION}-amd64_linux.tar.xz",
        "3db5d3294707439db97866feab8d75d800f028f48481a40547411824da4288a1",
        "upx",
    ),
    "windows-x86_64": (
        f"upx-{UPX_VERSION}-win64.zip",
        "b471ebf1b7f20f4a89150264ed9a008a2a5bfd247f3c6d1184a75bb59ca08f5d",
        "upx.exe",
    ),
}

VERSION_RE = re.compile(
    r"(?<![0-9A-Za-z])"
    r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)"
    r"(?![0-9A-Za-z])"
)

# This script lives at <repository>/scripts/dist/prepare_release.py. Keeping the
# repository root anchored to the script (rather than the caller's cwd) makes
# destructive-path validation stable in CI and local invocations alike.
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command: list[str], *, timeout: int = 60) -> str:
    print("+", " ".join(command), flush=True)
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    if result.stdout:
        print(result.stdout.rstrip())
    if result.returncode != 0:
        raise RuntimeError(
            f"command exited with status {result.returncode}: {' '.join(command)}"
        )
    return result.stdout


def reported_version(executable: Path) -> str:
    output = run([str(executable.resolve()), "--version"])
    versions = VERSION_RE.findall(output)
    if not versions:
        raise RuntimeError(f"could not parse a semantic version from {executable} --version")
    return versions[-1]


def sanitize_version(version: str) -> str:
    # '+' is valid SemVer but awkward in archive/download names.
    sanitized = re.sub(r"[^0-9A-Za-z._-]+", "-", version.replace("+", "-"))
    if not sanitized:
        raise RuntimeError("version produced an empty artifact identifier")
    return sanitized


def reject_embedded_build_paths(executables: list[Path], roots: list[str]) -> None:
    """Reject release binaries that disclose a builder home or checkout path."""

    needles: list[bytes] = []
    for root in dict.fromkeys(roots):
        if len(root) < 8:
            continue
        needles.append(root.encode("utf-8"))
        needles.append(root.encode("utf-16-le"))

    for executable in executables:
        contents = executable.read_bytes()
        for needle in needles:
            if needle in contents:
                raise RuntimeError(
                    "release executable contains a machine-specific build path: "
                    f"{executable.name}"
                )


def is_equal_or_ancestor(candidate: Path, descendant: Path) -> bool:
    return candidate == descendant or candidate in descendant.parents


def validated_stage_dir(stage_dir: Path, target_dir: Path) -> Path:
    """Return a canonical, narrow staging path that is safe to recursively reset."""

    canonical_stage = stage_dir.resolve(strict=False)
    canonical_target = target_dir.resolve(strict=False)
    canonical_repository = REPOSITORY_ROOT.resolve()
    repository_dist = canonical_repository / "dist"
    temporary_root = Path(tempfile.gettempdir()).resolve()

    anchor = Path(canonical_stage.anchor)
    relative_parts = canonical_stage.parts[len(anchor.parts) :]
    unsafe_reason: str | None = None

    if canonical_stage == anchor or canonical_stage.is_mount():
        unsafe_reason = "filesystem root or mount point"
    elif len(relative_parts) < 2:
        unsafe_reason = "path is too broad"
    elif is_equal_or_ancestor(canonical_stage, canonical_target):
        unsafe_reason = "path is equal to or contains the Cargo target directory"
    elif is_equal_or_ancestor(canonical_target, canonical_stage):
        unsafe_reason = "path is inside the Cargo target directory"
    elif is_equal_or_ancestor(canonical_stage, canonical_repository):
        unsafe_reason = "path is equal to or contains the repository root"
    elif canonical_repository in canonical_stage.parents:
        # A repository-local recursive reset is permitted only under the
        # dedicated dist/ tree. In particular, .git/, crates/, resources/, and
        # source directories are never valid staging roots. Do not resolve
        # repository_dist separately: a symlinked dist/ must not become a
        # backdoor into another repository child.
        if repository_dist not in canonical_stage.parents:
            unsafe_reason = "repository child is outside the dedicated dist directory"
    elif temporary_root not in canonical_stage.parents:
        unsafe_reason = "path is outside the repository dist and OS temporary directories"

    if unsafe_reason:
        raise RuntimeError(
            f"unsafe stage directory ({unsafe_reason}): {stage_dir} resolves to {canonical_stage}"
        )
    if canonical_stage.exists() and not canonical_stage.is_dir():
        raise RuntimeError(f"stage path is not a directory: {canonical_stage}")

    return canonical_stage


def download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "ConMan-release-builder"})
    with urllib.request.urlopen(request, timeout=60) as response:
        with destination.open("wb") as output:
            shutil.copyfileobj(response, output)


def safe_extract_tar(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with tarfile.open(archive, "r:xz") as bundle:
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if target != root and root not in target.parents:
                raise RuntimeError(f"UPX archive contains an unsafe path: {member.name}")
        bundle.extractall(destination)


def safe_extract_zip(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        for name in bundle.namelist():
            target = (destination / name).resolve()
            if target != root and root not in target.parents:
                raise RuntimeError(f"UPX archive contains an unsafe path: {name}")
        bundle.extractall(destination)


def provision_upx(platform: str, cache_dir: Path) -> Path:
    asset_name, expected_sha, executable_name = UPX_ASSETS[platform]
    cache_dir.mkdir(parents=True, exist_ok=True)
    archive = cache_dir / asset_name
    if not archive.exists() or sha256(archive) != expected_sha:
        archive.unlink(missing_ok=True)
        print(f"Downloading pinned UPX {UPX_VERSION}: {asset_name}")
        download(f"{UPX_RELEASE_BASE}/{asset_name}", archive)
    actual_sha = sha256(archive)
    if actual_sha != expected_sha:
        archive.unlink(missing_ok=True)
        raise RuntimeError(
            f"UPX checksum mismatch for {asset_name}: expected {expected_sha}, got {actual_sha}"
        )

    extract_dir = cache_dir / f"upx-{UPX_VERSION}-{platform}"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True)
    if archive.suffix == ".zip":
        safe_extract_zip(archive, extract_dir)
    else:
        safe_extract_tar(archive, extract_dir)

    matches = list(extract_dir.rglob(executable_name))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one {executable_name} in {asset_name}, found {len(matches)}"
        )
    upx = matches[0]
    upx.chmod(upx.stat().st_mode | stat.S_IXUSR)
    return upx


def github_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as output:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise RuntimeError(f"GitHub output {key} contains a newline")
            output.write(f"{key}={value}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-dir", type=Path, default=Path("target/release"))
    parser.add_argument("--stage-dir", type=Path, default=Path("dist/stage"))
    parser.add_argument(
        "--platform",
        required=True,
        choices=("linux-x86_64", "macos-arm64", "windows-x86_64"),
    )
    parser.add_argument("--expected-version")
    parser.add_argument("--upx-cache", type=Path, default=Path(".cache/upx"))
    parser.add_argument(
        "--skip-upx",
        action="store_true",
        help="Explicit local troubleshooting escape hatch; official builds must not use it.",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        default=(
            Path(os.environ["GITHUB_OUTPUT"])
            if os.environ.get("GITHUB_OUTPUT")
            else None
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    windows = args.platform.startswith("windows-")
    suffix = ".exe" if windows else ""

    # Canonicalize before any existence checks or recursive deletion. In
    # particular, this resolves symlinked parents so a harmless-looking path
    # cannot alias the repository, target tree, a mount point, or a filesystem
    # root. All later operations use the path that was actually validated.
    args.target_dir = args.target_dir.resolve(strict=False)
    args.stage_dir = validated_stage_dir(args.stage_dir, args.target_dir)

    required_names = (f"conman{suffix}", f"conmanctl{suffix}")
    missing = [name for name in required_names if not (args.target_dir / name).is_file()]
    if missing:
        raise RuntimeError(
            "required release executable(s) missing: "
            + ", ".join(str(args.target_dir / name) for name in missing)
        )

    source_executables = [args.target_dir / name for name in required_names]
    reject_embedded_build_paths(
        source_executables,
        [
            os.environ.get("HOME", ""),
            os.environ.get("USERPROFILE", ""),
            os.environ.get("GITHUB_WORKSPACE", ""),
        ],
    )

    if args.stage_dir.exists():
        shutil.rmtree(args.stage_dir)
    args.stage_dir.mkdir(parents=True)

    staged_executables: list[Path] = []
    for name in required_names:
        source = args.target_dir / name
        destination = args.stage_dir / name
        shutil.copy2(source, destination)
        staged_executables.append(destination)

    if windows:
        dll = args.target_dir / "ghostty-vt.dll"
        if not dll.is_file():
            raise RuntimeError(f"required Windows runtime library is missing: {dll}")
        shutil.copy2(dll, args.stage_dir / dll.name)

    version = reported_version(staged_executables[0])
    if args.expected_version and version != args.expected_version:
        raise RuntimeError(
            f"binary reports {version}, but release expects {args.expected_version}"
        )

    packed = False
    if args.platform in UPX_ASSETS and not args.skip_upx:
        upx = provision_upx(args.platform, args.upx_cache)
        run([str(upx.resolve()), "--version"])
        for executable in staged_executables:
            run([str(upx.resolve()), "--best", "--no-progress", str(executable.resolve())], timeout=180)
            run([str(upx.resolve()), "-t", str(executable.resolve())], timeout=180)
        packed = True
    elif args.platform in UPX_ASSETS:
        print("WARNING: UPX explicitly skipped; this is not permitted for official artifacts")

    # Packing must not alter identity or startup viability. This smoke check also
    # runs on macOS, where UPX is intentionally unsupported.
    for executable in staged_executables:
        if reported_version(executable) != version:
            raise RuntimeError(f"version changed after staging/finalization: {executable}")

    metadata = {
        "version": version,
        "sanitized_version": sanitize_version(version),
        "platform": args.platform,
        "packed_with_upx": packed,
        "upx_version": UPX_VERSION if packed else None,
        "executables": [path.name for path in staged_executables],
    }
    metadata_path = args.stage_dir / "release-metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    if args.github_output:
        github_output(
            args.github_output,
            {
                "version": version,
                "sanitized_version": metadata["sanitized_version"],
                "platform": args.platform,
                "stage_dir": str(args.stage_dir),
            },
        )
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"release preparation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
