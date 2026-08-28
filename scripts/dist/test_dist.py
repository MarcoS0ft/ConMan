#!/usr/bin/env python3
"""Focused contract tests for the release staging/finalization scripts."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


SCRIPT_DIR = Path(__file__).resolve().parent
PREPARE = SCRIPT_DIR / "prepare_release.py"
PACKAGE = SCRIPT_DIR / "package_release.py"
TEST_VERSION = "0.1.0-dev.42+g0123456789"

PREPARE_SPEC = importlib.util.spec_from_file_location("conman_prepare_release", PREPARE)
if PREPARE_SPEC is None or PREPARE_SPEC.loader is None:
    raise RuntimeError(f"could not import {PREPARE}")
PREPARE_MODULE = importlib.util.module_from_spec(PREPARE_SPEC)
PREPARE_SPEC.loader.exec_module(PREPARE_MODULE)


def executable(path: Path, version: str = TEST_VERSION) -> None:
    path.write_text(f'#!/bin/sh\necho "ConMan {version}"\n', encoding="utf-8")
    path.chmod(0o755)


class DistributionContractTests(unittest.TestCase):
    def run_prepare(
        self, root: Path, platform: str, *extra: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(PREPARE),
                "--target-dir",
                str(root / "target"),
                "--stage-dir",
                str(root / "stage"),
                "--platform",
                platform,
                *extra,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_missing_conmanctl_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").mkdir()
            executable(root / "target/conman")

            result = self.run_prepare(root, "macos-arm64")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("required release executable(s) missing", result.stderr)
            self.assertIn("conmanctl", result.stderr)

    def test_stage_equal_to_target_fails_without_deleting_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").mkdir()
            executable(root / "target/conman")
            executable(root / "target/conmanctl")

            result = subprocess.run(
                [
                    sys.executable,
                    str(PREPARE),
                    "--target-dir",
                    str(root / "target"),
                    "--stage-dir",
                    str(root / "target"),
                    "--platform",
                    "macos-arm64",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe stage directory", result.stderr)
            self.assertTrue((root / "target/conman").is_file())
            self.assertTrue((root / "target/conmanctl").is_file())

    def test_stage_ancestor_of_target_fails_without_deleting_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "broad/target/release"
            target.mkdir(parents=True)
            executable(target / "conman")
            executable(target / "conmanctl")

            result = self.run_prepare_from_paths(
                target, root / "broad", "macos-arm64"
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contains the Cargo target directory", result.stderr)
            self.assertTrue((target / "conman").is_file())

    def test_filesystem_and_repository_roots_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            executable(target / "conman")
            executable(target / "conmanctl")

            for unsafe in (Path(unsafe_anchor(target)), SCRIPT_DIR.parents[1]):
                with self.subTest(stage=unsafe):
                    result = self.run_prepare_from_paths(
                        target, unsafe, "macos-arm64"
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("unsafe stage directory", result.stderr)
                    self.assertTrue((target / "conman").is_file())

    def test_sensitive_repository_children_are_rejected_with_sentinels_intact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            target = root / "target/release"
            target.mkdir(parents=True)
            executable(target / "conman")
            executable(target / "conmanctl")

            for child in (".git", "crates", "resources"):
                with self.subTest(child=child):
                    stage = repository / child
                    stage.mkdir(parents=True)
                    sentinel = stage / "must-survive.txt"
                    sentinel.write_text(f"sentinel:{child}", encoding="utf-8")

                    argv = [
                        str(PREPARE),
                        "--target-dir",
                        str(target),
                        "--stage-dir",
                        str(stage),
                        "--platform",
                        "macos-arm64",
                    ]
                    with mock.patch.object(
                        PREPARE_MODULE, "REPOSITORY_ROOT", repository
                    ), mock.patch.object(sys, "argv", argv):
                        with self.assertRaisesRegex(
                            RuntimeError, "repository child is outside"
                        ):
                            PREPARE_MODULE.main()

                    self.assertEqual(
                        sentinel.read_text(encoding="utf-8"), f"sentinel:{child}"
                    )

    def test_repository_dist_descendant_is_an_allowed_staging_location(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            target = root / "target/release"
            target.mkdir(parents=True)
            stage = repository / "dist/stage"

            with mock.patch.object(PREPARE_MODULE, "REPOSITORY_ROOT", repository):
                validated = PREPARE_MODULE.validated_stage_dir(stage, target)

            self.assertEqual(validated, stage.resolve())

    def test_symlinked_stage_into_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            executable(target / "conman")
            executable(target / "conmanctl")
            alias = root / "target-alias"
            try:
                alias.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            result = self.run_prepare_from_paths(
                target, alias / "stage", "macos-arm64"
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe stage directory", result.stderr)
            self.assertTrue((target / "conman").is_file())

    def test_symlinked_stage_to_filesystem_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            executable(target / "conman")
            executable(target / "conmanctl")
            alias = root / "root-alias"
            try:
                alias.symlink_to(Path(unsafe_anchor(target)), target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            result = self.run_prepare_from_paths(target, alias, "macos-arm64")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe stage directory", result.stderr)
            self.assertTrue((target / "conman").is_file())

    def test_windows_runtime_dll_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").mkdir()
            executable(root / "target/conman.exe")
            executable(root / "target/conmanctl.exe")

            result = self.run_prepare(root, "windows-x86_64", "--skip-upx")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ghostty-vt.dll", result.stderr)

    def test_macos_stages_both_executables_without_upx(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").mkdir()
            executable(root / "target/conman")
            executable(root / "target/conmanctl")

            result = self.run_prepare(root, "macos-arm64")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "stage/conman").is_file())
            self.assertTrue((root / "stage/conmanctl").is_file())
            metadata = json.loads((root / "stage/release-metadata.json").read_text())
            self.assertEqual(metadata["executables"], ["conman", "conmanctl"])
            self.assertFalse(metadata["packed_with_upx"])

    def test_expected_version_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").mkdir()
            executable(root / "target/conman")
            executable(root / "target/conmanctl")

            result = self.run_prepare(
                root, "macos-arm64", "--expected-version", "9.9.9"
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("release expects 9.9.9", result.stderr)

    def test_package_contains_both_windows_executables_and_dll(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "stage"
            stage.mkdir()
            for name in ("conman.exe", "conmanctl.exe", "ghostty-vt.dll"):
                (stage / name).write_bytes(name.encode())
            (stage / "release-metadata.json").write_text(
                json.dumps(
                    {
                        "version": "0.1.0",
                        "sanitized_version": "0.1.0",
                        "platform": "windows-x86_64",
                        "packed_with_upx": True,
                        "upx_version": "5.2.0",
                        "executables": ["conman.exe", "conmanctl.exe"],
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(PACKAGE),
                    "--stage-dir",
                    str(stage),
                    "--output-dir",
                    str(root / "packages"),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            archive = next((root / "packages").glob("*.zip"))
            with zipfile.ZipFile(archive) as bundle:
                members = {Path(name).name for name in bundle.namelist()}
            self.assertEqual(
                members, {"conman.exe", "conmanctl.exe", "ghostty-vt.dll"}
            )

    def run_prepare_from_paths(
        self, target: Path, stage: Path, platform: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(PREPARE),
                "--target-dir",
                str(target),
                "--stage-dir",
                str(stage),
                "--platform",
                platform,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )


def unsafe_anchor(path: Path) -> str:
    return path.resolve().anchor


if __name__ == "__main__":
    unittest.main()
