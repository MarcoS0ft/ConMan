#!/usr/bin/env python3
"""Portable contract checks for the Windows Velopack package definition."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import unittest


REPOSITORY = Path(__file__).resolve().parents[3]
TOOLCHAIN = REPOSITORY / "packaging/windows/velopack-toolchain.json"
BUILD_SCRIPT = REPOSITORY / "scripts/package/windows/build.ps1"
VALIDATE_SCRIPT = REPOSITORY / "scripts/package/windows/validate.ps1"
BOOTSTRAP_SCRIPT = REPOSITORY / "scripts/package/windows/bootstrap-velopack.ps1"
ADAPTER = REPOSITORY / "crates/conman/src/windows_velopack.rs"
VERSION_SCRIPT = REPOSITORY / "scripts/package/windows/version.ps1"


@unittest.skipUnless(shutil.which("pwsh") or shutil.which("powershell"), "PowerShell required")
class MsiVersionTests(unittest.TestCase):
    def version(self, version: str, revision: int) -> subprocess.CompletedProcess[str]:
        shell = shutil.which("pwsh") or shutil.which("powershell")
        script = (
            "$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest; "
            f". '{str(VERSION_SCRIPT).replace(chr(39), chr(39) * 2)}'; "
            f"Get-ConManMsiVersion -Version '{version}' -Revision {revision}"
        )
        return subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, check=False,
        )

    def resolved(self, version: str, revision: int) -> tuple[int, ...]:
        result = self.version(version, revision)
        self.assertEqual(result.returncode, 0, result.stderr)
        parts = tuple(map(int, result.stdout.strip().split(".")))
        self.assertEqual(len(parts), 3, "MSI ignores a fourth field")
        return parts

    def test_dev_builds_upgrade_using_the_first_three_fields(self) -> None:
        old = self.resolved("0.1.0-dev.405+g0123456789", 405)
        new = self.resolved("0.1.0-dev.406+gabcdef0123", 406)
        self.assertEqual(new, (0, 1, 812))
        self.assertGreater(new, old)

    def test_stable_sorts_after_same_revision_dev_and_before_next_dev(self) -> None:
        dev = self.resolved("0.1.0-dev.406+gabcdef0123", 406)
        stable = self.resolved("0.1.0", 406)
        next_dev = self.resolved("0.1.1-dev.407+g0123456789", 407)
        self.assertEqual(stable, (0, 1, 813))
        self.assertLess(dev, stable)
        self.assertLess(stable, next_dev)

    def test_bounds_fail_instead_of_wrapping_or_colliding(self) -> None:
        self.assertEqual(self.resolved("255.255.1", 32767), (255, 255, 65535))
        for version, revision in [
            ("0.1.0", 32768), ("256.1.0", 1), ("0.256.0", 1),
            ("0.1.0", 0), ("0.1.0", -1),
            ("0.1.0-dev.405+g0123456789", 406), ("0.1.0-rc.1", 406),
        ]:
            with self.subTest(version=version, revision=revision):
                self.assertNotEqual(self.version(version, revision).returncode, 0)


class WindowsPackagingContracts(unittest.TestCase):
    def test_velopack_is_pinned_to_the_w0_approved_version_and_checksum(self) -> None:
        toolchain = json.loads(TOOLCHAIN.read_text(encoding="utf-8"))
        self.assertEqual(toolchain["version"], "1.2.0")
        self.assertEqual(toolchain["runtime"], "net8.0")
        self.assertRegex(toolchain["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("3e458a676be46d1122e522312db18411f36ea8c70e586f81a676695d43f89dbc", toolchain["sha256"])
        self.assertNotIn("latest", toolchain["url"].lower())

    def test_build_uses_one_velopack_lineage_and_no_nsis(self) -> None:
        source = BUILD_SCRIPT.read_text(encoding="utf-8")
        validation = VALIDATE_SCRIPT.read_text(encoding="utf-8")
        bootstrap = BOOTSTRAP_SCRIPT.read_text(encoding="utf-8")
        combined = "\n".join((source, validation, bootstrap))
        for required in (
            "com.marcos0ft.conman",
            '"--runtime", "win-x64"',
            '"--msi", "true"',
            '"--instLocation", "Either"',
            '"--delta", "None"',
            "-full.nupkg",
            "-setup.exe",
            ".msi",
            "conmanctl.exe",
            "ghostty-vt.dll",
            "licenses",
            "velopack-toolchain.json",
        ):
            self.assertIn(required, combined)
        self.assertNotIn("makensis", combined.lower())
        self.assertNotIn("conman.nsi", combined.lower())

    def test_packaging_sources_contain_no_machine_specific_network_details(self) -> None:
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (BUILD_SCRIPT, VALIDATE_SCRIPT, BOOTSTRAP_SCRIPT, ADAPTER)
        )
        self.assertNotIn("10.200.", combined)
        self.assertNotIn("devlocal", combined.lower())
        self.assertNotIn("devstation", combined.lower())

    def test_package_validation_is_exact_and_portable_is_immutable(self) -> None:
        source = VALIDATE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Compare-Object", source)
        self.assertIn("bin/conmanctl.exe", source)
        self.assertIn("Portable ZIP contents differ", source)
        self.assertIn("sha256", source.lower())
        self.assertIn("only installed-update asset", source)

    def test_build_and_validation_share_the_msi_version_mapping(self) -> None:
        for path in (BUILD_SCRIPT, VALIDATE_SCRIPT):
            source = path.read_text(encoding="utf-8")
            self.assertIn('"version.ps1"', source)
            self.assertIn("Get-ConManMsiVersion", source)
            self.assertIn("rev-list --count HEAD", source)
        validation = VALIDATE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("WindowsInstaller.Installer", validation)
        self.assertIn("ProductVersion", validation)

    def test_startup_and_lifecycle_contract(self) -> None:
        source = ADAPTER.read_text(encoding="utf-8")
        for required in (
            "is_internal_hook",
            "set_auto_apply_on_startup(false)",
            "on_after_install_fast_callback",
            "on_after_update_fast_callback",
            "on_before_update_fast_callback",
            "on_before_uninstall_fast_callback",
            "wait_exit_then_apply_updates",
            "get_is_portable",
            "detect_install_context",
            "conman-path.marker",
            "terminators",
            "KEY_WOW64_64KEY",
            "broadcast_environment_change",
        ):
            self.assertIn(required, source)
        self.assertNotIn(".check_for_updates", source)
        self.assertNotIn(".apply_updates_and_restart", source)

    def test_no_legacy_installer_definition_remains(self) -> None:
        self.assertFalse((REPOSITORY / "packaging/windows/conman.nsi").exists())

    def test_smoke_checks_scope_metadata_and_lifecycle_artifacts(self) -> None:
        smoke = (REPOSITORY / "scripts/package/windows/install-smoke.ps1").read_text(
            encoding="utf-8"
        )
        for required in (
            "Get-PathRegistrySnapshot",
            "Registry64",
            "WScript.Shell",
            "Add/Remove Programs",
            "PATH text, registry type",
            "msiexec.exe",
            "conmanctl.exe",
        ):
            self.assertIn(required, smoke)


if __name__ == "__main__":
    unittest.main()
