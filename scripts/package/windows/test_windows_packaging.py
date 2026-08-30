#!/usr/bin/env python3
"""Portable contract checks for the Windows package definition."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[3]
DEFINITION = REPOSITORY / "packaging/windows/conman.nsi"
BUILD_SCRIPT = REPOSITORY / "scripts/package/windows/build.ps1"
VALIDATE_SCRIPT = REPOSITORY / "scripts/package/windows/validate.ps1"
INSTALL_SMOKE = REPOSITORY / "scripts/package/windows/install-smoke.ps1"


class WindowsPackagingContracts(unittest.TestCase):
    def test_installer_has_both_scopes_and_complete_payload(self) -> None:
        source = DEFINITION.read_text(encoding="utf-8")
        for required in (
            "MULTIUSER_PAGE_INSTALLMODE",
            "MULTIUSER_INSTALLMODE_COMMANDLINE",
            'File "${STAGE_DIR}\\conman.exe"',
            'File "${STAGE_DIR}\\conmanctl.exe"',
            'File "${STAGE_DIR}\\ghostty-vt.dll"',
            'File "update-path.ps1"',
            "-Action Add -Scope $1 -Entry",
            "-Action Remove -Scope $1 -Entry",
            'WriteRegDWORD ShCtx "${UNINSTALL_KEY}" "PathEntryAdded" 1',
            'WriteRegStr ShCtx "${UNINSTALL_KEY}" "PathAddMode"',
        ):
            self.assertIn(required, source)

    def test_packaging_sources_contain_no_machine_specific_network_details(self) -> None:
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (DEFINITION, BUILD_SCRIPT, VALIDATE_SCRIPT, INSTALL_SMOKE)
        )
        self.assertNotIn("10.200.", combined)
        self.assertNotIn("devlocal", combined.lower())
        self.assertNotIn("devstation", combined.lower())

    @unittest.skipUnless(shutil.which("makensis"), "makensis is not installed")
    def test_nsis_definition_compiles_with_the_required_runtime_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "stage"
            stage.mkdir()
            for name in ("conman.exe", "conmanctl.exe", "ghostty-vt.dll"):
                (stage / name).write_bytes(name.encode("ascii"))
            installer = root / "conman-setup.exe"

            result = subprocess.run(
                [
                    shutil.which("makensis") or "makensis",
                    "-V2",
                    "-DPRODUCT_VERSION=0.1.0-dev.1+g0123456789",
                    f"-DSTAGE_DIR={stage}",
                    f"-DOUTPUT_FILE={installer}",
                    str(DEFINITION),
                ],
                cwd=REPOSITORY,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertTrue(installer.is_file())
            self.assertGreater(installer.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
