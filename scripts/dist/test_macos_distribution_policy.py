#!/usr/bin/env python3
"""Regression checks for downloadable macOS distribution policy."""

from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
APPLE_SECRETS = (
    "MACOS_CERTIFICATE_P12",
    "MACOS_CERTIFICATE_PASSWORD",
    "CONMAN_MACOS_APP_PROVISIONING_PROFILE",
    "CONMAN_MACOS_CLI_PROVISIONING_PROFILE",
    "NOTARIZE_API_KEY_ID",
    "NOTARIZE_API_KEY_ISSUER",
    "NOTARIZE_API_KEY_P8_BASE64",
)


class MacosDistributionPolicyTests(unittest.TestCase):
    def test_rolling_downloads_require_the_explicit_signing_contract(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/dev-release.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("sign_macos: true", workflow)
        self.assertNotIn("ad-hoc signed and is not notarized", workflow)
        for name in APPLE_SECRETS:
            with self.subTest(secret=name):
                self.assertIn(f"{name}: ${{{{ secrets.{name} }}}}", workflow)

    def test_only_the_signed_outer_dmg_is_submitted_and_stapled(self) -> None:
        release_script = (
            REPOSITORY_ROOT / "scripts/package/macos/release.sh"
        ).read_text(encoding="utf-8")
        validator = (
            REPOSITORY_ROOT / "scripts/package/macos/validate.sh"
        ).read_text(encoding="utf-8")

        self.assertEqual(release_script.count('notarize "$dmg"'), 1)
        self.assertNotIn('notarize "$zip_path"', release_script)
        self.assertNotIn('stapler staple "$app"', release_script)
        self.assertIn('codesign "${dmg_sign_args[@]}" "$dmg"', release_script)
        self.assertIn(
            "spctl --assess --type open --context context:primary-signature",
            validator,
        )

    def test_gui_and_cli_are_separately_profiled_for_one_access_group(self) -> None:
        builder = (REPOSITORY_ROOT / "scripts/package/macos/build-app.sh").read_text(
            encoding="utf-8"
        )
        validator = (
            REPOSITORY_ROOT / "scripts/package/macos/validate.sh"
        ).read_text(encoding="utf-8")
        gui_entitlements = (
            REPOSITORY_ROOT / "packaging/macos/ConMan.entitlements"
        ).read_text(encoding="utf-8")
        cli_entitlements = (
            REPOSITORY_ROOT / "packaging/macos/conmanctl.entitlements"
        ).read_text(encoding="utf-8")

        self.assertIn('cli_app="$app/Contents/Helpers/conmanctl.app"', builder)
        self.assertIn('cli_executable="$cli_app/Contents/MacOS/conmanctl"', builder)
        self.assertIn("Developer ID signing requires GUI and conmanctl", builder)
        self.assertIn("--require-keychain-sharing", validator)
        expected_group = "2NZRF4HQT7.com.marcos0ft.conman.shared"
        self.assertIn(expected_group, gui_entitlements)
        self.assertIn(expected_group, cli_entitlements)
        self.assertIn("2NZRF4HQT7.com.marcos0ft.conman</string>", gui_entitlements)
        self.assertIn(
            "2NZRF4HQT7.com.marcos0ft.conman.conmanctl</string>", cli_entitlements
        )


if __name__ == "__main__":
    unittest.main()
