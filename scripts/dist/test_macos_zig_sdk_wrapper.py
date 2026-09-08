from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


class MacosZigSdkWrapperTests(unittest.TestCase):
    def test_xcrun_sdk_query_uses_the_configured_compatible_sdk(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        wrapper = repository / "scripts" / "ci" / "xcrun"
        environment = os.environ.copy()
        environment["CONMAN_ZIG_MACOS_SDK"] = "/compatible/MacOSX.sdk"

        result = subprocess.run(
            [str(wrapper), "--sdk", "macosx", "--show-sdk-path"],
            check=True,
            capture_output=True,
            env=environment,
            text=True,
        )

        self.assertEqual(result.stdout.strip(), "/compatible/MacOSX.sdk")


if __name__ == "__main__":
    unittest.main()
