from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


class LibghosttyBuildContractTests(unittest.TestCase):
    def test_zig_cache_layout_contract(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        build_script = repository / "vendor" / "libghostty-vt-sys" / "build.rs"

        with tempfile.TemporaryDirectory() as directory:
            test_binary = Path(directory) / "libghostty-build-tests"
            subprocess.run(
                [
                    "rustc",
                    "--edition=2024",
                    "--test",
                    str(build_script),
                    "-o",
                    str(test_binary),
                ],
                check=True,
            )
            subprocess.run([str(test_binary)], check=True)


if __name__ == "__main__":
    unittest.main()
