from __future__ import annotations

import unittest

from configure_rust_path_remap import remap_flags


class RustPathRemapTests(unittest.TestCase):
    def test_remaps_home_and_workspace_and_preserves_existing_flags(self) -> None:
        self.assertEqual(
            remap_flags("/Users/build", "/Users/Shared/actions-work/conman", "-Copt-level=2"),
            "-Copt-level=2 "
            "--remap-path-prefix=/Users/build=/build/home "
            "--remap-path-prefix=/Users/Shared/actions-work/conman=/build/conman",
        )

    def test_rejects_roots_that_rustflags_cannot_represent_safely(self) -> None:
        with self.assertRaisesRegex(ValueError, "no whitespace"):
            remap_flags("/Users/Build User", "/work/conman")


if __name__ == "__main__":
    unittest.main()
