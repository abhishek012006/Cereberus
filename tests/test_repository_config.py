"""Offline checks for repository security configuration."""

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class TestRepositoryConfiguration(unittest.TestCase):
    def assert_git_ignore_result(self, path: str, expected: bool) -> None:
        if shutil.which("git") is None:
            self.skipTest("Git is unavailable in the test environment.")

        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", "--", path],
            cwd=ROOT,
            check=False,
        )
        self.assertEqual(result.returncode == 0, expected, path)

    def test_environment_variants_are_ignored(self):
        self.assert_git_ignore_result(".env.production", True)
        self.assert_git_ignore_result(".env.test", True)

    def test_environment_template_remains_trackable(self):
        self.assert_git_ignore_result(".env.example", False)


if __name__ == "__main__":
    unittest.main()
