#!/usr/bin/env python3
"""Exercise the actual stdin bootstrap without network or system changes."""

import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = (ROOT / "install.sh").read_text(encoding="utf-8")
BOOTSTRAP = INSTALLER.split("# Bash does not populate BASH_SOURCE", 1)[1]
BOOTSTRAP = "# Bash does not populate BASH_SOURCE" + BOOTSTRAP.split("\nfor required_file in", 1)[0]
DEFAULTS = "\n".join(
    line for line in INSTALLER.splitlines()
    if line.startswith(("DEFAULT_REPOSITORY=", "DEFAULT_RELEASE_REF="))
)


class BootstrapTests(unittest.TestCase):
    def run_bootstrap(self, repository=None, release_ref=None):
        environment = os.environ.copy()
        environment.pop("QOS_REPOSITORY", None)
        environment.pop("QOS_RELEASE_REF", None)
        if repository is not None:
            environment["QOS_REPOSITORY"] = repository
        if release_ref is not None:
            environment["QOS_RELEASE_REF"] = release_ref
        harness = "\n".join([
            "set -Eeuo pipefail",
            DEFAULTS,
            'die() { printf "%s\\n" "$*" >&2; exit 1; }',
            'mktemp() { printf "/mock-bootstrap-download\\n"; }',
            'curl() { printf "DOWNLOAD %s\\n" "$*"; return 97; }',
            BOOTSTRAP,
        ])
        return subprocess.run(
            [environment.get("BASH_EXECUTABLE", "bash"), "--noprofile", "--norc", "-s"],
            input=harness, text=True, capture_output=True, env=environment,
            check=False,
        )

    def test_stdin_reaches_default_release_download(self):
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 97, result.stderr)
        self.assertIn("/archive/refs/tags/v1.3.1.tar.gz", result.stdout)
        self.assertNotIn("unbound variable", result.stderr)

    def test_override_repository_and_ref(self):
        result = self.run_bootstrap("example-owner/example-repo", "v2.0.0")
        self.assertEqual(result.returncode, 97, result.stderr)
        self.assertIn(
            "https://github.com/example-owner/example-repo/archive/refs/tags/v2.0.0.tar.gz",
            result.stdout,
        )

    def test_unresolved_repository_is_rejected_without_download(self):
        result = self.run_bootstrap("__REPO_" + "SLUG__")
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid QOS_REPOSITORY", result.stderr)
        self.assertNotIn("DOWNLOAD", result.stdout)


if __name__ == "__main__":
    unittest.main()
