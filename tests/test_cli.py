import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import cull


class CliTests(unittest.TestCase):
    def test_main_exits_with_error_for_missing_github_token(self):
        argv = ["cull", "axios@1.2.3", "--github-org", "openai"]
        with mock.patch.object(sys, "argv", argv):
            with self.assertRaises(SystemExit) as exc:
                cull.main()
        self.assertEqual(exc.exception.code, 2)

    def test_installed_cli_runs_clean_locally(self):
        repo_root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo_root)
        proc = subprocess.run(
            [sys.executable, "-m", "cull", "axios@9.9.9", "--dirs", "."],
            cwd=repo_root,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Result: clean", proc.stdout)
