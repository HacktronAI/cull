import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import cull


class ParsingTests(unittest.TestCase):
    def test_parse_pkg_arg_supports_scoped_packages(self):
        target = cull.parse_pkg_arg("@nestjs/axios@4.0.0")
        self.assertEqual(target.name, "@nestjs/axios")
        self.assertEqual(target.version, "4.0.0")

    def test_pnpm_versions_keep_build_metadata(self):
        content = "packages:\n  /axios/1.2.3+build.1:\n    resolution: {}\n"
        self.assertEqual(
            cull._versions_from_pnpm_lock(content, "axios"),
            {"1.2.3+build.1"},
        )

    def test_versions_from_npm_lock_finds_nested_dependency(self):
        content = """
        {
          "packages": {},
          "dependencies": {
            "foo": {
              "version": "1.0.0",
              "dependencies": {
                "axios": {
                  "version": "1.2.3"
                }
              }
            }
          }
        }
        """
        self.assertEqual(cull._versions_from_npm_lock(content, "axios"), {"1.2.3"})

    def test_check_content_or_error_flags_unparsable_lockfile(self):
        result = cull._check_content_or_error(
            "axios: 1.2.3\n",
            "axios",
            "1.2.3",
            "local",
            "repo/pnpm-lock.yaml",
            "pnpm-lock.yaml",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "error")
        self.assertIn("could not be parsed", result.version)

    def test_check_lockfile_reports_oversized_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "package-lock.json"
            path.write_text("{}")
            with mock.patch.object(
                Path,
                "stat",
                return_value=SimpleNamespace(st_size=cull.MAX_FILE_BYTES + 1),
            ):
                result = cull._check_lockfile(path, "axios", "1.2.3")

        self.assertIsNotNone(result)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.version, "exceeds size limit")
