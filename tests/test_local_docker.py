import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import cull
from cull import scanners


class LocalDockerTests(unittest.TestCase):
    def test_scan_layer_reports_oversized_entries(self):
        entry = SimpleNamespace(
            isfile=lambda: True,
            size=cull.MAX_FILE_BYTES + 1,
            name="app/pnpm-lock.yaml",
        )

        class FakeLayer:
            def __iter__(self):
                return iter([entry])

        findings = []
        cull._scan_layer(FakeLayer(), "img:tag", [cull.Target("axios", "1.2.3")], findings)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "error")
        self.assertIn("exceeds size limit", findings[0].version)

    def test_scan_local_finds_lockfile_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "package-lock.json"
            path.write_text(
                '{"packages":{"node_modules/axios":{"version":"1.2.3"}}}',
                encoding="utf-8",
            )
            findings = cull.scan_local([tmpdir], "axios", "1.2.3")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "found")
        self.assertEqual(findings[0].version, "1.2.3")

    def test_scan_local_reports_invalid_directory(self):
        findings = cull.scan_local(["/definitely/not/a/real/dir"], "axios", "1.2.3")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "error")

    def test_scan_single_image_no_pull_returns_error(self):
        with mock.patch.object(
            scanners,
            "run",
            return_value=cull.RunResult(False, detail="No such image"),
        ):
            findings = cull._scan_single_image(
                "repo/image:tag",
                [cull.Target("axios", "1.2.3")],
                auto_pull=False,
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "error")
        self.assertIn("use without --no-pull", findings[0].version)
