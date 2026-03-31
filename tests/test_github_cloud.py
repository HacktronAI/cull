import unittest
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlparse

import cull
from cull import scanners


class GitHubCloudTests(unittest.TestCase):
    def test_scan_github_marks_search_failure_as_error(self):
        with mock.patch.object(scanners, "http_get", return_value=None):
            findings = cull.scan_github("token", "org", "axios", "1.2.3")

        self.assertTrue(findings)
        self.assertTrue(all(f.status == "error" for f in findings))

    def test_scan_github_fetches_multiple_pages(self):
        responses = {
            1: {
                "total_count": 150,
                "items": [
                    {"repository": {"full_name": "org/repo"}, "path": "package-lock.json"}
                ] * 100,
            },
            2: {
                "total_count": 150,
                "items": [
                    {"repository": {"full_name": "org/repo"}, "path": "package-lock.json"}
                ] * 50,
            },
        }
        seen_pages = []

        def fake_http_get(url, headers):
            page = int(parse_qs(urlparse(url).query)["page"][0])
            seen_pages.append(page)
            return responses[page]

        with mock.patch.object(scanners, "http_get", side_effect=fake_http_get):
            findings = cull.scan_github("token", "org", "axios", None)

        self.assertEqual(seen_pages, [1, 2] * len(cull.LOCK_FILES))
        self.assertEqual(len(findings), 150 * len(cull.LOCK_FILES))

    def test_list_gar_images_splits_multiple_tags(self):
        with mock.patch.object(
            scanners,
            "run",
            return_value=cull.RunResult(
                True,
                stdout="us-central1-docker.pkg.dev/proj/repo/img\tv1,v2",
            ),
        ):
            images, error = cull.list_gar_images("repo")

        self.assertIsNone(error)
        self.assertEqual(
            images,
            [
                "us-central1-docker.pkg.dev/proj/repo/img:v1",
                "us-central1-docker.pkg.dev/proj/repo/img:v2",
            ],
        )

    def test_list_gar_images_rejects_malformed_output(self):
        with mock.patch.object(
            scanners,
            "run",
            return_value=cull.RunResult(True, stdout="pkg-only-no-tag"),
        ):
            images, error = cull.list_gar_images("repo")

        self.assertEqual(images, [])
        self.assertIn("unexpected gcloud GAR output", error)

    def test_collect_images_surfaces_missing_clis_as_errors(self):
        args = SimpleNamespace(images=None, docker=True, gcr_project="proj", gar_repo="repo")
        with mock.patch.object(scanners, "has_cmd", return_value=False):
            images, findings = cull._collect_images(args)

        self.assertEqual(images, [])
        self.assertEqual(
            [(f.source, f.status) for f in findings],
            [("docker", "error"), ("gcr", "error"), ("gar", "error")],
        )

    def test_list_gcr_images_propagates_tag_listing_errors(self):
        results = [
            cull.RunResult(True, stdout="gcr.io/test/repo"),
            cull.RunResult(False, detail="permission denied"),
        ]
        with mock.patch.object(scanners, "run", side_effect=results):
            images, error = cull.list_gcr_images("proj")

        self.assertEqual(images, [])
        self.assertIn("failed listing tags for gcr.io/test/repo", error)
