import json
import tempfile
import unittest
from pathlib import Path

from cull.llm.cache import VerdictCache, cache_key
from cull.llm.chunker import chunk_text
from cull.llm.discover import discover
from cull.llm.filter import should_scan
from cull.llm.orchestrator import ScanOptions, estimate, prepare
from cull.llm.pricing import cost_for, estimate_tokens, normalize_model_id
from cull.llm.schema import Finding, PackageFile, Verdict, merge_verdicts, validate_verdict


def _verdict(level, confidence, summary, findings):
    return Verdict(level, confidence, summary, findings)


def _finding(indicator, snippet, explanation="why " * 6):
    return Finding(indicator, snippet, explanation)


class ValidateVerdictTests(unittest.TestCase):
    def test_clean_drops_summary_and_findings(self):
        verdict = validate_verdict({"level": "clean", "confidence": "high", "summary": "ignored", "findings": []})
        self.assertEqual(verdict.level, "clean")
        self.assertEqual(verdict.summary, "")
        self.assertEqual(verdict.findings, [])

    def test_clean_with_findings_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_verdict(
                {
                    "level": "clean",
                    "confidence": "high",
                    "summary": "",
                    "findings": [{"indicator": "other", "snippet": "x", "explanation": "x"}],
                }
            )

    def test_malicious_keeps_finding_explanation(self):
        explanation = "Reads NPM_TOKEN at install time, reusable to publish compromised releases. " * 2
        verdict = validate_verdict(
            {
                "level": "malicious",
                "confidence": "high",
                "summary": "Package reads npm credentials during install.",
                "findings": [
                    {"indicator": "credential_theft", "snippet": "process.env.NPM_TOKEN", "explanation": explanation}
                ],
            }
        )
        self.assertEqual(verdict.findings[0].indicator, "credential_theft")
        self.assertIn("NPM_TOKEN", verdict.findings[0].explanation)

    def test_non_clean_finding_requires_explanation(self):
        with self.assertRaises(ValueError):
            validate_verdict(
                {
                    "level": "suspicious",
                    "confidence": "medium",
                    "summary": "Runs an install hook.",
                    "findings": [{"indicator": "install_hook", "snippet": "postinstall", "explanation": ""}],
                }
            )


class ChunkerTests(unittest.TestCase):
    def _line_text(self, lines: int) -> str:
        return "".join(f"L{i:05d}\n" for i in range(lines))

    def test_short_text_yields_single_chunk(self):
        chunks = chunk_text("small payload", token_budget=200, overlap_tokens=50)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].text, "small payload")

    def test_every_byte_covered_by_some_chunk(self):
        text = self._line_text(8000)
        chunks = chunk_text(text, token_budget=200, overlap_tokens=50)
        self.assertGreater(len(chunks), 10)

        covered = bytearray(len(text))
        cursor = 0
        for chunk in chunks:
            offset = text.find(chunk.text, max(0, cursor - len(chunk.text)))
            self.assertGreaterEqual(offset, 0)
            covered[offset:offset + len(chunk.text)] = b"\x01" * len(chunk.text)
            cursor = offset + len(chunk.text)
        self.assertNotIn(0, covered)

    def test_consecutive_chunks_overlap(self):
        text = self._line_text(8000)
        chunks = chunk_text(text, token_budget=200, overlap_tokens=50)
        self.assertGreater(len(chunks), 1)
        next_start = text.find(chunks[1].text)
        overlap = len(chunks[0].text) - next_start
        self.assertGreater(overlap, 0)

    def test_chunks_carry_index_metadata(self):
        chunks = chunk_text(self._line_text(2000), token_budget=200, overlap_tokens=50)
        for index, chunk in enumerate(chunks, start=1):
            self.assertEqual(chunk.index, index)
            self.assertEqual(chunk.total, len(chunks))


class FilterTests(unittest.TestCase):
    def _make_file(self, root: Path, rel: str, content: bytes = b"x = 1\n") -> PackageFile:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return PackageFile(
            ecosystem="npm",
            package="demo",
            version="1.0.0",
            package_root=root,
            rel_path=Path(rel),
            abs_path=path,
            real_path=path.resolve(),
            size=path.stat().st_size,
        )

    def test_skips_type_declarations_and_sourcemaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in ("index.d.ts", "bundle.js.map", "image.png"):
                keep, reason = should_scan(self._make_file(root, rel), include_tests=False)
                self.assertFalse(keep, rel)
                self.assertEqual(reason, "unsupported extension")

    def test_skips_doc_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in ("README.md", "LICENSE", "CHANGELOG.md", "notes.txt"):
                keep, reason = should_scan(self._make_file(root, rel), include_tests=False)
                self.assertFalse(keep, rel)
                self.assertEqual(reason, "docs")

    def test_skips_test_directories_unless_opted_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = self._make_file(root, "__tests__/index.js")
            self.assertEqual(should_scan(file, include_tests=False), (False, "test file"))
            self.assertEqual(should_scan(file, include_tests=True), (True, ""))

    def test_skips_binary_by_null_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = self._make_file(root, "weird.js", content=b"\x00\x00\x00binary")
            keep, reason = should_scan(file, include_tests=False)
            self.assertFalse(keep)
            self.assertEqual(reason, "binary")

    def test_keeps_normal_javascript(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = self._make_file(root, "src/index.js", content=b"export const x = 1;\n")
            self.assertEqual(should_scan(file, include_tests=False), (True, ""))


class MergeVerdictsTests(unittest.TestCase):
    def test_empty_list_returns_clean(self):
        merged = merge_verdicts([])
        self.assertEqual(merged.level, "clean")
        self.assertEqual(merged.findings, [])

    def test_worst_level_wins(self):
        clean = _verdict("clean", "high", "", [])
        suspicious = _verdict("suspicious", "low", "minor", [_finding("install_hook", "postinstall")])
        malicious = _verdict("malicious", "high", "exfil", [_finding("network_exfil", "curl evil.tld")])
        merged = merge_verdicts([clean, suspicious, malicious])
        self.assertEqual(merged.level, "malicious")
        self.assertEqual(merged.confidence, "high")
        self.assertEqual(merged.summary, "exfil")

    def test_dedup_by_indicator_and_normalized_snippet(self):
        a = _verdict("malicious", "high", "x", [_finding("network_exfil", "curl   evil.tld")])
        b = _verdict("malicious", "high", "x", [_finding("network_exfil", "curl evil.tld")])
        merged = merge_verdicts([a, b])
        self.assertEqual(len(merged.findings), 1)

    def test_caps_findings_at_ten(self):
        findings = [_finding("other", f"snippet {i}") for i in range(25)]
        verdict = _verdict("malicious", "high", "many", findings)
        merged = merge_verdicts([verdict])
        self.assertEqual(len(merged.findings), 10)


class CacheTests(unittest.TestCase):
    def test_round_trip_persists_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.json"
            cache = VerdictCache(path=path)
            verdict = _verdict("malicious", "high", "exfil", [_finding("network_exfil", "curl evil.tld")])
            cache.set("k", verdict)
            cache.flush()

            reopened = VerdictCache(path=path)
            loaded = reopened.get("k")
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.level, "malicious")
            self.assertEqual(loaded.findings[0].indicator, "network_exfil")

    def test_disabled_cache_skips_io(self):
        cache = VerdictCache(enabled=False, path=Path("/nonexistent/cull/cache.json"))
        cache.set("k", _verdict("clean", "high", "", []))
        cache.flush()
        self.assertIsNone(cache.get("k"))

    def test_cache_key_changes_with_model_or_prompt(self):
        base = cache_key("chunk", model="gemini-3.1-flash-lite", prompt_version="v1")
        self.assertNotEqual(base, cache_key("chunk", model="gemini-3.1-flash-lite", prompt_version="v2"))
        self.assertNotEqual(base, cache_key("chunk", model="other", prompt_version="v1"))
        self.assertEqual(base, cache_key("chunk", model="gemini-3.1-flash-lite", prompt_version="v1"))


class PricingTests(unittest.TestCase):
    def test_normalize_strips_provider_and_date_suffix(self):
        self.assertEqual(
            normalize_model_id("google/gemini-3.1-flash-lite-preview-20260303"),
            "gemini-3.1-flash-lite-preview",
        )

    def test_estimate_tokens_matches_heuristic(self):
        self.assertAlmostEqual(estimate_tokens("x" * 35), 10, delta=1)
        self.assertEqual(estimate_tokens(""), 1)

    def test_cost_for_known_model_is_positive(self):
        cost = cost_for("gemini-3.1-flash-lite", 1_000_000, 1_000_000)
        self.assertIsNotNone(cost)
        self.assertGreater(cost, 0)


class DiscoverAndEstimateTests(unittest.TestCase):
    def test_node_modules_discovery_and_estimate(self):
        with tempfile.TemporaryDirectory() as tmp:
            node_modules = Path(tmp) / "node_modules"
            package = node_modules / "@scope" / "demo"
            package.mkdir(parents=True)
            (package / "package.json").write_text(json.dumps({"name": "@scope/demo", "version": "1.0.0"}), encoding="utf-8")
            (package / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
            (package / "README.md").write_text("docs\n", encoding="utf-8")

            files, errors = discover([str(node_modules)])
            self.assertFalse(errors)
            self.assertTrue(any(file.package == "@scope/demo" for file in files))

            options = ScanOptions(
                include_tests=False,
                no_cache=True,
                concurrency=1,
                max_files_per_pkg=200,
                chunk_tokens=4000,
                chunk_overlap_tokens=600,
                progress=False,
            )
            prepared = prepare([str(node_modules)], options)
            self.assertEqual(len(prepared.files), 2)

            result = estimate(prepared.files, model="gemini-3.1-flash-lite", options=options)
            self.assertEqual(result.package_count, 1)
            self.assertEqual(result.file_count, 2)
            self.assertEqual(result.chunk_count, 2)
            self.assertIsNotNone(result.estimated_cost_usd)


if __name__ == "__main__":
    unittest.main()
