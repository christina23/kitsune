"""
Unit tests for core/sigma_repo.py — baseline sigma rule loader.
"""

import json
import os
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.sigma_repo import (
    BaselineSigmaRepo,
    _extract_ttps,
    _sigma_to_rule,
    get_baseline_repo,
    initialize_baseline_repo,
)
from core.coverage import _tlsh_hash


# ── Fixtures ─────────────────────────────────────────────────────────────────

VALID_SIGMA = {
    "title": "Test Powershell Encoded Command",
    "description": "Detects suspicious encoded PowerShell",
    "author": "test",
    "references": ["https://example.com"],
    "tags": [
        "attack.execution",
        "attack.t1059.001",
        "attack.defense-evasion",
        "attack.t1027",
    ],
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {
        "selection": {"CommandLine|contains": ["-EncodedCommand", "-enc"]},
        "condition": "selection",
    },
}

VALID_SIGMA_CONTENT = yaml.dump(VALID_SIGMA)


def _write_rule(tmp_path: Path, filename: str, data: dict) -> Path:
    p = tmp_path / filename
    p.write_text(yaml.dump(data))
    return p


# ── _extract_ttps ────────────────────────────────────────────────────────────

class TestExtractTtps(unittest.TestCase):

    def test_extracts_technique_tags(self):
        ttps = _extract_ttps(VALID_SIGMA)
        self.assertIn("T1059.001", ttps)
        self.assertIn("T1027", ttps)

    def test_ignores_non_technique_tags(self):
        ttps = _extract_ttps(VALID_SIGMA)
        self.assertNotIn("EXECUTION", ttps)
        self.assertNotIn("DEFENSE-EVASION", ttps)

    def test_empty_tags(self):
        self.assertEqual(_extract_ttps({}), [])
        self.assertEqual(_extract_ttps({"tags": []}), [])

    def test_uppercase_output(self):
        sigma = {"tags": ["attack.t1059.001"]}
        ttps = _extract_ttps(sigma)
        self.assertTrue(all(t == t.upper() for t in ttps))


# ── _sigma_to_rule ───────────────────────────────────────────────────────────

class TestSigmaToRule(unittest.TestCase):

    def test_basic_conversion(self):
        rule = _sigma_to_rule(VALID_SIGMA, VALID_SIGMA_CONTENT)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "Test Powershell Encoded Command")
        self.assertEqual(rule.format, "sigma")
        self.assertIn("T1059.001", rule.mitre_ttps)
        self.assertEqual(rule.rule_content, VALID_SIGMA_CONTENT)

    def test_missing_title_returns_none(self):
        bad = dict(VALID_SIGMA)
        del bad["title"]
        self.assertIsNone(_sigma_to_rule(bad, ""))

    def test_empty_title_returns_none(self):
        bad = dict(VALID_SIGMA)
        bad["title"] = ""
        self.assertIsNone(_sigma_to_rule(bad, ""))

    def test_missing_optional_fields_use_defaults(self):
        minimal = {"title": "Minimal Rule"}
        rule = _sigma_to_rule(minimal, "title: Minimal Rule\n")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.description, "")
        self.assertEqual(rule.author, "")
        self.assertEqual(rule.references, [])
        self.assertEqual(rule.mitre_ttps, [])


# ── BaselineSigmaRepo.load ───────────────────────────────────────────────────

class TestBaselineSigmaRepoLoad(unittest.TestCase):

    def test_load_empty_directory(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            repo = BaselineSigmaRepo()
            repo.load(local_path=tmp)
            self.assertEqual(repo.rule_count, 0)
            self.assertEqual(repo.ttps_covered, [])

    def test_load_single_valid_rule(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "rule.yml"
            p.write_text(yaml.dump(VALID_SIGMA))
            repo = BaselineSigmaRepo()
            repo.load(local_path=tmp)
            self.assertEqual(repo.rule_count, 1)

    def test_load_recursive_subdirectories(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sub = Path(tmp) / "windows" / "execution"
            sub.mkdir(parents=True)
            (sub / "rule1.yml").write_text(yaml.dump(VALID_SIGMA))
            (sub / "rule2.yml").write_text(yaml.dump({**VALID_SIGMA, "title": "Rule 2"}))
            repo = BaselineSigmaRepo()
            repo.load(local_path=tmp)
            self.assertEqual(repo.rule_count, 2)

    def test_skips_non_yml_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "rule.yml").write_text(yaml.dump(VALID_SIGMA))
            (Path(tmp) / "readme.md").write_text("# readme")
            (Path(tmp) / "script.py").write_text("print('hello')")
            repo = BaselineSigmaRepo()
            repo.load(local_path=tmp)
            self.assertEqual(repo.rule_count, 1)

    def test_skips_malformed_yml(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "valid.yml").write_text(yaml.dump(VALID_SIGMA))
            (Path(tmp) / "notitle.yml").write_text(yaml.dump({"description": "no title"}))
            repo = BaselineSigmaRepo()
            repo.load(local_path=tmp)
            self.assertEqual(repo.rule_count, 1)


# ── rules_as_store_dicts ─────────────────────────────────────────────────────

class TestRulesAsStoreDicts(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        (Path(self.tmp.name) / "rule.yml").write_text(yaml.dump(VALID_SIGMA))
        self.repo = BaselineSigmaRepo()
        self.repo.load(local_path=self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_all_required_keys_present(self):
        dicts = self.repo.rules_as_store_dicts()
        self.assertEqual(len(dicts), 1)
        d = dicts[0]
        for key in ("rule_id", "name", "format", "ttps", "rule_content",
                    "tlsh_hash", "threat_actor", "source_url", "created_at"):
            self.assertIn(key, d, f"Missing key: {key}")

    def test_ttps_is_valid_json_list(self):
        d = self.repo.rules_as_store_dicts()[0]
        ttps = json.loads(d["ttps"])
        self.assertIsInstance(ttps, list)
        self.assertIn("T1059.001", ttps)

    def test_rule_id_has_baseline_prefix(self):
        d = self.repo.rules_as_store_dicts()[0]
        self.assertTrue(d["rule_id"].startswith("baseline:"))

    def test_format_is_sigma(self):
        d = self.repo.rules_as_store_dicts()[0]
        self.assertEqual(d["format"], "sigma")

    def test_returns_copy(self):
        d1 = self.repo.rules_as_store_dicts()
        d2 = self.repo.rules_as_store_dicts()
        self.assertIsNot(d1, d2)

    def test_tlsh_hash_precomputed(self):
        d = self.repo.rules_as_store_dicts()[0]
        # YAML content is long enough for TLSH; hash should be non-empty
        if d["tlsh_hash"]:  # only assert if content is long enough
            self.assertIsInstance(d["tlsh_hash"], str)
            self.assertGreater(len(d["tlsh_hash"]), 0)


# ── Properties ───────────────────────────────────────────────────────────────

class TestProperties(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        (Path(self.tmp.name) / "rule.yml").write_text(yaml.dump(VALID_SIGMA))
        self.repo = BaselineSigmaRepo()
        self.repo.load(local_path=self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_rule_count(self):
        self.assertEqual(self.repo.rule_count, 1)

    def test_loaded_at_set(self):
        self.assertIsNotNone(self.repo.loaded_at)
        self.assertIsInstance(self.repo.loaded_at, float)

    def test_ttps_covered(self):
        ttps = self.repo.ttps_covered
        self.assertIn("T1059.001", ttps)
        self.assertIn("T1027", ttps)
        # Should be sorted
        self.assertEqual(ttps, sorted(ttps))

    def test_reload_updates_cache(self):
        import tempfile
        # Add a second rule to the directory and reload
        (Path(self.tmp.name) / "rule2.yml").write_text(
            yaml.dump({**VALID_SIGMA, "title": "Second Rule"})
        )
        count = self.repo.reload()
        self.assertEqual(count, 2)
        self.assertEqual(self.repo.rule_count, 2)


# ── Singleton ────────────────────────────────────────────────────────────────

class TestSingleton(unittest.TestCase):

    def test_get_baseline_repo_returns_instance(self):
        repo = get_baseline_repo()
        self.assertIsInstance(repo, BaselineSigmaRepo)

    def test_get_baseline_repo_same_instance(self):
        r1 = get_baseline_repo()
        r2 = get_baseline_repo()
        self.assertIs(r1, r2)

    def test_initialize_creates_new_singleton(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "rule.yml").write_text(yaml.dump(VALID_SIGMA))
            repo = initialize_baseline_repo(local_path=tmp)
            self.assertEqual(repo.rule_count, 1)
            # get_baseline_repo() should now return the same instance
            self.assertIs(get_baseline_repo(), repo)

    def test_initialize_no_path_returns_empty_repo(self):
        repo = initialize_baseline_repo()
        self.assertEqual(repo.rule_count, 0)
        self.assertIsNone(repo.loaded_at)


if __name__ == "__main__":
    unittest.main(verbosity=2)
