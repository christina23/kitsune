"""
Verify TLSH fuzzy matching against a real sigma rule repository.

Loads 50 sigma rules from the demo dataset, ingests them into the store,
and verifies that:
1. TLSH hashes are computed and stored for each rule
2. Similar rule content produces low TLSH distances (fuzzy match)
3. Unrelated content produces high TLSH distances (no false positives)
4. analyze_gaps() correctly identifies fuzzy matches vs real gaps
"""

import json
import os
import sys
import unittest
from pathlib import Path

import yaml

# Allow importing from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import tlsh

from core.coverage import TLSH_THRESHOLD, _tlsh_distance, _tlsh_hash, analyze_gaps
from core.ioc_parser import Technique
from core.models import DetectionRule

SIGMA_DIR = Path(
    "/home/christina/Documents/KITSUNE-DEMO/sample-data/"
    "KITSUNE-DEMO-sigma-50-rules/sigma/rules"
)


def _load_sigma_rules() -> list[dict]:
    """Load all .yml files from the sigma repo and return parsed dicts."""
    rules = []
    for yml_path in sorted(SIGMA_DIR.rglob("*.yml")):
        with open(yml_path) as f:
            data = yaml.safe_load(f)
        if data and isinstance(data, dict):
            data["_path"] = str(yml_path)
            data["_content"] = yml_path.read_text()
            rules.append(data)
    return rules


def _extract_ttps(sigma: dict) -> list[str]:
    """Extract MITRE ATT&CK technique IDs from sigma tags."""
    ttps = []
    for tag in sigma.get("tags", []):
        tag = tag.lower()
        if tag.startswith("attack.t"):
            ttp = tag.replace("attack.", "").upper()
            ttps.append(ttp)
    return ttps


def _to_detection_rule(sigma: dict) -> DetectionRule:
    """Convert a parsed sigma dict to a DetectionRule."""
    return DetectionRule(
        name=sigma.get("title", "Unknown"),
        description=sigma.get("description", ""),
        author=sigma.get("author", ""),
        references=sigma.get("references", []),
        mitre_ttps=_extract_ttps(sigma),
        rule_content=sigma["_content"],
        format="sigma",
    )


class TestTLSHWithSigmaRepo(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sigma_rules = _load_sigma_rules()
        assert len(cls.sigma_rules) == 50, f"Expected 50 rules, got {len(cls.sigma_rules)}"
        cls.detection_rules = [_to_detection_rule(s) for s in cls.sigma_rules]

    # ── TLSH hash computation ────────────────────────────────────────────────

    def test_all_rules_produce_valid_tlsh_hashes(self):
        """Every sigma rule should be long enough to produce a non-TNULL hash."""
        no_hash = []
        for rule in self.detection_rules:
            h = _tlsh_hash(rule.rule_content)
            if not h:
                no_hash.append(rule.name)
        self.assertEqual(
            no_hash, [],
            f"{len(no_hash)} rules produced no TLSH hash: {no_hash[:5]}"
        )

    def test_identical_content_distance_zero(self):
        """Same content should have distance 0."""
        content = self.detection_rules[0].rule_content
        h1 = _tlsh_hash(content)
        h2 = _tlsh_hash(content)
        dist = _tlsh_distance(h1, h2)
        self.assertEqual(dist, 0)

    # ── Fuzzy similarity between related rules ───────────────────────────────

    def test_similar_rules_have_low_distance(self):
        """Rules in the same directory (same OS/category) should tend to be
        more similar to each other than to rules from other categories."""
        windows_rules = [r for r in self.sigma_rules if "/windows/" in r["_path"]]
        linux_rules = [r for r in self.sigma_rules if "/linux/" in r["_path"]]

        self.assertGreater(len(windows_rules), 2)
        self.assertGreater(len(linux_rules), 2)

        # Average intra-category distance (windows vs windows)
        win_hashes = [_tlsh_hash(r["_content"]) for r in windows_rules]
        intra_dists = []
        for i in range(len(win_hashes)):
            for j in range(i + 1, len(win_hashes)):
                d = _tlsh_distance(win_hashes[i], win_hashes[j])
                if d is not None:
                    intra_dists.append(d)

        # Average cross-category distance (windows vs linux)
        linux_hashes = [_tlsh_hash(r["_content"]) for r in linux_rules]
        cross_dists = []
        for wh in win_hashes:
            for lh in linux_hashes:
                d = _tlsh_distance(wh, lh)
                if d is not None:
                    cross_dists.append(d)

        avg_intra = sum(intra_dists) / len(intra_dists)
        avg_cross = sum(cross_dists) / len(cross_dists)

        print(f"\n  Avg intra-windows distance: {avg_intra:.0f}")
        print(f"  Avg cross (windows↔linux) distance: {avg_cross:.0f}")

        # Intra-category should tend to be lower (more similar)
        self.assertLess(avg_intra, avg_cross,
                        "Same-category rules should be more similar than cross-category")

    def test_modified_rule_detected_as_fuzzy_match(self):
        """A slightly modified version of a rule should be within TLSH threshold."""
        original = self.detection_rules[0].rule_content

        # Simulate a minor edit (change field name, add a line)
        modified = original.replace("CommandLine", "ProcessCommandLine")
        modified += "\n    - ParentImage\n"

        h_orig = _tlsh_hash(original)
        h_mod = _tlsh_hash(modified)
        dist = _tlsh_distance(h_orig, h_mod)

        print(f"\n  Original↔Modified distance: {dist}")
        self.assertIsNotNone(dist)
        self.assertLess(dist, TLSH_THRESHOLD,
                        f"Minor edit should be below threshold ({TLSH_THRESHOLD}), got {dist}")

    def test_unrelated_content_above_threshold(self):
        """Completely unrelated content should exceed TLSH threshold."""
        rule_hash = _tlsh_hash(self.detection_rules[0].rule_content)

        # Generate unrelated content (a fake Python script)
        unrelated = """
import requests
import json

def fetch_data(url):
    response = requests.get(url, timeout=30)
    data = response.json()
    for item in data['results']:
        print(f"Name: {item['name']}, Value: {item['value']}")
        if item['status'] == 'active':
            process_item(item)

def process_item(item):
    result = transform(item['payload'])
    save_to_database(result)
    notify_subscribers(item['name'])
""" * 3  # repeat to ensure enough entropy for TLSH

        unrelated_hash = _tlsh_hash(unrelated)
        dist = _tlsh_distance(rule_hash, unrelated_hash)

        print(f"\n  Rule↔Unrelated distance: {dist}")
        self.assertIsNotNone(dist)
        self.assertGreater(dist, TLSH_THRESHOLD,
                           f"Unrelated content should exceed threshold ({TLSH_THRESHOLD}), got {dist}")

    # ── analyze_gaps() integration with real sigma rules ─────────────────────

    def test_analyze_gaps_exact_coverage(self):
        """Techniques that match rule TTPs should not appear as gaps."""
        # Pick techniques that we know are covered by the sigma rules
        all_ttps = set()
        for rule in self.detection_rules:
            all_ttps.update(rule.mitre_ttps)

        covered_ttps = list(all_ttps)[:5]
        techniques = [
            Technique(id=t, tactic="execution", confidence=0.9, context="")
            for t in covered_ttps
        ]

        gaps = analyze_gaps(techniques, self.detection_rules, use_tlsh=False)
        gap_ids = {g.technique_id for g in gaps}

        for t in covered_ttps:
            parent = t.split(".")[0]
            # Either the exact TTP or its parent should be covered
            self.assertTrue(
                t not in gap_ids and parent not in gap_ids,
                f"{t} should be covered but appeared as a gap"
            )

    def test_analyze_gaps_fuzzy_match_with_store_rules(self):
        """Simulate Phase 1: store rules with TLSH hashes should produce
        fuzzy matches for techniques with similar context."""
        # Use one rule's content as the technique "context"
        source_rule = self.detection_rules[0]
        context = source_rule.rule_content

        # Create a slightly modified version as a "store rule"
        modified_content = context.replace("CommandLine", "ProcessCmdLine")
        store_rules = [{
            "ttps": json.dumps(["T9999"]),  # Deliberate TTP mismatch
            "rule_content": modified_content,
            "tlsh_hash": _tlsh_hash(modified_content),
        }]

        # Technique with uncovered TTP but context similar to store rule
        techniques = [
            Technique(id="T1059.001", tactic="execution", confidence=0.9, context=context)
        ]

        gaps = analyze_gaps(
            techniques, [], store_rules=store_rules, use_tlsh=True
        )

        self.assertEqual(len(gaps), 1)
        gap = gaps[0]
        print(f"\n  Fuzzy match: {gap.fuzzy_match}, score: {gap.fuzzy_score}")
        self.assertTrue(gap.fuzzy_match,
                        "Should detect fuzzy match between similar rule content")
        self.assertEqual(gap.priority, "low")
        self.assertLess(gap.fuzzy_score, TLSH_THRESHOLD)

    def test_analyze_gaps_no_fuzzy_for_unrelated_context(self):
        """Unrelated technique context should NOT fuzzy-match sigma rules."""
        unrelated_context = """
The threat actor deployed a custom backdoor written in Golang that
communicates over DNS-over-HTTPS to exfiltrate data from air-gapped
networks. The malware uses steganography to hide C2 commands within
JPEG images downloaded from compromised WordPress sites. Initial access
was gained through a supply chain compromise of a popular npm package.
""" * 3

        store_rules = [{
            "ttps": json.dumps(["T9999"]),
            "rule_content": self.detection_rules[0].rule_content,
            "tlsh_hash": _tlsh_hash(self.detection_rules[0].rule_content),
        }]

        techniques = [
            Technique(id="T1071", tactic="command-and-control",
                      confidence=0.9, context=unrelated_context)
        ]

        gaps = analyze_gaps(
            techniques, [], store_rules=store_rules, use_tlsh=True
        )

        self.assertEqual(len(gaps), 1)
        self.assertFalse(gaps[0].fuzzy_match,
                         "Unrelated context should NOT produce a fuzzy match")

    # ── Coverage stats ───────────────────────────────────────────────────────

    def test_coverage_stats(self):
        """Print coverage statistics for the 50-rule sigma repo."""
        all_ttps = set()
        ttp_to_rules = {}
        for rule in self.detection_rules:
            for ttp in rule.mitre_ttps:
                all_ttps.add(ttp)
                ttp_to_rules.setdefault(ttp, []).append(rule.name)

        print(f"\n  Total rules: {len(self.detection_rules)}")
        print(f"  Unique TTPs covered: {len(all_ttps)}")
        print(f"  Unique parent TTPs: {len({t.split('.')[0] for t in all_ttps})}")
        print(f"  TTPs with multiple rules: "
              f"{sum(1 for v in ttp_to_rules.values() if len(v) > 1)}")

        # Verify reasonable coverage
        self.assertGreater(len(all_ttps), 10,
                           "50 sigma rules should cover more than 10 TTPs")


if __name__ == "__main__":
    unittest.main(verbosity=2)
