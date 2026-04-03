"""
Tests for coverage gap analysis (core/coverage.py).
"""

import unittest
from unittest.mock import patch

from core.coverage import analyze_gaps, TLSH_THRESHOLD
from core.ioc_parser import Technique
from core.models import DetectionRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _technique(tid, tactic="execution", confidence=0.95, context=""):
    return Technique(id=tid, tactic=tactic, confidence=confidence, context=context)


def _rule(ttps, content="rule content"):
    return DetectionRule(
        name="Test",
        description="",
        author="",
        references=[],
        mitre_ttps=ttps,
        rule_content=content,
        format="sigma",
    )


# ---------------------------------------------------------------------------
# Basic gap detection
# ---------------------------------------------------------------------------

class TestAnalyzeGapsBasic(unittest.TestCase):

    def test_no_techniques_returns_empty(self):
        gaps = analyze_gaps([], [], use_tlsh=False)
        self.assertEqual(gaps, [])

    def test_uncovered_technique_becomes_gap(self):
        gaps = analyze_gaps([_technique("T1059")], [], use_tlsh=False)
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].technique_id, "T1059")

    def test_covered_technique_excluded(self):
        gaps = analyze_gaps(
            [_technique("T1059")],
            [_rule(["T1059"])],
            use_tlsh=False,
        )
        self.assertEqual(gaps, [])

    def test_subtechnique_covered_by_parent_rule(self):
        """T1059.001 should be considered covered when T1059 is in a rule."""
        gaps = analyze_gaps(
            [_technique("T1059.001")],
            [_rule(["T1059"])],
            use_tlsh=False,
        )
        self.assertEqual(gaps, [])

    def test_parent_covered_by_subtechnique_rule(self):
        """T1059 should be considered covered when T1059.001 is in a rule."""
        gaps = analyze_gaps(
            [_technique("T1059")],
            [_rule(["T1059.001"])],
            use_tlsh=False,
        )
        self.assertEqual(gaps, [])

    def test_multiple_techniques_partial_coverage(self):
        gaps = analyze_gaps(
            [_technique("T1059"), _technique("T1078"), _technique("T1003")],
            [_rule(["T1059"])],
            use_tlsh=False,
        )
        gap_ids = {g.technique_id for g in gaps}
        self.assertNotIn("T1059", gap_ids)
        self.assertIn("T1078", gap_ids)
        self.assertIn("T1003", gap_ids)


# ---------------------------------------------------------------------------
# Priority assignment
# ---------------------------------------------------------------------------

class TestGapPriority(unittest.TestCase):

    def test_high_confidence_is_high_priority(self):
        gaps = analyze_gaps([_technique("T1059", confidence=0.95)], [], use_tlsh=False)
        self.assertEqual(gaps[0].priority, "high")

    def test_medium_confidence_is_medium_priority(self):
        gaps = analyze_gaps([_technique("T1059", confidence=0.80)], [], use_tlsh=False)
        self.assertEqual(gaps[0].priority, "medium")

    def test_low_confidence_is_low_priority(self):
        gaps = analyze_gaps([_technique("T1059", confidence=0.50)], [], use_tlsh=False)
        self.assertEqual(gaps[0].priority, "low")

    def test_sorted_high_before_low(self):
        gaps = analyze_gaps(
            [_technique("T1059", confidence=0.50), _technique("T1078", confidence=0.95)],
            [],
            use_tlsh=False,
        )
        self.assertEqual(gaps[0].priority, "high")
        self.assertEqual(gaps[1].priority, "low")


# ---------------------------------------------------------------------------
# Store rules coverage
# ---------------------------------------------------------------------------

class TestStoreRulesCoverage(unittest.TestCase):

    def test_store_rule_ttps_counted_as_covered(self):
        import json
        store_rules = [{"ttps": json.dumps(["T1078"]), "rule_content": "x"}]
        gaps = analyze_gaps(
            [_technique("T1078")],
            [],
            store_rules=store_rules,
            use_tlsh=False,
        )
        self.assertEqual(gaps, [])

    def test_store_rule_subtechnique_covers_parent(self):
        import json
        store_rules = [{"ttps": json.dumps(["T1059.001"]), "rule_content": "x"}]
        gaps = analyze_gaps(
            [_technique("T1059")],
            [],
            store_rules=store_rules,
            use_tlsh=False,
        )
        self.assertEqual(gaps, [])

    def test_combined_generated_and_store_rules(self):
        import json
        store_rules = [{"ttps": json.dumps(["T1078"]), "rule_content": "x"}]
        gaps = analyze_gaps(
            [_technique("T1059"), _technique("T1078")],
            [_rule(["T1059"])],
            store_rules=store_rules,
            use_tlsh=False,
        )
        self.assertEqual(gaps, [])


# ---------------------------------------------------------------------------
# TLSH fuzzy matching
# ---------------------------------------------------------------------------

class TestTLSHFuzzy(unittest.TestCase):

    def test_tlsh_disabled_skips_fuzzy(self):
        """With use_tlsh=False, no fuzzy gaps even with matching content."""
        context = "A" * 100
        gaps = analyze_gaps(
            [_technique("T1059", context=context)],
            [_rule(["T1999"], content=context)],  # T1999 not covering T1059
            use_tlsh=False,
        )
        # Gap exists and is NOT fuzzy (TLSH disabled)
        self.assertEqual(len(gaps), 1)
        self.assertFalse(gaps[0].fuzzy_match)

    def test_tlsh_skipped_for_short_context(self):
        """Contexts shorter than 50 bytes are not checked with TLSH."""
        gaps = analyze_gaps(
            [_technique("T1059", context="short")],
            [_rule(["T1999"], content="short")],
            use_tlsh=True,
        )
        # No fuzzy match because context is too short
        self.assertEqual(len(gaps), 1)
        self.assertFalse(gaps[0].fuzzy_match)

    def test_fuzzy_match_sets_flag_and_low_priority(self):
        """A TLSH match below threshold should create a fuzzy gap."""
        context = "index=windows EventCode=4688 CommandLine=powershell " * 5

        with patch("core.coverage._tlsh_hash") as mock_hash, \
             patch("core.coverage._tlsh_distance") as mock_dist:
            mock_hash.return_value = "FAKEHASH"
            mock_dist.return_value = 50  # below TLSH_THRESHOLD=150

            gaps = analyze_gaps(
                [_technique("T1059", context=context)],
                [_rule(["T1999"], content=context)],
                use_tlsh=True,
            )

        self.assertEqual(len(gaps), 1)
        self.assertTrue(gaps[0].fuzzy_match)
        self.assertEqual(gaps[0].priority, "low")
        self.assertEqual(gaps[0].fuzzy_score, 50.0)

    def test_no_fuzzy_match_above_threshold(self):
        """TLSH distance above threshold does not produce a fuzzy gap."""
        context = "index=windows EventCode=4688 CommandLine=powershell " * 5

        with patch("core.coverage._tlsh_hash") as mock_hash, \
             patch("core.coverage._tlsh_distance") as mock_dist:
            mock_hash.return_value = "FAKEHASH"
            mock_dist.return_value = TLSH_THRESHOLD + 1

            gaps = analyze_gaps(
                [_technique("T1059", context=context)],
                [_rule(["T1999"], content=context)],
                use_tlsh=True,
            )

        self.assertEqual(len(gaps), 1)
        self.assertFalse(gaps[0].fuzzy_match)


if __name__ == "__main__":
    unittest.main(verbosity=2)
