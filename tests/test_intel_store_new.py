"""
Tests for new RedisIntelStore methods added in the coverage/pipeline update:
  - IOC hash indexing (rules_exist_for_ioc_hash, get_rules_by_ioc_hash)
  - update_rule()
  - query_rules() returns rule_id
  - ingest_rules() stores rule_content, tlsh_hash, ioc_hash index
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from core.intel_store import RedisIntelStore
from core.models import DetectionRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store() -> tuple[RedisIntelStore, MagicMock]:
    with patch("redis.from_url") as mock_from_url:
        mock_redis = MagicMock()
        mock_from_url.return_value = mock_redis
        store = RedisIntelStore("redis://localhost:6379", key_prefix="test")
    return store, mock_redis


def _rule(name="Rule", content="rule content here", ttps=None, fmt="sigma"):
    return DetectionRule(
        name=name,
        description="",
        author="tester",
        references=[],
        mitre_ttps=ttps or ["T1059"],
        rule_content=content,
        format=fmt,
    )


# ---------------------------------------------------------------------------
# IOC hash index — rules_exist_for_ioc_hash / get_rules_by_ioc_hash
# ---------------------------------------------------------------------------

class TestIocHashIndex(unittest.TestCase):

    def test_rules_exist_returns_true_when_set_nonempty(self):
        store, mock_redis = _make_store()
        mock_redis.scard.return_value = 3
        self.assertTrue(store.rules_exist_for_ioc_hash("abc123"))
        mock_redis.scard.assert_called_once_with(store._ioc_hash_rule_idx("abc123"))

    def test_rules_exist_returns_false_when_set_empty(self):
        store, mock_redis = _make_store()
        mock_redis.scard.return_value = 0
        self.assertFalse(store.rules_exist_for_ioc_hash("abc123"))

    def test_get_rules_by_ioc_hash_returns_rule_dicts(self):
        store, mock_redis = _make_store()
        rule_key = "test:rule:aabbcc"
        mock_redis.smembers.return_value = {rule_key}
        mock_redis.hgetall.return_value = {
            "name": "My Rule",
            "format": "sigma",
            "rule_content": "detection: ...",
            "ttps": json.dumps(["T1059"]),
        }

        results = store.get_rules_by_ioc_hash("abc123")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "My Rule")
        self.assertEqual(results[0]["rule_id"], rule_key)

    def test_get_rules_by_ioc_hash_empty_set(self):
        store, mock_redis = _make_store()
        mock_redis.smembers.return_value = set()
        results = store.get_rules_by_ioc_hash("abc123")
        self.assertEqual(results, [])

    def test_get_rules_respects_limit(self):
        store, mock_redis = _make_store()
        keys = {f"test:rule:{i}" for i in range(10)}
        mock_redis.smembers.return_value = keys
        mock_redis.hgetall.return_value = {"name": "R", "rule_content": "x"}

        results = store.get_rules_by_ioc_hash("abc123", limit=3)
        self.assertLessEqual(len(results), 3)


# ---------------------------------------------------------------------------
# update_rule()
# ---------------------------------------------------------------------------

class TestUpdateRule(unittest.TestCase):

    def test_update_rule_returns_true_and_sets_fields(self):
        store, mock_redis = _make_store()
        mock_redis.exists.return_value = True

        result = store.update_rule("test:rule:abc", "new content here")

        self.assertTrue(result)
        mock_redis.hset.assert_called_once()
        mapping = mock_redis.hset.call_args[1]["mapping"]
        self.assertEqual(mapping["rule_content"], "new content here")
        self.assertIn("tlsh_hash", mapping)

    def test_update_rule_returns_false_when_not_found(self):
        store, mock_redis = _make_store()
        mock_redis.exists.return_value = False

        result = store.update_rule("test:rule:missing", "content")

        self.assertFalse(result)
        mock_redis.hset.assert_not_called()


# ---------------------------------------------------------------------------
# ingest_rules() — new fields stored + ioc_hash indexing
# ---------------------------------------------------------------------------

class TestIngestRulesNewFields(unittest.TestCase):

    def _setup_pipe(self, mock_redis):
        pipe = MagicMock()
        mock_redis.pipeline.return_value = pipe
        return pipe

    def test_rule_content_and_tlsh_hash_stored(self):
        store, mock_redis = _make_store()
        self._setup_pipe(mock_redis)
        mock_redis.smembers.return_value = set()

        store.ingest_rules([_rule(content="my spl search")], source_url="https://x.com", threat_actor="APT1")

        mapping = mock_redis.hset.call_args[1]["mapping"]
        self.assertEqual(mapping["rule_content"], "my spl search")
        self.assertIn("tlsh_hash", mapping)  # field present (may be empty if py-tlsh unavailable)

    def test_ioc_hash_index_created_when_provided(self):
        store, mock_redis = _make_store()
        pipe = self._setup_pipe(mock_redis)
        mock_redis.smembers.return_value = set()

        store.ingest_rules(
            [_rule()],
            source_url="https://x.com",
            threat_actor="APT1",
            ioc_hash="deadbeef",
        )

        idx_key = store._ioc_hash_rule_idx("deadbeef")
        sadd_calls = [str(c) for c in pipe.sadd.call_args_list]
        self.assertTrue(any(idx_key in c for c in sadd_calls),
                        f"Expected sadd to ioc_hash index {idx_key}, calls: {sadd_calls}")

    def test_no_ioc_hash_index_when_empty(self):
        store, mock_redis = _make_store()
        pipe = self._setup_pipe(mock_redis)
        mock_redis.smembers.return_value = set()

        store.ingest_rules([_rule()], source_url="https://x.com", threat_actor="APT1", ioc_hash="")

        idx_key_pattern = ":idx:ioc_hash:"
        sadd_calls = [str(c) for c in pipe.sadd.call_args_list]
        self.assertFalse(any(idx_key_pattern in c for c in sadd_calls))


# ---------------------------------------------------------------------------
# query_rules() — returns rule_id
# ---------------------------------------------------------------------------

class TestQueryRulesRuleId(unittest.TestCase):

    def test_query_rules_includes_rule_id(self):
        store, mock_redis = _make_store()
        rule_key = "test:rule:myrule"

        # Simulate scanning rules index
        mock_redis.smembers.return_value = {rule_key}
        mock_redis.scan_iter.return_value = iter([rule_key])
        mock_redis.hgetall.return_value = {
            "name": "My Rule",
            "format": "sigma",
            "ttps": "[]",
            "threat_actor": "APT1",
            "source_url": "https://x.com",
            "created_at": "1234.0",
        }

        results = store.query_rules(limit=10)

        self.assertTrue(len(results) > 0)
        self.assertIn("rule_id", results[0])
        self.assertEqual(results[0]["rule_id"], rule_key)


# ---------------------------------------------------------------------------
# _ioc_hash_rule_idx helper
# ---------------------------------------------------------------------------

class TestIocHashRuleIdx(unittest.TestCase):

    def test_key_format(self):
        store, _ = _make_store()
        key = store._ioc_hash_rule_idx("abc123")
        self.assertEqual(key, "test:idx:ioc_hash:abc123:rules")

    def test_different_hashes_produce_different_keys(self):
        store, _ = _make_store()
        self.assertNotEqual(
            store._ioc_hash_rule_idx("hash1"),
            store._ioc_hash_rule_idx("hash2"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
