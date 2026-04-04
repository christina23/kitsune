"""
Tests for RedisIntelStore focusing on the flush() and URL-based rule
deduplication behaviour added in the latest change.

Uses unittest.mock to patch the underlying Redis client so no live
Redis server is required.
"""

import json
import unittest
from unittest.mock import MagicMock, call, patch

from core.intel_store import RedisIntelStore
from core.models import DetectionRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store() -> tuple[RedisIntelStore, MagicMock]:
    """Return a store with a fully-mocked Redis client."""
    with patch("redis.ConnectionPool.from_url") as mock_pool, \
         patch("redis.Redis") as mock_redis_cls:
        mock_redis = MagicMock()
        mock_redis_cls.return_value = mock_redis
        store = RedisIntelStore("redis://localhost:6379", key_prefix="test")
    return store, mock_redis


def _rule(name="Test Rule", content="rule content", ttps=None, fmt="sigma"):
    return DetectionRule(
        name=name,
        description="",
        author="",
        references=[],
        mitre_ttps=ttps or ["T1059"],
        rule_content=content,
        format=fmt,
    )


# ---------------------------------------------------------------------------
# flush()
# ---------------------------------------------------------------------------

class TestFlush(unittest.TestCase):

    def test_flush_deletes_all_prefixed_keys(self):
        store, mock_redis = _make_store()
        keys = ["test:ioc:ip:abc", "test:rule:xyz", "test:idx:actor:apt28:rules"]
        mock_redis.scan_iter.return_value = iter(keys)

        deleted = store.flush()

        mock_redis.scan_iter.assert_called_once_with("test:*")
        mock_redis.delete.assert_called_once_with(*keys)
        self.assertEqual(deleted, 3)

    def test_flush_returns_zero_when_empty(self):
        store, mock_redis = _make_store()
        mock_redis.scan_iter.return_value = iter([])

        deleted = store.flush()

        mock_redis.delete.assert_not_called()
        self.assertEqual(deleted, 0)

    def test_flush_uses_correct_prefix(self):
        with patch("redis.ConnectionPool.from_url") as mock_pool, \
             patch("redis.Redis") as mock_redis_cls:
            mock_redis = MagicMock()
            mock_redis_cls.return_value = mock_redis
            store = RedisIntelStore("redis://localhost:6379", key_prefix="kitsune")

        mock_redis.scan_iter.return_value = iter([])
        store.flush()
        mock_redis.scan_iter.assert_called_once_with("kitsune:*")


# ---------------------------------------------------------------------------
# ingest_rules() — URL-based deduplication
# ---------------------------------------------------------------------------

class TestIngestRulesDeduplication(unittest.TestCase):

    def _setup_pipe(self, mock_redis):
        """Wire up pipeline mock so pipeline() returns a consistent mock."""
        pipe = MagicMock()
        mock_redis.pipeline.return_value = pipe
        return pipe

    def test_first_ingestion_stores_rule_and_src_tracking(self):
        """New URL: no old keys, rule is stored and tracked."""
        store, mock_redis = _make_store()
        self._setup_pipe(mock_redis)

        # No previous keys for this URL
        mock_redis.smembers.return_value = set()

        rule = _rule()
        store.ingest_rules([rule], source_url="https://example.com/report1", threat_actor="APT28")

        # Write pipeline hset was called to store the rule
        pipe = mock_redis.pipeline.return_value
        hset_calls = [c for c in pipe.hset.call_args_list]
        self.assertTrue(len(hset_calls) > 0, "Expected at least one hset call in pipeline")
        stored_mapping = hset_calls[0][1]["mapping"]
        self.assertEqual(stored_mapping["name"], "Test Rule")

        # pipeline sadd was called for the src tracking key
        src_key = store._src_rules_key("https://example.com/report1")
        pipe.sadd.assert_any_call(src_key, unittest.mock.ANY)

    def test_duplicate_url_removes_old_rules_before_adding_new(self):
        """Re-submitting the same URL should purge old rules from indices."""
        store, mock_redis = _make_store()
        pipe = self._setup_pipe(mock_redis)
        # read_pipe returns old rule data
        pipe.execute.side_effect = [
            [{"name": "Old Rule", "format": "sigma", "ttps": json.dumps(["T1021"]),
              "threat_actor": "APT28", "source_url": "https://example.com/report1",
              "created_at": "1000.0"}],  # read pipeline
            None,  # cleanup pipeline
            None,  # write pipeline
        ]

        old_rule_key = "test:rule:oldkey123"
        src_key = store._src_rules_key("https://example.com/report1")
        mock_redis.smembers.return_value = {old_rule_key}

        rule = _rule(name="New Rule", content="new content", ttps=["T1059"])
        store.ingest_rules([rule], source_url="https://example.com/report1", threat_actor="APT28")

        # Old rule hash should have been deleted (in cleanup pipeline)
        pipe.delete.assert_any_call(old_rule_key)
        # Src tracking set should have been cleared
        pipe.delete.assert_any_call(src_key)
        # Old rule should be removed from actor and TTP indices
        pipe.srem.assert_any_call(store._actor_rule_idx("APT28"), old_rule_key)
        pipe.srem.assert_any_call(store._ttp_rule_idx("T1021"), old_rule_key)

    def test_duplicate_url_stores_new_rule_after_cleanup(self):
        """After cleanup, the new rule should be written to Redis."""
        store, mock_redis = _make_store()
        pipe = self._setup_pipe(mock_redis)
        pipe.execute.side_effect = [
            [{"name": "Old", "format": "sigma", "ttps": "[]",
              "threat_actor": "", "source_url": "https://example.com/report1",
              "created_at": "1.0"}],  # read pipeline
            None,  # cleanup pipeline
            None,  # write pipeline
        ]

        mock_redis.smembers.return_value = {"test:rule:oldkey"}

        rule = _rule(name="Fresh Rule", content="fresh content")
        store.ingest_rules([rule], source_url="https://example.com/report1", threat_actor="Lazarus")

        # Check write pipeline hset call
        hset_calls = [c for c in pipe.hset.call_args_list]
        # Find the call that stores the actual rule (has "name" in mapping)
        rule_hset = [c for c in hset_calls if c[1].get("mapping", {}).get("name") == "Fresh Rule"]
        self.assertTrue(len(rule_hset) > 0, f"Expected hset for Fresh Rule, got: {hset_calls}")
        stored_mapping = rule_hset[0][1]["mapping"]
        self.assertEqual(stored_mapping["threat_actor"], "Lazarus")

    def test_different_urls_do_not_interfere(self):
        """Rules from different URLs should coexist independently."""
        store, mock_redis = _make_store()
        pipe = self._setup_pipe(mock_redis)

        # Simulate URL-A having an existing rule
        url_b = "https://example.com/report-b"

        # URL-B has no prior history
        mock_redis.smembers.return_value = set()

        rule_b = _rule(name="Rule B", content="content b")
        store.ingest_rules([rule_b], source_url=url_b, threat_actor="APT29")

        # No deletions should have happened (empty smembers for URL-B)
        pipe.delete.assert_not_called()

        # Rule B was stored (in write pipeline)
        hset_calls = [c for c in pipe.hset.call_args_list]
        self.assertTrue(len(hset_calls) > 0)

    def test_missing_old_rule_hash_is_handled_gracefully(self):
        """If old rule key is in tracking set but hash is gone, no crash."""
        store, mock_redis = _make_store()
        pipe = self._setup_pipe(mock_redis)
        # read pipeline returns empty dict (ghost key)
        pipe.execute.side_effect = [
            [{}],  # read pipeline
            None,  # cleanup pipeline
            None,  # write pipeline
        ]

        mock_redis.smembers.return_value = {"test:rule:ghost"}

        rule = _rule()
        # Should not raise
        store.ingest_rules([rule], source_url="https://example.com/report1", threat_actor="APT28")

        # Ghost key is still deleted
        pipe.delete.assert_any_call("test:rule:ghost")


# ---------------------------------------------------------------------------
# src key helper
# ---------------------------------------------------------------------------

class TestSrcRulesKey(unittest.TestCase):

    def test_same_url_produces_same_key(self):
        store, _ = _make_store()
        url = "https://example.com/report"
        self.assertEqual(store._src_rules_key(url), store._src_rules_key(url))

    def test_different_urls_produce_different_keys(self):
        store, _ = _make_store()
        self.assertNotEqual(
            store._src_rules_key("https://example.com/a"),
            store._src_rules_key("https://example.com/b"),
        )

    def test_key_uses_correct_prefix(self):
        store, _ = _make_store()
        key = store._src_rules_key("https://example.com/report")
        self.assertTrue(key.startswith("test:src:"))
        self.assertTrue(key.endswith(":rules"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
