"""
Persistent IOC and threat intel store backed by Redis.

The store is opt-in: the pipeline runs normally when Redis is unavailable.
Use create_store() to get a configured store or None.
"""

import hashlib
import json
import re
import time
import warnings
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .models import DetectionRule, ThreatIntelligence


def _slug(name: str) -> str:
    """Lowercase slug for use in Redis key names."""
    return name.lower().replace(" ", "_")


# LLM extraction sometimes returns multiple actors as a single string
# (e.g. "UNC6353, UNC6691" or "APT29 / Cozy Bear"). Split these into
# individual actor names so each is indexed separately.
_ACTOR_SPLIT_RE = re.compile(r"\s*(?:,|/|&|\band\b)\s*", re.IGNORECASE)


def _split_actor_names(raw: Optional[str]) -> List[str]:
    """Split a possibly-combined actor string into individual names."""
    if not raw:
        return []
    parts = _ACTOR_SPLIT_RE.split(raw)
    return [p.strip() for p in parts if p.strip()]


def _sha(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]


def _compute_tlsh_safe(content: str) -> str:
    """Compute TLSH hash of content; returns empty string if unavailable."""
    try:
        import tlsh  # py-tlsh

        h = tlsh.hash(content.encode())
        return h if h != "TNULL" else ""
    except Exception:
        return ""


def _merge_json_list(existing: Optional[str], new_items: List[str]) -> str:
    """Merge new_items into a JSON-encoded list, deduplicating."""
    current: List[str] = json.loads(existing) if existing else []
    merged = list(dict.fromkeys(current + new_items))
    return json.dumps(merged)


# ── Abstract interface ────────────────────────────────────────────────────────


class ThreatIntelStore(ABC):
    """Abstract interface for the persistent threat intel store."""

    @abstractmethod
    def ingest_threat_intel(
        self, threat_intel: ThreatIntelligence, source_url: str
    ) -> None:
        """Persist all IOCs and TTPs from a ThreatIntelligence object."""

    @abstractmethod
    def ingest_rules(
        self,
        rules: List[DetectionRule],
        source_url: str,
        threat_actor: str,
    ) -> None:
        """Persist detection rules and index them by actor and TTP."""

    @abstractmethod
    def query_iocs(
        self,
        actor: Optional[str] = None,
        ttp: Optional[str] = None,
        ioc_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Return IOCs filtered by actor, TTP, and/or IOC type."""

    @abstractmethod
    def query_rules(
        self,
        actor: Optional[str] = None,
        ttp: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Return rules filtered by actor and/or TTP."""

    @abstractmethod
    def get_coverage_summary(self) -> Dict[str, Dict]:
        """
        Per-TTP coverage: {ttp_id: {has_iocs, has_rules, ioc_count,
        rule_count}}.
        """

    @abstractmethod
    def get_trending_ttps(self, n: int = 10) -> List[Dict]:
        """Return top-n TTPs by ingestion frequency."""

    @abstractmethod
    def get_actor_summary(self, actor_name: str) -> Dict:
        """Return IOC counts by type, TTPs, and campaigns for an actor."""

    @abstractmethod
    def rules_exist_for_ioc_hash(self, ioc_hash: str) -> bool:
        """Return True if rules are indexed under this IOC hash."""

    @abstractmethod
    def get_rules_by_ioc_hash(self, ioc_hash: str, limit: int = 50) -> List[Dict]:
        """Return rules stored under this IOC hash."""

    @abstractmethod
    def update_rule(self, rule_id: str, new_content: str) -> bool:
        """Update rule_content for a stored rule. Returns False if not found."""

    @abstractmethod
    def is_ttp_covered(self, ttp_id: str) -> bool:
        """Return True if at least one rule covers this TTP (O(1) lookup)."""

    @abstractmethod
    def get_all_tlsh_hashes(self) -> Dict[str, str]:
        """Return mapping of rule_key → tlsh_hash for all rules (baseline + generated)."""

    @abstractmethod
    def ingest_baseline_rule(self, rule: "DetectionRule", source: str = "") -> str:
        """Persist a baseline sigma rule and update all indexes. Returns the rule key."""

    @abstractmethod
    def get_baseline_stats(self) -> Dict[str, Any]:
        """Return baseline stats: rule_count, ttps_covered, last_sync_ts, last_sync_sha."""

    @abstractmethod
    def get_baseline_sync_sha(self) -> Optional[str]:
        """Return the last commit SHA that was synced, or None."""

    @abstractmethod
    def set_baseline_sync_sha(self, sha: str) -> None:
        """Store the commit SHA after a successful sync."""

    @abstractmethod
    def flush(self) -> int:
        """Delete all keys belonging to this store's prefix. Returns count of deleted keys."""


# ── Redis implementation ──────────────────────────────────────────────────────


class RedisIntelStore(ThreatIntelStore):
    """Redis-backed implementation of ThreatIntelStore."""

    def __init__(
        self,
        redis_url: str,
        key_prefix: str = "kitsune",
        max_connections: int = 20,
        default_ttl_days: int = 90,
    ):
        import redis  # lazy import — missing package won't break module load

        pool = redis.ConnectionPool.from_url(
            redis_url, max_connections=max_connections, decode_responses=True,
        )
        self._r = redis.Redis(connection_pool=pool)
        self._p = key_prefix
        self._ioc_ttl = default_ttl_days * 86400  # seconds

    # ── Key helpers ───────────────────────────────────────────────────────────

    def _ioc_key(self, ioc_type: str, value: str) -> str:
        return f"{self._p}:ioc:{ioc_type}:{_sha(value.lower())}"

    def _rule_key(self, name: str, content: str) -> str:
        return f"{self._p}:rule:{_sha(name + content)}"

    def _actor_ioc_idx(self, actor: str) -> str:
        return f"{self._p}:idx:actor:{_slug(actor)}:iocs"

    def _actor_rule_idx(self, actor: str) -> str:
        return f"{self._p}:idx:actor:{_slug(actor)}:rules"

    def _ttp_ioc_idx(self, ttp_id: str) -> str:
        return f"{self._p}:idx:ttp:{ttp_id}:iocs"

    def _ttp_rule_idx(self, ttp_id: str) -> str:
        return f"{self._p}:idx:ttp:{ttp_id}:rules"

    def _timeline_key(self) -> str:
        return f"{self._p}:timeline:iocs"

    def _trend_key(self) -> str:
        return f"{self._p}:trend:ttps"

    def _actors_key(self) -> str:
        return f"{self._p}:actors"

    def _lookup_key(self, value: str) -> str:
        return f"{self._p}:lookup:{_sha(value.lower())}"

    def _src_rules_key(self, url: str) -> str:
        return f"{self._p}:src:{_sha(url)}:rules"

    def _ioc_hash_rule_idx(self, ioc_hash: str) -> str:
        return f"{self._p}:idx:ioc_hash:{ioc_hash}:rules"

    def _covered_ttps_key(self) -> str:
        return f"{self._p}:covered_ttps"

    def _tlsh_all_key(self) -> str:
        return f"{self._p}:tlsh:all"

    def _baseline_key(self, uid: str) -> str:
        return f"{self._p}:baseline:{uid}"

    def _baseline_sync_key(self) -> str:
        return f"{self._p}:baseline:sync"

    def _baseline_rules_set_key(self) -> str:
        return f"{self._p}:idx:baseline:rules"

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def _ingest_single_ioc(
        self,
        ioc_type: str,
        value: str,
        actors: List[str],
        campaigns: List[str],
        ttps: List[str],
        source_url: str,
    ) -> None:
        key = self._ioc_key(ioc_type, value)
        now = str(time.time())

        # Batch: set core fields + read existing JSON fields in one pipeline
        pipe = self._r.pipeline()
        pipe.hsetnx(key, "first_seen", now)
        pipe.hset(
            key,
            mapping={"type": ioc_type, "value": value, "last_seen": now},
        )
        # Read existing JSON merge fields
        for field_name in ("threat_actors", "campaigns", "ttps", "source_urls"):
            pipe.hget(key, field_name)
        results = pipe.execute()

        # Results: [hsetnx, hset, hget_actors, hget_campaigns, hget_ttps, hget_urls]
        existing_actors = results[2]
        existing_campaigns = results[3]
        existing_ttps = results[4]
        existing_urls = results[5]

        # Batch: write merged JSON fields + indexes in one pipeline
        pipe = self._r.pipeline()
        pipe.hset(key, mapping={
            "threat_actors": _merge_json_list(existing_actors, actors),
            "campaigns": _merge_json_list(existing_campaigns, campaigns),
            "ttps": _merge_json_list(existing_ttps, ttps),
            "source_urls": _merge_json_list(existing_urls, [source_url]),
        })
        # TTL for IOC records
        if self._ioc_ttl > 0:
            pipe.expire(key, self._ioc_ttl)
        for actor in actors:
            pipe.sadd(self._actor_ioc_idx(actor), key)
        for ttp_id in ttps:
            pipe.sadd(self._ttp_ioc_idx(ttp_id), key)
            pipe.zincrby(self._trend_key(), 1, ttp_id)
        pipe.zadd(self._timeline_key(), {key: float(now)})
        pipe.set(self._lookup_key(value), key)
        if actors:
            pipe.sadd(self._actors_key(), *actors)
        pipe.execute()

    def ingest_threat_intel(
        self, threat_intel: ThreatIntelligence, source_url: str
    ) -> None:
        actors = _split_actor_names(threat_intel.threat_actor)
        campaigns = (
            [threat_intel.campaign_name] if threat_intel.campaign_name else []
        )
        ttps = [t.id for t in (threat_intel.techniques or [])]
        iocs = threat_intel.iocs

        for ioc_type, values in iocs.to_dict().items():
            for value in values:
                self._ingest_single_ioc(
                    ioc_type, value, actors, campaigns, ttps, source_url
                )

    def ingest_rules(
        self,
        rules: List[DetectionRule],
        source_url: str,
        threat_actor: str,
        ioc_hash: str = "",
    ) -> None:
        src_key = self._src_rules_key(source_url)

        # Remove stale rules from a previous run of this same URL
        old_rule_keys = self._r.smembers(src_key)
        if old_rule_keys:
            # Batch read all old rule data in one pipeline
            read_pipe = self._r.pipeline()
            old_keys_list = list(old_rule_keys)
            for old_key in old_keys_list:
                read_pipe.hgetall(old_key)
            old_data_list = read_pipe.execute()

            # Batch cleanup in one pipeline
            cleanup_pipe = self._r.pipeline()
            for old_key, old_data in zip(old_keys_list, old_data_list):
                if old_data:
                    old_actor = old_data.get("threat_actor", "")
                    old_ttps = json.loads(old_data.get("ttps", "[]"))
                    old_ioc_hash = old_data.get("ioc_hash", "")
                    if old_actor:
                        cleanup_pipe.srem(self._actor_rule_idx(old_actor), old_key)
                    for ttp_id in old_ttps:
                        cleanup_pipe.srem(self._ttp_rule_idx(ttp_id), old_key)
                    if old_ioc_hash:
                        cleanup_pipe.srem(self._ioc_hash_rule_idx(old_ioc_hash), old_key)
                cleanup_pipe.delete(old_key)
            cleanup_pipe.delete(src_key)
            cleanup_pipe.execute()

        # Batch write all new rules in one pipeline
        write_pipe = self._r.pipeline()
        for rule in rules:
            key = self._rule_key(rule.name, rule.rule_content)
            tlsh_hash = _compute_tlsh_safe(rule.rule_content)
            write_pipe.hset(
                key,
                mapping={
                    "name": rule.name,
                    "format": rule.format,
                    "ttps": json.dumps(rule.mitre_ttps),
                    "threat_actor": threat_actor,
                    "source_url": source_url,
                    "created_at": str(time.time()),
                    "rule_content": rule.rule_content,
                    "tlsh_hash": tlsh_hash,
                    "ioc_hash": ioc_hash,
                },
            )
            if threat_actor:
                write_pipe.sadd(self._actor_rule_idx(threat_actor), key)
            for ttp_id in rule.mitre_ttps:
                write_pipe.sadd(self._ttp_rule_idx(ttp_id), key)
                write_pipe.sadd(self._covered_ttps_key(), ttp_id.upper())
            write_pipe.sadd(src_key, key)
            if ioc_hash:
                write_pipe.sadd(self._ioc_hash_rule_idx(ioc_hash), key)
            if tlsh_hash:
                write_pipe.hset(self._tlsh_all_key(), key, tlsh_hash)
        write_pipe.execute()

    # ── Querying ──────────────────────────────────────────────────────────────

    def query_iocs(
        self,
        actor: Optional[str] = None,
        ttp: Optional[str] = None,
        ioc_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        if actor and ttp:
            keys = self._r.sinter(
                self._actor_ioc_idx(actor), self._ttp_ioc_idx(ttp)
            )
        elif actor:
            keys = self._r.smembers(self._actor_ioc_idx(actor))
        elif ttp:
            keys = self._r.smembers(self._ttp_ioc_idx(ttp))
        else:
            keys = self._r.zrevrange(self._timeline_key(), 0, limit - 1)

        keys_list = list(keys)[:limit]
        if not keys_list:
            return []

        # Batch fetch all hashes in one pipeline
        pipe = self._r.pipeline()
        for key in keys_list:
            pipe.hgetall(key)
        all_data = pipe.execute()

        results = []
        for data in all_data:
            if not data:
                continue
            if ioc_type and data.get("type") != ioc_type:
                continue
            results.append(data)
        return results

    def query_rules(
        self,
        actor: Optional[str] = None,
        ttp: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        if actor and ttp:
            keys = self._r.sinter(
                self._actor_rule_idx(actor), self._ttp_rule_idx(ttp)
            )
        elif actor:
            keys = self._r.smembers(self._actor_rule_idx(actor))
        elif ttp:
            keys = self._r.smembers(self._ttp_rule_idx(ttp))
        else:
            # Scan for all rule keys (pipeline + baseline)
            keys = list(self._r.scan_iter(f"{self._p}:rule:*"))
            baseline_keys = list(self._r.smembers(self._baseline_rules_set_key()))
            keys = list(dict.fromkeys(keys + baseline_keys))  # dedupe, preserve order

        keys_list = list(keys)[:limit]
        if not keys_list:
            return []

        # Batch fetch all hashes in one pipeline
        pipe = self._r.pipeline()
        for key in keys_list:
            pipe.hgetall(key)
        all_data = pipe.execute()

        results = []
        for key, data in zip(keys_list, all_data):
            if data:
                results.append({"rule_id": key, **data})
        # Sort by created_at descending (newest first)
        results.sort(key=lambda r: float(r.get("created_at", 0)), reverse=True)
        return results

    def rules_exist_for_ioc_hash(self, ioc_hash: str) -> bool:
        return self._r.scard(self._ioc_hash_rule_idx(ioc_hash)) > 0

    def get_rules_by_ioc_hash(self, ioc_hash: str, limit: int = 50) -> List[Dict]:
        keys = list(self._r.smembers(self._ioc_hash_rule_idx(ioc_hash)))[:limit]
        if not keys:
            return []

        pipe = self._r.pipeline()
        for k in keys:
            pipe.hgetall(k)
        all_data = pipe.execute()

        return [
            {"rule_id": k, **d}
            for k, d in zip(keys, all_data)
            if d
        ]

    def update_rule(self, rule_id: str, new_content: str) -> bool:
        if not self._r.exists(rule_id):
            return False
        tlsh_hash = _compute_tlsh_safe(new_content)
        pipe = self._r.pipeline()
        pipe.hset(
            rule_id,
            mapping={
                "rule_content": new_content,
                "tlsh_hash": tlsh_hash,
            },
        )
        if tlsh_hash:
            pipe.hset(self._tlsh_all_key(), rule_id, tlsh_hash)
        pipe.execute()
        return True

    # ── TTP coverage (O(1) lookup) ───────────────────────────────────────────

    def is_ttp_covered(self, ttp_id: str) -> bool:
        return self._r.sismember(self._covered_ttps_key(), ttp_id.upper())

    # ── TLSH hash map ────────────────────────────────────────────────────────

    def get_all_tlsh_hashes(self) -> Dict[str, str]:
        return self._r.hgetall(self._tlsh_all_key())

    # ── Baseline rule management ─────────────────────────────────────────────

    def ingest_baseline_rule(self, rule: "DetectionRule", source: str = "") -> str:
        uid = _sha(rule.name + rule.rule_content)
        key = self._baseline_key(uid)
        tlsh_hash = _compute_tlsh_safe(rule.rule_content)

        pipe = self._r.pipeline()
        pipe.hset(
            key,
            mapping={
                "name": rule.name,
                "format": rule.format,
                "ttps": json.dumps(rule.mitre_ttps),
                "rule_content": rule.rule_content,
                "source": source,
                "tlsh_hash": tlsh_hash,
                "created_at": str(time.time()),
            },
        )
        pipe.sadd(self._baseline_rules_set_key(), key)
        for ttp_id in rule.mitre_ttps:
            pipe.sadd(self._covered_ttps_key(), ttp_id.upper())
            pipe.sadd(self._ttp_rule_idx(ttp_id), key)
        if tlsh_hash:
            pipe.hset(self._tlsh_all_key(), key, tlsh_hash)
        pipe.execute()
        return key

    def get_baseline_stats(self) -> Dict[str, Any]:
        pipe = self._r.pipeline()
        pipe.scard(self._baseline_rules_set_key())
        pipe.smembers(self._covered_ttps_key())
        pipe.hgetall(self._baseline_sync_key())
        results = pipe.execute()

        sync_data = results[2] or {}
        return {
            "rule_count": results[0],
            "ttps_covered": sorted(results[1]),
            "last_sync_ts": sync_data.get("ts"),
            "last_sync_sha": sync_data.get("sha"),
        }

    def get_baseline_sync_sha(self) -> Optional[str]:
        return self._r.hget(self._baseline_sync_key(), "sha")

    def set_baseline_sync_sha(self, sha: str) -> None:
        self._r.hset(
            self._baseline_sync_key(),
            mapping={"sha": sha, "ts": str(time.time())},
        )

    # ── Analytics ─────────────────────────────────────────────────────────────

    def get_coverage_summary(self) -> Dict[str, Dict]:
        summary: Dict[str, Dict] = {}
        pattern = f"{self._p}:idx:ttp:*"
        for key in self._r.scan_iter(pattern):
            # key format: {prefix}:idx:ttp:{TTP_ID}:(iocs|rules)
            parts = key.split(":")
            if len(parts) < 5:
                continue
            ttp_id = parts[-2]
            kind = parts[-1]  # "iocs" or "rules"
            if ttp_id not in summary:
                summary[ttp_id] = {
                    "has_iocs": False,
                    "has_rules": False,
                    "ioc_count": 0,
                    "rule_count": 0,
                }
            count = self._r.scard(key)
            if kind == "iocs":
                summary[ttp_id]["has_iocs"] = count > 0
                summary[ttp_id]["ioc_count"] = count
            elif kind == "rules":
                summary[ttp_id]["has_rules"] = count > 0
                summary[ttp_id]["rule_count"] = count
        return summary

    def get_trending_ttps(self, n: int = 10) -> List[Dict]:
        entries = self._r.zrevrange(
            self._trend_key(), 0, n - 1, withscores=True
        )
        return [{"ttp_id": ttp, "count": int(score)} for ttp, score in entries]

    def count_iocs(self) -> int:
        """Distinct IOC count (each IOC is indexed once in the timeline)."""
        return int(self._r.zcard(self._timeline_key()) or 0)

    def flush(self) -> int:
        keys = list(self._r.scan_iter(f"{self._p}:*"))
        if keys:
            self._r.delete(*keys)
        return len(keys)

    def normalize_combined_actors(self) -> Dict[str, Any]:
        """Split any combined-name actor entries into individual actors.

        Finds actor-set members whose names contain a separator (comma,
        slash, ampersand, or the word "and"), splits them into constituent
        names, merges each combined actor's IOC and rule indexes into the
        individual actors' indexes, rewrites the ``threat_actors`` JSON
        field on every referenced IOC/rule, and removes the combined names.

        Returns a summary dict: ``{"removed": [...], "added": [...]}``.
        """
        all_actors = list(self._r.smembers(self._actors_key()))
        combined = [a for a in all_actors if _ACTOR_SPLIT_RE.search(a)]
        if not combined:
            return {"removed": [], "added": []}

        added_set: set = set()
        for combined_name in combined:
            parts = _split_actor_names(combined_name)
            if not parts:
                continue

            # Merge the combined actor's IOC/rule index keys into each
            # individual actor's indexes, then delete the combined indexes.
            combined_ioc_idx = self._actor_ioc_idx(combined_name)
            combined_rule_idx = self._actor_rule_idx(combined_name)
            ioc_keys = self._r.smembers(combined_ioc_idx)
            rule_keys = self._r.smembers(combined_rule_idx)

            pipe = self._r.pipeline()
            for name in parts:
                if ioc_keys:
                    pipe.sadd(self._actor_ioc_idx(name), *ioc_keys)
                if rule_keys:
                    pipe.sadd(self._actor_rule_idx(name), *rule_keys)
                pipe.sadd(self._actors_key(), name)
                added_set.add(name)
            pipe.delete(combined_ioc_idx, combined_rule_idx)
            pipe.srem(self._actors_key(), combined_name)
            pipe.execute()

            # Rewrite the threat_actors JSON field on each referenced IOC
            for ioc_key in ioc_keys:
                raw = self._r.hget(ioc_key, "threat_actors")
                if not raw:
                    continue
                current = json.loads(raw)
                updated = []
                for a in current:
                    if a == combined_name:
                        updated.extend(parts)
                    else:
                        updated.append(a)
                # Dedupe while preserving order
                updated = list(dict.fromkeys(updated))
                self._r.hset(ioc_key, "threat_actors", json.dumps(updated))

            # Rewrite the threat_actor field on each referenced rule
            for rule_key in rule_keys:
                current = self._r.hget(rule_key, "threat_actor")
                if current == combined_name:
                    # Rules only store a single actor string today; keep
                    # the first split name so the existing schema is happy.
                    self._r.hset(rule_key, "threat_actor", parts[0])

        return {
            "removed": sorted(combined),
            "added": sorted(added_set),
        }

    def get_actor_summary(self, actor_name: str) -> Dict:
        ioc_keys = self._r.smembers(self._actor_ioc_idx(actor_name))
        ioc_counts: Dict[str, int] = {}
        campaigns: List[str] = []
        ttps: List[str] = []

        ioc_keys_list = list(ioc_keys)
        if ioc_keys_list:
            # Batch fetch all IOC data
            pipe = self._r.pipeline()
            for key in ioc_keys_list:
                pipe.hgetall(key)
            all_data = pipe.execute()

            for data in all_data:
                if not data:
                    continue
                ioc_type = data.get("type", "unknown")
                ioc_counts[ioc_type] = ioc_counts.get(ioc_type, 0) + 1
                campaigns += json.loads(data.get("campaigns", "[]"))
                ttps += json.loads(data.get("ttps", "[]"))

        rule_keys = self._r.smembers(self._actor_rule_idx(actor_name))

        return {
            "actor": actor_name,
            "ioc_counts": ioc_counts,
            "total_iocs": len(ioc_keys_list) if ioc_keys_list else 0,
            "total_rules": len(rule_keys),
            "ttps": list(dict.fromkeys(ttps)),
            "campaigns": list(dict.fromkeys(campaigns)),
        }


# ── Factory ───────────────────────────────────────────────────────────────────

_cached_store: Optional[ThreatIntelStore] = None


def create_store(
    redis_url: Optional[str] = None,
) -> Optional[ThreatIntelStore]:
    """
    Return a configured RedisIntelStore, or None with a warning if:
    - REDIS_URL is not set and redis_url is not provided
    - the redis package is not installed
    - the Redis server is not reachable

    Uses a module-level singleton so callers share a single connection pool.
    """
    global _cached_store

    url = redis_url or __import__("os").getenv("REDIS_URL")
    if not url:
        warnings.warn(
            "[store] REDIS_URL not set — persistent store disabled.",
            stacklevel=2,
        )
        return None

    if _cached_store is not None:
        try:
            _cached_store._r.ping()
            return _cached_store
        except Exception:
            _cached_store = None

    try:
        from .config import RedisConfig

        cfg = RedisConfig()
        store = RedisIntelStore(
            url,
            key_prefix=cfg.key_prefix,
            max_connections=cfg.max_connections,
            default_ttl_days=cfg.default_ttl_days,
        )
        store._r.ping()
        _cached_store = store
        return store
    except ImportError:
        warnings.warn(
            "[store] redis package not installed"
            " (pip install redis[hiredis])"
            " — persistent store disabled.",
            stacklevel=2,
        )
        return None
    except Exception as e:
        warnings.warn(
            f"[store] Redis not reachable ({e})"
            " — persistent store disabled.",
            stacklevel=2,
        )
        return None
