"""
Persistent IOC and threat intel store backed by Redis.

The store is opt-in: the pipeline runs normally when Redis is unavailable.
Use create_store() to get a configured store or None.
"""

import hashlib
import json
import time
import warnings
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from models import DetectionRule, ThreatIntelligence


def _slug(name: str) -> str:
    """Lowercase slug for use in Redis key names."""
    return name.lower().replace(" ", "_")


def _sha(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]


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


# ── Redis implementation ──────────────────────────────────────────────────────


class RedisIntelStore(ThreatIntelStore):
    """Redis-backed implementation of ThreatIntelStore."""

    def __init__(self, redis_url: str, key_prefix: str = "kitsune"):
        import redis  # lazy import — missing package won't break module load

        self._r = redis.from_url(redis_url, decode_responses=True)
        self._p = key_prefix

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

        pipe = self._r.pipeline()
        pipe.hsetnx(key, "first_seen", now)
        pipe.hset(
            key,
            mapping={"type": ioc_type, "value": value, "last_seen": now},
        )
        pipe.execute()

        # Merge JSON arrays
        for field_name, new_items in [
            ("threat_actors", actors),
            ("campaigns", campaigns),
            ("ttps", ttps),
            ("source_urls", [source_url]),
        ]:
            existing = self._r.hget(key, field_name)
            self._r.hset(
                key, field_name, _merge_json_list(existing, new_items)
            )

        # Indexes and timeline
        pipe = self._r.pipeline()
        for actor in actors:
            pipe.sadd(self._actor_ioc_idx(actor), key)
        for ttp_id in ttps:
            pipe.sadd(self._ttp_ioc_idx(ttp_id), key)
            pipe.zincrby(self._trend_key(), 1, ttp_id)
        pipe.zadd(self._timeline_key(), {key: float(now)})
        pipe.set(self._lookup_key(value), key)
        pipe.execute()

        if actors:
            self._r.sadd(self._actors_key(), *actors)

    def ingest_threat_intel(
        self, threat_intel: ThreatIntelligence, source_url: str
    ) -> None:
        actors = (
            [threat_intel.threat_actor] if threat_intel.threat_actor else []
        )
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
    ) -> None:
        for rule in rules:
            key = self._rule_key(rule.name, rule.rule_content)
            self._r.hset(
                key,
                mapping={
                    "name": rule.name,
                    "format": rule.format,
                    "ttps": json.dumps(rule.mitre_ttps),
                    "threat_actor": threat_actor,
                    "source_url": source_url,
                    "created_at": str(time.time()),
                },
            )
            pipe = self._r.pipeline()
            if threat_actor:
                pipe.sadd(self._actor_rule_idx(threat_actor), key)
            for ttp_id in rule.mitre_ttps:
                pipe.sadd(self._ttp_rule_idx(ttp_id), key)
            pipe.execute()

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

        results = []
        for key in list(keys)[:limit]:
            data = self._r.hgetall(key)
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
            # Scan for all rule keys
            keys = list(self._r.scan_iter(f"{self._p}:rule:*"))

        results = []
        for key in list(keys)[:limit]:
            data = self._r.hgetall(key)
            if data:
                results.append(data)
        return results

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

    def get_actor_summary(self, actor_name: str) -> Dict:
        ioc_keys = self._r.smembers(self._actor_ioc_idx(actor_name))
        ioc_counts: Dict[str, int] = {}
        campaigns: List[str] = []
        ttps: List[str] = []

        for key in ioc_keys:
            data = self._r.hgetall(key)
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
            "total_iocs": len(ioc_keys),
            "total_rules": len(rule_keys),
            "ttps": list(dict.fromkeys(ttps)),
            "campaigns": list(dict.fromkeys(campaigns)),
        }


# ── Factory ───────────────────────────────────────────────────────────────────


def create_store(
    redis_url: Optional[str] = None,
) -> Optional[ThreatIntelStore]:
    """
    Return a configured RedisIntelStore, or None with a warning if:
    - REDIS_URL is not set and redis_url is not provided
    - the redis package is not installed
    - the Redis server is not reachable
    """
    url = redis_url or __import__("os").getenv("REDIS_URL")
    if not url:
        warnings.warn(
            "[store] REDIS_URL not set — persistent store disabled.",
            stacklevel=2,
        )
        return None

    try:
        store = RedisIntelStore(url)
        store._r.ping()
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
