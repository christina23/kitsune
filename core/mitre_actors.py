"""
MITRE ATT&CK threat-actor → group-id mapping.

Fetches the canonical STIX bundle from the MITRE CTI repo, parses
intrusion-set objects, and builds a {normalized_alias: G####} dict.
Cached in Redis (7d TTL) with an in-memory layer on top; falls back
to the static dict in config.ActorGroupMapping on any failure.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
import warnings
from typing import Dict, Optional

from .config import ActorGroupMapping

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master"
    "/enterprise-attack/enterprise-attack.json"
)
_REDIS_KEY_SUFFIX = "mitre:actor_to_group"
_CACHE_TTL_SECONDS = 7 * 86400  # 7 days

_memory_cache: Optional[Dict[str, str]] = None


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def _parse_stix_bundle(bundle: dict) -> Dict[str, str]:
    """Extract {normalized_alias: G####} from a MITRE STIX bundle."""
    mapping: Dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        group_id = None
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack":
                eid = ref.get("external_id", "")
                if eid.startswith("G"):
                    group_id = eid
                    break
        if not group_id:
            continue

        aliases = [obj.get("name", "")] + list(obj.get("aliases", []) or [])
        for alias in aliases:
            key = _normalize(alias)
            if key:
                mapping.setdefault(key, group_id)
    return mapping


def _fetch_from_mitre(timeout: int = 20) -> Optional[Dict[str, str]]:
    """Fetch + parse the MITRE STIX bundle. Returns None on failure."""
    try:
        req = urllib.request.Request(
            MITRE_STIX_URL, headers={"User-Agent": "kitsune/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            bundle = json.loads(resp.read().decode("utf-8"))
        mapping = _parse_stix_bundle(bundle)
        if not mapping:
            return None
        return mapping
    except Exception as e:
        warnings.warn(
            f"[mitre_actors] MITRE STIX fetch failed: {e}", stacklevel=2
        )
        return None


def _redis_key() -> str:
    prefix = os.getenv("REDIS_KEY_PREFIX", "kitsune")
    return f"{prefix}:{_REDIS_KEY_SUFFIX}"


def _load_from_redis() -> Optional[Dict[str, str]]:
    try:
        from .intel_store import create_store

        store = create_store()
        if store is None:
            return None
        raw = store._r.get(_redis_key())
        if not raw:
            return None
        data = json.loads(raw)
        return data if isinstance(data, dict) and data else None
    except Exception:
        return None


def _save_to_redis(mapping: Dict[str, str]) -> None:
    try:
        from .intel_store import create_store

        store = create_store()
        if store is None:
            return
        store._r.setex(_redis_key(), _CACHE_TTL_SECONDS, json.dumps(mapping))
    except Exception:
        pass


def get_actor_to_mitre_group(refresh: bool = False) -> Dict[str, str]:
    """Return the {normalized_alias: G####} mapping.

    Lookup order:
    1. In-memory cache (unless refresh=True)
    2. Redis cache
    3. Live fetch from MITRE STIX → cached to Redis
    4. Static fallback from ActorGroupMapping.ACTOR_TO_MITRE_GROUP
    """
    global _memory_cache

    if _memory_cache is not None and not refresh:
        return _memory_cache

    if not refresh:
        cached = _load_from_redis()
        if cached:
            _memory_cache = cached
            return _memory_cache

    fetched = _fetch_from_mitre()
    if fetched:
        # Merge static fallback as a supplement — keeps common short aliases
        # like "lazarus" or "sandworm" that MITRE only stores as full names.
        merged = dict(ActorGroupMapping.ACTOR_TO_MITRE_GROUP)
        merged.update(fetched)  # MITRE data wins on conflicts
        _save_to_redis(merged)
        _memory_cache = merged
        return _memory_cache

    _memory_cache = dict(ActorGroupMapping.ACTOR_TO_MITRE_GROUP)
    return _memory_cache


def lookup(actor_slug: str) -> Optional[str]:
    """Convenience: look up a normalized actor slug, return G#### or None."""
    return get_actor_to_mitre_group().get(actor_slug)
