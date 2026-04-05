"""
MITRE ATT&CK technique -> tactic(s) lookup.

The sigma rules in our baseline typically only carry `attack.t####` tags
without the accompanying tactic slug, so we maintain a separate mapping
derived from MITRE's published STIX data.

On first use the module fetches `enterprise-attack.json` from the
official MITRE repo, extracts the technique→tactic map, and caches it
to `~/.cache/kitsune/ttp_tactics.json`. Subsequent calls read from the
cache. If the fetch fails we return an empty map and log a warning —
callers see empty tactic lists and techniques land in the "unknown"
bucket, which degrades gracefully.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List

log = logging.getLogger(__name__)

_CACHE_PATH = Path.home() / ".cache" / "kitsune" / "ttp_tactics.json"
_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

_cache: Dict[str, List[str]] | None = None


def _parse_stix(stix: dict) -> Dict[str, List[str]]:
    """Extract {technique_id: [tactic_slug,...]} from a STIX bundle."""
    mapping: Dict[str, List[str]] = {}
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        # Find the technique ID (T####/T####.###)
        ttp_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ttp_id = ref.get("external_id")
                break
        if not ttp_id:
            continue
        # Tactics come from kill_chain_phases on ATT&CK objects
        tactics = [
            p.get("phase_name")
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
            and p.get("phase_name")
        ]
        if tactics:
            mapping[ttp_id.upper()] = tactics
    return mapping


def _fetch_and_cache() -> Dict[str, List[str]]:
    """Download the MITRE STIX bundle and cache the distilled mapping."""
    import requests

    log.info("Fetching MITRE ATT&CK TTP→tactic mapping from %s", _STIX_URL)
    resp = requests.get(_STIX_URL, timeout=30)
    resp.raise_for_status()
    mapping = _parse_stix(resp.json())
    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CACHE_PATH.write_text(json.dumps(mapping))
    log.info("Cached %d TTP→tactic mappings to %s", len(mapping), _CACHE_PATH)
    return mapping


def get_ttp_tactic_map() -> Dict[str, List[str]]:
    """Return the TTP→tactic mapping, fetching+caching on first access."""
    global _cache
    if _cache is not None:
        return _cache
    if _CACHE_PATH.exists():
        try:
            _cache = json.loads(_CACHE_PATH.read_text())
            return _cache
        except Exception as exc:
            log.warning("TTP tactic cache unreadable (%s), refetching", exc)
    try:
        _cache = _fetch_and_cache()
    except Exception as exc:
        log.warning("Could not fetch MITRE TTP→tactic map: %s", exc)
        _cache = {}
    return _cache


def tactics_for(ttp_id: str) -> List[str]:
    """Return tactic slugs for a TTP id, falling back to parent technique."""
    mapping = get_ttp_tactic_map()
    ttp_id = (ttp_id or "").upper().strip()
    if ttp_id in mapping:
        return mapping[ttp_id]
    # Sub-technique fallback: T1059.007 → T1059
    if "." in ttp_id:
        parent = ttp_id.split(".", 1)[0]
        if parent in mapping:
            return mapping[parent]
    return []
