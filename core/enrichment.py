"""
Enrichment functions that decorate rules and detection events with
threat actor, tradecraft, and TTP context from the intel store.
"""

import json
from typing import Any, Dict, List

from .intel_store import ThreatIntelStore
from .models import DetectionRule


def enrich_rule(rule: DetectionRule, store: ThreatIntelStore) -> Dict:
    """
    Return a dict enriching the rule with related actors, IOCs, and
    campaigns sourced from the store. The rule object is not mutated.
    """
    related_actors: List[str] = []
    related_iocs: Dict[str, List[str]] = {
        "ips": [],
        "domains": [],
        "hashes": [],
        "files": [],
        "urls": [],
    }
    associated_campaigns: List[str] = []

    # O(1) membership tracking (preserves insertion order in output lists)
    seen_actors = set()
    seen_campaigns = set()
    seen_iocs: Dict[str, set] = {k: set() for k in related_iocs}

    for ttp_id in rule.mitre_ttps:
        iocs = store.query_iocs(ttp=ttp_id)
        for ioc in iocs:
            ioc_type = ioc.get("type")
            value = ioc.get("value")
            if ioc_type and value and ioc_type in related_iocs:
                if value not in seen_iocs[ioc_type]:
                    seen_iocs[ioc_type].add(value)
                    related_iocs[ioc_type].append(value)
            actors = json.loads(ioc.get("threat_actors", "[]"))
            for a in actors:
                if a not in seen_actors:
                    seen_actors.add(a)
                    related_actors.append(a)
            camps = json.loads(ioc.get("campaigns", "[]"))
            for c in camps:
                if c not in seen_campaigns:
                    seen_campaigns.add(c)
                    associated_campaigns.append(c)

    return {
        "rule_name": rule.name,
        "rule_format": rule.format,
        "mitre_ttps": rule.mitre_ttps,
        "enrichment": {
            "related_actors": related_actors,
            "related_iocs": related_iocs,
            "associated_campaigns": associated_campaigns,
        },
    }


def enrich_detection_event(
    event: Dict[str, Any], store: ThreatIntelStore
) -> Dict[str, Any]:
    """
    Enrich a detection event dict with actor attribution, IOC context,
    and TTP context from the store.

    Expected event keys (both optional):
        matched_iocs: List[str]  — IOC values observed in the alert
        ttp_ids:      List[str]  — MITRE technique IDs in the alert
    """
    matched_iocs: List[str] = event.get("matched_iocs", [])
    ttp_ids: List[str] = event.get("ttp_ids", [])

    actor_attribution: List[str] = []
    campaign_context: List[str] = []
    ttp_context: List[Dict] = []
    related_iocs: List[str] = []
    matched_in_store = 0

    seen_actors = set()
    seen_campaigns = set()
    seen_related = set()
    matched_set = set(matched_iocs)

    # Reverse-lookup each matched IOC
    for value in matched_iocs:
        ioc_key = store._r.get(store._lookup_key(value))
        if not ioc_key:
            continue
        matched_in_store += 1
        data = store._r.hgetall(ioc_key)
        if not data:
            continue
        for a in json.loads(data.get("threat_actors", "[]")):
            if a not in seen_actors:
                seen_actors.add(a)
                actor_attribution.append(a)
        for c in json.loads(data.get("campaigns", "[]")):
            if c not in seen_campaigns:
                seen_campaigns.add(c)
                campaign_context.append(c)

    # TTP-based additional context
    for ttp_id in ttp_ids:
        iocs = store.query_iocs(ttp=ttp_id)
        for ioc in iocs:
            v = ioc.get("value")
            if v and v not in seen_related and v not in matched_set:
                seen_related.add(v)
                related_iocs.append(v)
        ttp_context.append({"ttp_id": ttp_id, "related_ioc_count": len(iocs)})

    confidence = matched_in_store / max(len(matched_iocs), 1)

    enriched = dict(event)
    enriched["enrichment"] = {
        "actor_attribution": actor_attribution,
        "related_iocs": related_iocs,
        "campaign_context": campaign_context,
        "ttp_context": ttp_context,
        "confidence": round(confidence, 3),
    }
    return enriched


def get_coverage_trends(store: ThreatIntelStore, top_n: int = 10) -> str:
    """Return a formatted plain-text coverage and trend report."""
    trending = store.get_trending_ttps(top_n)
    coverage = store.get_coverage_summary()
    actors = list(store._r.smembers(store._actors_key()))

    total_iocs = sum(
        v.get("ioc_count", 0) for v in coverage.values()
    )
    total_rules = sum(
        v.get("rule_count", 0) for v in coverage.values()
    )

    lines = [
        "=" * 60,
        "THREAT INTEL COVERAGE REPORT",
        "=" * 60,
        "",
        f"Top {top_n} Trending TTPs:",
    ]
    for entry in trending:
        lines.append(f"  {entry['ttp_id']:12s}  count={entry['count']}")

    lines += [
        "",
        f"{'TTP':12s}  {'IOCs':>6}  {'Rules':>6}  {'Has IOCs':>9}"
        f"  {'Has Rules':>10}",
        "-" * 52,
    ]
    for ttp_id, info in sorted(coverage.items()):
        lines.append(
            f"{ttp_id:12s}  {info['ioc_count']:>6}  {info['rule_count']:>6}"
            f"  {str(info['has_iocs']):>9}  {str(info['has_rules']):>10}"
        )

    lines += [
        "",
        f"Known actors ({len(actors)}): {', '.join(sorted(actors)) or 'none'}",
        f"Total IOCs indexed: {total_iocs}",
        f"Total rules indexed: {total_rules}",
        "=" * 60,
    ]
    return "\n".join(lines)
