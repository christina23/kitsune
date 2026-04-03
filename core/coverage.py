"""
Coverage gap analysis for the Threat Detection Agent.

Compares extracted MITRE techniques against existing detection rules to
identify which techniques lack coverage, their priority, and recommended
data sources.
"""

import json
from typing import Dict, List, Optional

from .ioc_parser import Technique
from .models import DetectionRule, CoverageGap

# Maximum TLSH distance to consider two content blobs "similar"
TLSH_THRESHOLD = 150


def _tlsh_hash(content: str) -> str:
    """Compute TLSH hash; returns empty string if py-tlsh unavailable or content too short."""
    try:
        import tlsh  # py-tlsh

        h = tlsh.hash(content.encode())
        return h if h != "TNULL" else ""
    except Exception:
        return ""


def _tlsh_distance(h1: str, h2: str) -> Optional[int]:
    """Return TLSH distance between two hashes, or None if either is empty."""
    if not h1 or not h2:
        return None
    try:
        import tlsh

        return tlsh.diff(h1, h2)
    except Exception:
        return None

# Maps top-level technique IDs to the log sources most likely to detect them
TECHNIQUE_DATA_SOURCES: Dict[str, List[str]] = {
    "T1003": [
        "Windows Security Events (4688)",
        "Sysmon (EventID 10)",
        "PowerShell Logging",
    ],
    "T1005": ["File Audit Logs", "Sysmon (EventID 11)", "DLP Telemetry"],
    "T1020": ["Network Flow Logs", "Proxy Logs", "Cloud Storage Audit Logs"],
    "T1021": [
        "Windows Security Events (4624, 4648)",
        "Sysmon (EventID 3)",
        "RDP Logs",
    ],
    "T1027": ["Sysmon (EventID 1)", "AV/EDR Telemetry", "File Audit Logs"],
    "T1046": ["Network Flow Logs", "Sysmon (EventID 3)", "IDS/IPS Alerts"],
    "T1047": [
        "Windows Security Events (4688)",
        "Sysmon (EventID 1)",
        "WMI Activity Logs",
    ],
    "T1053": [
        "Windows Security Events (4698, 4702)",
        "Sysmon (EventID 1)",
        "Task Scheduler Logs",
    ],
    "T1055": [
        "Sysmon (EventID 8, 10)",
        "Windows Security Events (4688)",
        "EDR Telemetry",
    ],
    "T1059": [
        "Sysmon (EventID 1)",
        "PowerShell Script Block Logging",
        "Windows Events (4688)",
    ],
    "T1070": [
        "Sysmon (EventID 1, 3)",
        "Windows Security Events (1102)",
        "File Audit Logs",
    ],
    "T1071": ["Proxy Logs", "Network Flow Logs", "DNS Query Logs"],
    "T1078": [
        "Windows Security Events (4624, 4625)",
        "Cloud Authentication Logs",
    ],
    "T1082": [
        "Sysmon (EventID 1)",
        "Windows Security Events (4688)",
        "EDR Telemetry",
    ],
    "T1083": [
        "Sysmon (EventID 1)",
        "Windows Security Events (4688)",
        "File Audit Logs",
    ],
    "T1087": [
        "Windows Security Events (4661)",
        "Sysmon (EventID 1)",
        "LDAP Logs",
    ],
    "T1090": ["Network Flow Logs", "Proxy Logs", "Firewall Logs"],
    "T1095": ["Network Flow Logs", "Firewall Logs", "IDS/IPS Alerts"],
    "T1098": [
        "Windows Security Events (4738)",
        "Cloud IAM Audit Logs",
        "Directory Service Logs",
    ],
    "T1105": ["Network Flow Logs", "Proxy Logs", "Sysmon (EventID 3, 11)"],
    "T1110": [
        "Windows Security Events (4625)",
        "Cloud Authentication Logs",
        "VPN Logs",
    ],
    "T1112": [
        "Sysmon (EventID 12, 13)",
        "Windows Security Events (4657)",
        "EDR Telemetry",
    ],
    "T1134": [
        "Windows Security Events (4672, 4673)",
        "Sysmon (EventID 1)",
        "EDR Telemetry",
    ],
    "T1190": [
        "Web Application Firewall Logs",
        "IDS/IPS Alerts",
        "Network Flow Logs",
    ],
    "T1204": [
        "Sysmon (EventID 1, 11)",
        "Email Gateway Logs",
        "Endpoint AV Logs",
    ],
    "T1218": [
        "Sysmon (EventID 1)",
        "Windows Security Events (4688)",
        "EDR Telemetry",
    ],
    "T1486": [
        "Sysmon (EventID 11)",
        "File Audit Logs",
        "Volume Shadow Copy Logs",
    ],
    "T1490": [
        "Windows Security Events (4688)",
        "Sysmon (EventID 1)",
        "Volume Shadow Copy Logs",
    ],
    "T1562": [
        "Windows Security Events (4688, 1102)",
        "Sysmon (EventID 1)",
        "AV/EDR Telemetry",
    ],
    "T1566": ["Email Gateway Logs", "Proxy Logs", "Endpoint AV Logs"],
}


def analyze_gaps(
    techniques: List[Technique],
    generated_rules: List[DetectionRule],
    store_rules: Optional[List[Dict]] = None,
    use_tlsh: bool = True,
) -> List[CoverageGap]:
    """
    Identify which extracted techniques have no corresponding detection rule.

    Sub-technique parent matching: T1059.001 is considered covered if T1059
    appears in any rule (and vice versa — T1059 is covered
    if T1059.001 exists).

    Priority is based on confidence:
      >= 0.9  → "high"
      >= 0.75 → "medium"
      < 0.75  → "low"

    When use_tlsh=True (Phase 1), techniques not covered by exact TTP match
    are checked against rule content via TLSH fuzzy hashing. A fuzzy match
    produces a "low" priority gap with fuzzy_match=True rather than a full gap.

    store_rules: raw dicts from RedisIntelStore.query_rules() — used in Phase 1
    to check existing store coverage before new rules are generated.

    Returns gaps sorted: high first, then descending confidence.
    """
    # Build set of all technique IDs covered by generated rules (normalized)
    covered: set = set()
    for rule in generated_rules:
        for tid in rule.mitre_ttps:
            tid_upper = tid.strip().upper()
            covered.add(tid_upper)
            covered.add(tid_upper.split(".")[0])

    # Also add coverage from store rules
    if store_rules:
        for sr in store_rules:
            for tid in json.loads(sr.get("ttps", "[]")):
                tid_upper = tid.strip().upper()
                covered.add(tid_upper)
                covered.add(tid_upper.split(".")[0])

    # Build TLSH content pairs for fuzzy checking (Phase 1 only)
    rule_tlsh_pairs: List[str] = []
    if use_tlsh:
        for rule in generated_rules:
            h = _tlsh_hash(rule.rule_content)
            if h:
                rule_tlsh_pairs.append(h)
        if store_rules:
            for sr in store_rules:
                h = sr.get("tlsh_hash", "")
                if not h and sr.get("rule_content"):
                    h = _tlsh_hash(sr["rule_content"])
                if h:
                    rule_tlsh_pairs.append(h)

    gaps: List[CoverageGap] = []
    for tech in techniques:
        tid = tech.id.upper()
        parent = tid.split(".")[0]

        # Exact coverage check
        if tid in covered or parent in covered:
            continue

        if tech.confidence >= 0.9:
            priority = "high"
        elif tech.confidence >= 0.75:
            priority = "medium"
        else:
            priority = "low"

        data_sources = TECHNIQUE_DATA_SOURCES.get(
            parent, ["General endpoint/network telemetry"]
        )

        # TLSH fuzzy check (Phase 1 only, requires ≥50 bytes of context)
        if use_tlsh and tech.context and len(tech.context) >= 50 and rule_tlsh_pairs:
            tech_hash = _tlsh_hash(tech.context)
            fuzzy_covered = False
            best_dist: Optional[int] = None
            if tech_hash:
                for rh in rule_tlsh_pairs:
                    dist = _tlsh_distance(tech_hash, rh)
                    if dist is not None:
                        if best_dist is None or dist < best_dist:
                            best_dist = dist
                        if dist < TLSH_THRESHOLD:
                            fuzzy_covered = True
                            break

            if fuzzy_covered and best_dist is not None:
                gaps.append(
                    CoverageGap(
                        technique_id=tid,
                        tactic=tech.tactic,
                        priority="low",
                        reason=(
                            f"Possible fuzzy coverage for {tid} ({tech.tactic})"
                            f" via TLSH dist={best_dist}; verify manually"
                        ),
                        data_sources=data_sources,
                        confidence=tech.confidence,
                        fuzzy_match=True,
                        fuzzy_score=float(best_dist),
                    )
                )
                continue

        gaps.append(
            CoverageGap(
                technique_id=tid,
                tactic=tech.tactic,
                priority=priority,
                reason=(
                    f"No detection rule covers {tid}"
                    f" ({tech.tactic});"
                    f" confidence={tech.confidence:.2f}"
                ),
                data_sources=data_sources,
                confidence=tech.confidence,
            )
        )

    # Sort: high → medium → low, then descending confidence within each tier
    priority_order = {"high": 0, "medium": 1, "low": 2}
    gaps.sort(key=lambda g: (priority_order[g.priority], -g.confidence))
    return gaps
