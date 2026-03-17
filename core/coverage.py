"""
Coverage gap analysis for the Threat Detection Agent.

Compares extracted MITRE techniques against existing detection rules to
identify which techniques lack coverage, their priority, and recommended
data sources.
"""

from typing import Dict, List

from .ioc_parser import Technique
from .models import DetectionRule, CoverageGap

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

    Returns gaps sorted: high first, then descending confidence.
    """
    # Build set of all technique IDs covered by existing rules (normalized)
    covered: set = set()
    for rule in generated_rules:
        for tid in rule.mitre_ttps:
            tid_upper = tid.strip().upper()
            covered.add(tid_upper)
            # Also register the parent so sub-techniques count
            parent = tid_upper.split(".")[0]
            covered.add(parent)

    gaps: List[CoverageGap] = []
    for tech in techniques:
        tid = tech.id.upper()
        parent = tid.split(".")[0]

        # Covered if exact ID or parent is in any rule
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
