"""
IOC extraction and validation for the Threat Detection Agent.

Provides:
  - IOCCollection  – typed Pydantic model replacing Dict[str, List[str]]
  - parse_iocs_from_text  – regex-based extraction from raw text
  - validate_and_enrich_iocs – merges LLM-extracted IOCs with regex findings
                               and deduplicates/normalizes each field
"""

import re
from typing import Dict, List, Optional
from pydantic import BaseModel

# ── Regex patterns ───────────────────────────────────────────────────────────

# IPv4, optionally with CIDR
_RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?\b"
)

# Simple domain / hostname (excludes bare TLDs and common non-IOC patterns)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|info|biz|gov|edu|ru|cn|de|uk|onion|"
    r"xyz|top|club|site|online|tech|app|dev|cloud|ai)\b",
    re.IGNORECASE,
)

# MD5, SHA-1, SHA-256 (hex strings of appropriate length)
_RE_HASH = re.compile(
    r"\b[0-9a-fA-F]{32}\b" r"|\b[0-9a-fA-F]{40}\b" r"|\b[0-9a-fA-F]{64}\b"
)

# HTTP/HTTPS/FTP URLs
_RE_URL = re.compile(
    r"https?://[^\s\"'<>{}\[\]]+|ftp://[^\s\"'<>{}\[\]]+",
    re.IGNORECASE,
)

# File names: anything with a known suspicious extension
_RE_FILE = re.compile(
    r"\b[\w\-. ]{1,64}"
    r"\.(?:exe|dll|bat|ps1|vbs|js|hta|msi|jar"
    r"|py|sh|elf|bin|dat|tmp|lnk|iso|img)\b",
    re.IGNORECASE,
)

# Noise: IPs that are obviously not IOCs
_PRIVATE_IP_RE = re.compile(
    r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)


# ── Model ────────────────────────────────────────────────────────────────────


class IOCCollection(BaseModel):
    """Typed container for all IOC categories."""

    ips: List[str] = []
    domains: List[str] = []
    hashes: List[str] = []
    files: List[str] = []
    urls: List[str] = []

    def is_empty(self) -> bool:
        return not any(
            [self.ips, self.domains, self.hashes, self.files, self.urls]
        )

    def total_count(self) -> int:
        items = [self.ips, self.domains, self.hashes, self.files, self.urls]
        return sum(len(v) for v in items)

    def to_dict(self) -> Dict[str, List[str]]:
        return {
            "ips": self.ips,
            "domains": self.domains,
            "hashes": self.hashes,
            "files": self.files,
            "urls": self.urls,
        }


# ── Helpers ──────────────────────────────────────────────────────────────────


def _dedupe(items: List[str]) -> List[str]:
    """Deduplicate while preserving insertion order."""
    seen: set = set()
    out: List[str] = []
    for item in items:
        norm = item.strip().lower()
        if norm and norm not in seen:
            seen.add(norm)
            out.append(item.strip())
    return out


def _is_public_ip(ip: str) -> bool:
    return not bool(_PRIVATE_IP_RE.match(ip))


def _urls_to_domains(urls: List[str]) -> List[str]:
    """Extract hostname from each URL for cross-referencing."""
    domains = []
    for url in urls:
        m = re.match(r"https?://([^/:?#\s]+)", url, re.IGNORECASE)
        if m:
            domains.append(m.group(1))
    return domains


# ── Public API ───────────────────────────────────────────────────────────────


def parse_iocs_from_text(text: str) -> IOCCollection:
    """
    Extract IOCs from raw text using regex patterns.
    Returns an IOCCollection with deduplicated, normalized values.
    """
    raw_ips = [ip for ip in _RE_IP.findall(text) if _is_public_ip(ip)]
    raw_urls = _RE_URL.findall(text)
    # Avoid double-counting domains already captured inside a URL
    url_hosts = set(h.lower() for h in _urls_to_domains(raw_urls))
    raw_domains = [
        d for d in _RE_DOMAIN.findall(text) if d.lower() not in url_hosts
    ]

    return IOCCollection(
        ips=_dedupe(raw_ips),
        domains=_dedupe(raw_domains),
        hashes=_dedupe(_RE_HASH.findall(text)),
        files=_dedupe(_RE_FILE.findall(text)),
        urls=_dedupe(raw_urls),
    )


# ── MITRE TTP Regex ──────────────────────────────────────────────────────────

_RE_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_RE_MITRE_FULL = re.compile(r"^T\d{4}(\.\d{3})?$")

_TACTIC_MAP: Dict[str, str] = {
    "T1003": "credential-access",
    "T1005": "collection",
    "T1020": "exfiltration",
    "T1021": "lateral-movement",
    "T1027": "defense-evasion",
    "T1046": "discovery",
    "T1047": "execution",
    "T1053": "persistence",
    "T1055": "defense-evasion",
    "T1059": "execution",
    "T1070": "defense-evasion",
    "T1071": "command-and-control",
    "T1078": "initial-access",
    "T1082": "discovery",
    "T1083": "discovery",
    "T1087": "discovery",
    "T1090": "command-and-control",
    "T1095": "command-and-control",
    "T1098": "persistence",
    "T1105": "command-and-control",
    "T1110": "credential-access",
    "T1112": "defense-evasion",
    "T1134": "privilege-escalation",
    "T1190": "initial-access",
    "T1204": "execution",
    "T1218": "defense-evasion",
    "T1486": "impact",
    "T1490": "impact",
    "T1497": "defense-evasion",
    "T1518": "discovery",
    "T1547": "persistence",
    "T1562": "defense-evasion",
    "T1566": "initial-access",
    "T1574": "privilege-escalation",
}


class Technique(BaseModel):
    """Typed MITRE ATT&CK technique with confidence scoring."""

    id: str  # e.g. "T1059.001"
    tactic: str  # from _TACTIC_MAP, else "unknown"
    confidence: float  # 0.0–1.0
    context: str = ""  # surrounding sentence from text


def _tactic_for(technique_id: str) -> str:
    """Look up tactic by technique ID or its parent."""
    parent = technique_id.split(".")[0]
    return _TACTIC_MAP.get(parent, "unknown")


def parse_ttps_from_text(text: str) -> List[Technique]:
    """
    Regex-scan raw text for MITRE technique IDs.
    Returns Technique objects with confidence=0.7 and ~120-char context window.
    """
    techniques: List[Technique] = []
    for m in _RE_MITRE.finditer(text):
        tid = m.group(0).upper()
        start = max(0, m.start() - 60)
        end = min(len(text), m.end() + 60)
        ctx = text[start:end].strip()
        techniques.append(
            Technique(
                id=tid,
                tactic=_tactic_for(tid),
                confidence=0.7,
                context=ctx,
            )
        )
    return techniques


def validate_ttps(llm_ttps: List[str], raw_text: str = "") -> List[Technique]:
    """
    Validate LLM-extracted TTP IDs and merge with regex findings from raw_text.

    - Rejects any LLM TTP that fails _RE_MITRE_FULL format check
    - confidence=1.0 if ID literally found in raw_text, else 0.85
    - Merges regex-only finds at confidence=0.7
    - Deduplicates (higher confidence wins), normalizes to uppercase
    - Returns sorted by confidence descending
    """
    validated: Dict[str, Technique] = {}

    for raw in llm_ttps:
        tid = raw.strip().upper()
        if not _RE_MITRE_FULL.match(tid):
            continue
        conf = 1.0 if (raw_text and tid in raw_text.upper()) else 0.85
        validated[tid] = Technique(
            id=tid, tactic=_tactic_for(tid), confidence=conf
        )

    if raw_text:
        for t in parse_ttps_from_text(raw_text):
            if t.id not in validated:
                validated[t.id] = t
            # keep the higher-confidence entry
            # (LLM-validated wins over regex-only)

    return sorted(validated.values(), key=lambda t: t.confidence, reverse=True)


def validate_and_enrich_iocs(
    llm_iocs: dict, raw_text: str = ""
) -> IOCCollection:
    """
    Build a validated IOCCollection from LLM-extracted IOC dict, optionally
    enriched with regex findings from raw_text.

    - Filters out clearly invalid values (empty strings, placeholder text)
    - Validates IPs against the IP regex; drops private IPs
    - Merges regex-found IOCs from raw_text when provided
    - Deduplicates across both sources
    """

    def _coerce_list(val) -> List[str]:
        if isinstance(val, list):
            return [str(v).strip() for v in val if v and str(v).strip()]
        if isinstance(val, str) and val.strip():
            return [val.strip()]
        return []

    llm_ips = [
        ip
        for ip in _coerce_list(llm_iocs.get("ips", []))
        if _RE_IP.fullmatch(ip) and _is_public_ip(ip)
    ]
    llm_domains = [
        d
        for d in _coerce_list(llm_iocs.get("domains", []))
        if _RE_DOMAIN.fullmatch(d)
    ]
    llm_hashes = [
        h
        for h in _coerce_list(llm_iocs.get("hashes", []))
        if _RE_HASH.fullmatch(h)
    ]
    llm_files = _coerce_list(llm_iocs.get("files", []))
    llm_urls = [
        u for u in _coerce_list(llm_iocs.get("urls", [])) if _RE_URL.match(u)
    ]

    if raw_text:
        regex_iocs = parse_iocs_from_text(raw_text)
        return IOCCollection(
            ips=_dedupe(llm_ips + regex_iocs.ips),
            domains=_dedupe(llm_domains + regex_iocs.domains),
            hashes=_dedupe(llm_hashes + regex_iocs.hashes),
            files=_dedupe(llm_files + regex_iocs.files),
            urls=_dedupe(llm_urls + regex_iocs.urls),
        )

    return IOCCollection(
        ips=_dedupe(llm_ips),
        domains=_dedupe(llm_domains),
        hashes=_dedupe(llm_hashes),
        files=_dedupe(llm_files),
        urls=_dedupe(llm_urls),
    )
