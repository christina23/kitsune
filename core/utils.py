"""
Utility functions for the Threat Detection Agent
"""

import os
import re
import json
from typing import List, Dict, Any
from .config import Settings, AuthorMapping


def parse_providers_from_env() -> List[str]:
    """
    Returns a normalized list of providers from env:
      - Prefer LLM_PROVIDERS (comma/space-separated)
      - Fallback to LLM_PROVIDER (single)
      - Fallback to ['openai']
    """
    raw = os.getenv("LLM_PROVIDERS") or os.getenv("LLM_PROVIDER")
    if not raw:
        return ["openai"]
    # support commas or spaces
    parts = [p.strip().lower() for p in re.split(r"[,\s]+", raw) if p.strip()]
    # de-dup while preserving order
    seen, out = set(), []
    for p in parts:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out or ["openai"]


def safe_filename(name: str) -> str:
    """Create a safe filename from a rule name"""
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", (name or "rule").strip())[
        : Settings.MAX_FILENAME_LENGTH
    ]
    return base or "rule"


def determine_author(url: str, threat_actor: str = None) -> str:
    """Determine appropriate author.

    Prefers the GitHub user name associated with GITHUB_TOKEN (so rules are
    attributed to the human running kitsune). Falls back to the report-domain
    mapping, then to the default.
    """
    try:
        from .github_pr import get_github_author_name
        gh_name = get_github_author_name()
        if gh_name:
            return gh_name
    except Exception:
        pass
    url_lower = (url or "").lower()
    for domain, author in AuthorMapping.DOMAIN_AUTHORS.items():
        if domain in url_lower:
            return author
    return AuthorMapping.DEFAULT_AUTHOR


def extract_json_from_text(text: str) -> Dict[str, Any]:
    """
    Extract JSON from text that may contain additional content.
    Handles various edge cases and malformed responses.
    Falls back to json-repair for LLM-generated JSON with unescaped quotes.
    """
    # First, try the most straightforward parsing
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass

    # Try to extract from markdown code blocks
    json_pattern = r"```(?:json)?\s*(.*?)\s*```"
    json_match = re.search(json_pattern, text, re.DOTALL | re.IGNORECASE)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find JSON object with proper brace matching
    brace_count = 0
    start_idx = -1
    end_idx = -1

    for i, char in enumerate(text):
        if char == "{" and start_idx == -1:
            start_idx = i
            brace_count = 1
        elif start_idx != -1:
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break

    if start_idx != -1 and end_idx != -1:
        json_str = text[start_idx:end_idx]

        # Clean up common JSON issues
        json_str = fix_json_formatting(json_str)

        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # Fallback: use json-repair to handle unescaped quotes and other
        # malformed LLM output (e.g. field="value" inside JSON strings)
        try:
            from json_repair import repair_json
            repaired = repair_json(json_str, return_objects=True)
            if isinstance(repaired, dict) and repaired:
                return repaired
        except Exception:
            pass

    # Last resort: attempt json-repair on the full text
    try:
        from json_repair import repair_json
        repaired = repair_json(text, return_objects=True)
        if isinstance(repaired, dict) and repaired:
            return repaired
    except Exception:
        pass

    raise ValueError("Could not extract valid JSON from response")


def fix_json_formatting(json_str: str) -> str:
    """Fix common JSON formatting issues"""
    # Remove trailing commas
    json_str = re.sub(r",\s*([}\]])", r"\1", json_str)

    # Fix missing commas between elements
    json_str = re.sub(r'"\s*\n\s*"', '",\n"', json_str)
    json_str = re.sub(r"}\s*\n\s*{", "},\n{", json_str)
    json_str = re.sub(r']\s*\n\s*"', '],\n"', json_str)
    json_str = re.sub(r"}\s*{", "},{", json_str)
    json_str = re.sub(r"]\s*\[", "],[", json_str)

    # Remove any BOM or zero-width characters
    json_str = json_str.encode("utf-8", "ignore").decode("utf-8-sig")

    return json_str


def scan_suspicious_input(text: str) -> list[str]:
    """Scan fetched intel text for instruction-like patterns that may
    indicate prompt injection. Returns a list of matched snippets (empty
    if clean). Non-blocking — callers decide what to do with matches.
    """
    if not text:
        return []
    matches: list[str] = []
    for pattern in Settings.SUSPICIOUS_INPUT_PATTERNS:
        for m in re.finditer(pattern, text, flags=re.IGNORECASE):
            matches.append(m.group(0))
    return matches
