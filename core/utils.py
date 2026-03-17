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
    """Determine appropriate author based on source URL"""
    url_lower = url.lower()
    for domain, author in AuthorMapping.DOMAIN_AUTHORS.items():
        if domain in url_lower:
            return author
    return AuthorMapping.DEFAULT_AUTHOR


def extract_json_from_text(text: str) -> Dict[str, Any]:
    """
    Extract JSON from text that may contain additional content.
    Handles various edge cases and malformed responses.
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
        except json.JSONDecodeError as e:
            print(f"JSON decode error after cleanup: {e}")
            print(f"Attempted to parse: {json_str[:200]}...")

    raise ValueError(f"Could not extract valid JSON from response")


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

    # Fix escaped characters that might cause issues
    json_str = json_str.replace('\\"', '"')
    json_str = re.sub(r"\\{2,}", r"\\", json_str)

    # Remove any BOM or zero-width characters
    json_str = json_str.encode("utf-8", "ignore").decode("utf-8-sig")

    return json_str


def sanitize_rule_content(content: str) -> str:
    """Check for and sanitize potentially dangerous rule content"""
    content_lower = content.lower()
    for term in Settings.FORBIDDEN_TERMS:
        if term in content_lower:
            return f"# [BLOCKED UNSAFE CONTENT]\n{content}"
    return content
