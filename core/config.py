"""
Configuration settings for the Threat Detection Agent
"""

import os
from dataclasses import dataclass, field
from typing import Dict, Any
from .models import LLMProvider


class LLMConfig:
    """LLM provider configurations"""

    DEFAULTS: Dict[LLMProvider, Dict[str, Any]] = {
        LLMProvider.ANTHROPIC: {
            "model": os.getenv(
                "ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"
            ),
            "api_key_env": "ANTHROPIC_API_KEY",
            "max_tokens": 4096,
        },
        LLMProvider.OPENAI: {
            "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            "api_key_env": "OPENAI_API_KEY",
            "max_tokens": 4096,
        },
    }


class AuthorMapping:
    """Domain to author attribution mapping"""

    DOMAIN_AUTHORS = {
        "google.com": "Google Threat Intelligence Group (GTIG)",
        "microsoft.com": "Microsoft Threat Intelligence",
        "crowdstrike.com": "CrowdStrike Intelligence",
        "fireeye.com": "Mandiant Threat Intelligence",
        "mandiant.com": "Mandiant Threat Intelligence",
        "symantec.com": "Symantec Threat Intelligence",
        "broadcom.com": "Symantec Threat Intelligence",
        "secureworks.com": "Secureworks CTU",
        "trendmicro.com": "Trend Micro Research",
        "kaspersky.com": "Kaspersky GReAT",
    }

    DEFAULT_AUTHOR = "Security Research Team"


class Settings:
    """General application settings"""

    # Text processing
    CHUNK_SIZE = 4000
    CHUNK_OVERLAP = 200

    # File handling
    MAX_FILENAME_LENGTH = 120
    OUTPUT_DIR = "output"

    # LLM settings
    DEFAULT_TEMPERATURE = 0
    MAX_RETRIES = 3
    RETRY_DELAY = 1.0

    # JSON extraction
    JSON_EXTRACT_MAX_RETRIES = 3

    # Content safety
    FORBIDDEN_TERMS = ["disable logging", "delete", "shutdown", "format disk"]


@dataclass
class RedisConfig:
    """Redis connection configuration for the optional threat intel store."""

    url: str = field(
        default_factory=lambda: os.getenv(
            "REDIS_URL", "redis://localhost:6379"
        )
    )
    key_prefix: str = field(
        default_factory=lambda: os.getenv("REDIS_KEY_PREFIX", "kitsune")
    )
    enabled: bool = field(
        default_factory=lambda: bool(os.getenv("REDIS_URL"))
    )
