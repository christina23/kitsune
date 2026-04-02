"""
Data models and schemas for the Threat Detection Agent
"""

from typing import List, Optional, Literal, TypedDict
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field

from .ioc_parser import IOCCollection, Technique


class LLMProvider(Enum):
    """Supported LLM providers"""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"


class CoverageGap(BaseModel):
    """A MITRE technique with no corresponding detection rule."""

    technique_id: str
    tactic: str
    priority: Literal["high", "medium", "low"]
    reason: str
    data_sources: List[str]
    confidence: float
    fuzzy_match: bool = False
    fuzzy_score: Optional[float] = None


class ThreatIntelligence(BaseModel):
    """Extracted threat intelligence data"""

    threat_actor: Optional[str]
    campaign_name: Optional[str]
    techniques: List[Technique] = []
    iocs: IOCCollection
    attack_description: str
    targeted_systems: List[str]
    key_behaviors: List[str]


class DetectionRule(BaseModel):
    """Detection rule with metadata"""

    name: str
    description: str
    author: str = "Unknown"
    date: str = Field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d")
    )
    references: List[str]
    mitre_ttps: List[str]
    rule_content: str
    format: Literal["sigma", "spl"]


class RuleOutput(BaseModel):
    """Individual rule output from LLM"""

    name: str
    description: str
    rule_content: str
    mitre_ttps: List[str] = []


class RulesBundle(BaseModel):
    """Bundle of multiple rules"""

    rules: List[RuleOutput]


class AgentState(TypedDict):
    """State for the LangGraph workflow"""

    url: str
    content: str
    threat_intel: Optional[ThreatIntelligence]
    detection_rules: List[DetectionRule]
    coverage_gaps: List[CoverageGap]
    rule_format: Literal["sigma", "spl"]
    error: Optional[str]
    _store_rules_cache: List[dict]
