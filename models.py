"""
Data models and schemas for the Threat Detection Agent
"""

from typing import Dict, List, Optional, Literal, TypedDict
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class LLMProvider(Enum):
    """Supported LLM providers"""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    PERPLEXITY = "perplexity"


class ThreatIntelligence(BaseModel):
    """Extracted threat intelligence data"""
    threat_actor: Optional[str]
    campaign_name: Optional[str]
    mitre_ttps: List[str]
    iocs: Dict[str, List[str]]
    attack_description: str
    targeted_systems: List[str]
    key_behaviors: List[str]


class DetectionRule(BaseModel):
    """Detection rule with metadata"""
    name: str
    description: str
    author: str = "Unknown"
    date: str = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))
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
    rule_format: Literal["sigma", "spl"]
    error: Optional[str]