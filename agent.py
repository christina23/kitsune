"""
Core Threat Detection Agent implementation
"""

import os
import time
import hashlib
from typing import Dict, List, Optional, Literal
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_community.document_loaders import WebBaseLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain.output_parsers import OutputFixingParser
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from models import (
    ThreatIntelligence,
    DetectionRule,
    AgentState,
    RuleOutput,
    RulesBundle,
    CoverageGap,
)
from config import Settings
from llm_factory import LLMFactory
from utils import (
    extract_json_from_text,
    fix_json_formatting,
    sanitize_rule_content,
    determine_author,
    safe_filename,
)
from prompts import (
    THREAT_INTEL_EXTRACTION_PROMPT,
    SPL_GENERATION_PROMPT,
    SIGMA_GENERATION_PROMPT,
    JSON_FORMAT_INSTRUCTIONS_ANTHROPIC,
)
from ioc_parser import validate_and_enrich_iocs, validate_ttps
from coverage import analyze_gaps


class ThreatDetectionAgent:
    """Main agent for generating threat detection rules
    from intelligence sources.
    """

    def __init__(
        self,
        llm_provider: Optional[str] = None,
        llm_model: Optional[str] = None,
        temperature: float = 0,
        api_keys: Optional[Dict[str, str]] = None,
        **llm_kwargs,
    ):
        self.llm_provider = llm_provider or os.getenv("LLM_PROVIDER", "openai")
        self.llm_factory = LLMFactory(
            default_provider=self.llm_provider, api_keys=api_keys
        )
        self.llm = self.llm_factory.create_model(
            provider=llm_provider,
            model_name=llm_model,
            temperature=temperature,
            **llm_kwargs,
        )
        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=Settings.CHUNK_SIZE,
            chunk_overlap=Settings.CHUNK_OVERLAP,
        )
        self.workflow = self._create_workflow()
        self.app = self.workflow.compile(checkpointer=MemorySaver())

    def _get_valid_json_response(
        self, prompt, expected_keys=None, max_retries=3
    ):
        """
        Get a valid JSON response from the LLM with retries
        for malformed responses.
        """
        for attempt in range(max_retries):
            try:
                if self.llm_provider == "anthropic":
                    # Add explicit JSON-only instruction for Anthropic
                    json_instruction = JSON_FORMAT_INSTRUCTIONS_ANTHROPIC

                    # Modify the prompt to emphasize JSON-only output
                    if isinstance(prompt, ChatPromptTemplate):
                        messages = prompt.messages.copy()
                        # Add JSON instruction to the last human message
                        if messages and isinstance(messages[-1], HumanMessage):
                            messages[-1].content = (
                                f"{messages[-1].content}"
                                f"\n\n{json_instruction}"
                            )
                        modified_prompt = ChatPromptTemplate.from_messages(
                            messages
                        )
                    else:
                        modified_prompt = prompt

                    chain = modified_prompt | self.llm
                else:
                    chain = prompt | self.llm

                response = chain.invoke({})
                response_text = (
                    response.content
                    if hasattr(response, "content")
                    else str(response)
                )

                # Extract and validate JSON
                result = extract_json_from_text(response_text)

                # Validate expected keys if provided
                if expected_keys:
                    for key in expected_keys:
                        if key not in result:
                            raise ValueError(f"Missing expected key: {key}")

                return result

            except Exception as e:
                if attempt == max_retries - 1:
                    print(f"All attempts failed to get valid JSON: {e}")
                    raise
                print(f"Attempt {attempt + 1} failed: {e}, retrying...")
                time.sleep(Settings.RETRY_DELAY)
                continue

        raise ValueError("Failed to get valid JSON response after all retries")

    def _retry_llm_call(
        self, chain, input_data: dict, max_retries: int = 3, delay: float = 1.0
    ):
        """Retry LLM calls with exponential backoff"""
        for attempt in range(max_retries):
            try:
                return chain.invoke(input_data)
            except Exception as e:
                if attempt == max_retries - 1:
                    raise e
                print(
                    f"Attempt {attempt + 1} failed"
                    f" for {self.llm_provider}: {str(e)}"
                )
                time.sleep(delay * (2**attempt))

    def _route_to_rule_generator(self, state: AgentState) -> str:
        """Route to appropriate rule generator based on format"""
        # Check if threat_intel extraction failed
        if state.get("threat_intel") is None:
            # Skip rule generation if no threat intel
            return "end"
        return state.get("rule_format", "spl")

    def _create_workflow(self) -> StateGraph:
        """Create the LangGraph workflow"""
        workflow = StateGraph(AgentState)
        workflow.add_node("fetch_content", self._fetch_content)
        workflow.add_node("extract_threat_intel", self._extract_threat_intel)
        workflow.add_node("generate_sigma_rules", self._generate_sigma_rules)
        workflow.add_node("generate_spl_rules", self._generate_spl_rules)
        workflow.add_node("analyze_coverage", self._analyze_coverage)
        workflow.set_entry_point("fetch_content")
        workflow.add_edge("fetch_content", "extract_threat_intel")
        workflow.add_conditional_edges(
            "extract_threat_intel",
            self._route_to_rule_generator,
            {
                "sigma": "generate_sigma_rules",
                "spl": "generate_spl_rules",
                "end": END,
            },
        )
        workflow.add_edge("generate_sigma_rules", "analyze_coverage")
        workflow.add_edge("generate_spl_rules", "analyze_coverage")
        workflow.add_edge("analyze_coverage", END)
        return workflow

    def _fetch_content(self, state: AgentState) -> AgentState:
        """Fetch and process content from URL"""
        try:
            loader = WebBaseLoader(state["url"])
            documents = loader.load()
            full_text = "\n".join([doc.page_content for doc in documents])
            chunks = self.splitter.split_text(full_text)
            relevant_content = (
                "\n".join(chunks[:3] + chunks[-2:])
                if len(chunks) > 5
                else full_text
            )
            state["content"] = relevant_content
            print(f"Fetched {len(relevant_content)} characters from URL")
        except Exception as e:
            state["error"] = f"Failed to fetch content: {str(e)}"
            state["content"] = ""
        return state

    def _extract_threat_intel(self, state: AgentState) -> AgentState:
        """Extract threat intelligence from content"""
        if not state["content"]:
            return state

        extraction_prompt = ChatPromptTemplate.from_messages(
            [
                SystemMessage(content=THREAT_INTEL_EXTRACTION_PROMPT),
                HumanMessage(
                    content=(
                        "Extract threat intelligence with maximum"
                        " precision from this security report:"
                        f"\n\n{state['content'][:4000]}"
                    ),
                ),
            ]
        )

        try:
            raw_intel = self._get_valid_json_response(
                extraction_prompt,
                expected_keys=[
                    "threat_actor",
                    "iocs",
                    "attack_description",
                    "targeted_systems",
                    "key_behaviors",
                ],
            )

            # Ensure all required fields are present with defaults
            raw_intel.setdefault("threat_actor", None)
            raw_intel.setdefault("campaign_name", None)
            raw_intel.setdefault(
                "attack_description", "Unknown attack methodology"
            )
            raw_intel.setdefault("targeted_systems", [])
            raw_intel.setdefault("key_behaviors", [])

            # Validate, normalise, and regex-enrich IOCs
            raw_intel["iocs"] = validate_and_enrich_iocs(
                raw_intel.get("iocs") or {},
                raw_text=state["content"],
            )

            # Validate, deduplicate, and confidence-score TTPs
            raw_ttps = raw_intel.pop("mitre_ttps", [])
            techniques = validate_ttps(raw_ttps, raw_text=state["content"])
            raw_intel["techniques"] = [t.model_dump() for t in techniques]

            threat_intel = ThreatIntelligence(**raw_intel)
            state["threat_intel"] = threat_intel
            actor = threat_intel.threat_actor or "Unknown Actor"
            ioc_count = threat_intel.iocs.total_count()
            ttp_count = len(threat_intel.techniques)
            print(
                f"Extracted threat intel for: {actor} "
                f"({ioc_count} IOCs, {ttp_count} TTPs)"
            )

        except Exception as e:
            print(f"Threat intel extraction failed: {str(e)}")
            state["error"] = f"Failed to extract threat intelligence: {str(e)}"
            state["threat_intel"] = None

        return state

    def _route_to_rule_generator(self, state: AgentState) -> str:
        """Route to appropriate rule generator based on format"""
        return state.get("rule_format", "spl")

    def generate_detections(
        self, url: str, rule_format: Literal["sigma", "spl"] = "spl"
    ) -> List[DetectionRule]:
        """Main public method to generate detection rules from a URL"""
        initial_state: AgentState = {
            "url": url,
            "content": "",
            "threat_intel": None,
            "detection_rules": [],
            "coverage_gaps": [],
            "rule_format": rule_format,
            "error": None,
        }
        config = {
            "configurable": {
                "thread_id": f"threat-detection-{hash(url) % 1000}"
            }
        }

        try:
            result = self.app.invoke(initial_state, config)
            if result.get("error"):
                print(f"Error: {result['error']}")
            return result.get("detection_rules", [])
        except Exception as e:
            print(f"Workflow execution failed: {str(e)}")
            return []

    def format_rule_output(self, rule: DetectionRule) -> str:
        """Format a detection rule for output"""
        if rule.format == "spl":
            header = f"""comment("
    Name: {rule.name}
    Author: {rule.author}
    Date: {rule.date}
    Description: {rule.description}
    References: {', '.join(rule.references)}
    MITRE TTPs: {', '.join(rule.mitre_ttps)}
    ")"""
            return f"{header}\n{rule.rule_content}"
        else:
            return rule.rule_content

    def _generate_spl_rules(self, state: AgentState) -> AgentState:
        """Generate Splunk SPL detection rules"""
        if not state.get("threat_intel"):
            state["detection_rules"] = []
            state["error"] = (
                "No threat intelligence available for rule generation"
            )
            return state

        intel = state["threat_intel"]
        author = determine_author(state["url"], intel.threat_actor)

        prompt_content = SPL_GENERATION_PROMPT.format(
            threat_actor=intel.threat_actor or "Unknown",
            campaign_name=intel.campaign_name or "N/A",
            mitre_ttps=", ".join(
                f"{t.id}({t.tactic})" for t in intel.techniques
            ),
            attack_description=intel.attack_description,
            key_behaviors=", ".join(intel.key_behaviors or []),
            targeted_systems=", ".join(intel.targeted_systems or []),
            iocs=intel.iocs.to_dict() if intel.iocs else {},
            json_format_section=(
                JSON_FORMAT_INSTRUCTIONS_ANTHROPIC
                if self.llm_provider == "anthropic"
                else ""
            ),
        )

        prompt = ChatPromptTemplate.from_messages(
            [
                SystemMessage(
                    content=(
                        "You are a principal detection engineer"
                        " with deep expertise in threat hunting"
                        " and Splunk SPL. Create sophisticated,"
                        " context-aware detection rules."
                    )
                ),
                HumanMessage(content=prompt_content),
            ]
        )

        try:
            bundle_data = self._get_valid_json_response(
                prompt, expected_keys=["rules"], max_retries=3
            )

            rules_list = bundle_data.get("rules", [])
            state["detection_rules"] = self._finalize_rules(
                rules_list,
                rule_format="spl",
                reference=state["url"],
                author=author,
            )
            print(f"Generated {len(state['detection_rules'])} SPL rules")

        except Exception as e:
            print(f"SPL rule generation failed: {str(e)}")
            state["error"] = f"Failed to generate SPL rules: {str(e)}"
            state["detection_rules"] = []
        return state

    def _generate_sigma_rules(self, state: AgentState) -> AgentState:
        """Generate Sigma detection rules"""
        if not state.get("threat_intel"):
            state["detection_rules"] = []
            state["error"] = (
                "No threat intelligence available for rule generation"
            )
            return state

        intel = state["threat_intel"]
        author = determine_author(state["url"], intel.threat_actor)

        prompt_content = SIGMA_GENERATION_PROMPT.format(
            threat_actor=intel.threat_actor or "Unknown",
            campaign_name=intel.campaign_name or "N/A",
            mitre_ttps=", ".join(
                f"{t.id}({t.tactic})" for t in intel.techniques
            ),
            attack_description=intel.attack_description,
            key_behaviors=", ".join(intel.key_behaviors or []),
            targeted_systems=", ".join(intel.targeted_systems or []),
            iocs=intel.iocs.to_dict() if intel.iocs else {},
            json_format_section=(
                JSON_FORMAT_INSTRUCTIONS_ANTHROPIC
                if self.llm_provider == "anthropic"
                else ""
            ),
        )

        prompt = ChatPromptTemplate.from_messages(
            [
                SystemMessage(
                    content=(
                        "You are a threat detection expert"
                        " specializing in Sigma rule development"
                        " for enterprise security operations."
                    )
                ),
                HumanMessage(content=prompt_content),
            ]
        )

        try:
            bundle_data = self._get_valid_json_response(
                prompt, expected_keys=["rules"], max_retries=3
            )

            rules_list = bundle_data.get("rules", [])
            state["detection_rules"] = self._finalize_rules(
                rules_list,
                rule_format="sigma",
                reference=state["url"],
                author=author,
            )
            print(f"Generated {len(state['detection_rules'])} Sigma rules")

        except Exception as e:
            print(f"Sigma rule generation failed: {str(e)}")
            state["error"] = f"Failed to generate Sigma rules: {str(e)}"
            state["detection_rules"] = []

        return state

    def _analyze_coverage(self, state: AgentState) -> AgentState:
        """Identify MITRE techniques lacking a corresponding detection rule."""
        techniques = getattr(state.get("threat_intel"), "techniques", []) or []
        gaps = analyze_gaps(techniques, state.get("detection_rules", []))
        state["coverage_gaps"] = gaps
        if gaps:
            print(f"\n[COVERAGE GAPS] {len(gaps)} uncovered technique(s):")
            for g in gaps:
                print(
                    f"  [{g.priority.upper()}]"
                    f" {g.technique_id} ({g.tactic})"
                )
                print(
                    "    Data sources needed: " + ", ".join(g.data_sources[:2])
                )
        else:
            print(
                "[COVERAGE] All techniques have corresponding"
                " detection rules."
            )
        return state

    def _finalize_rules(
        self,
        rule_outputs: List,
        rule_format: Literal["sigma", "spl"],
        reference: str,
        author: Optional[str] = None,
    ) -> List[DetectionRule]:
        """Finalize and deduplicate rules"""
        seen = set()
        finalized: List[DetectionRule] = []

        # Determine author if not provided
        if not author:
            author = determine_author(reference)

        for ro in rule_outputs:
            if isinstance(ro, dict):
                try:
                    ro = RuleOutput(**ro)
                except Exception as e:
                    print(f"Error creating RuleOutput: {e}")
                    # Handle missing fields with better defaults
                    ro = RuleOutput(
                        name=ro.get("name", "Unknown Rule"),
                        description=ro.get(
                            "description",
                            "Detection rule generated"
                            " from threat intelligence",
                        ),
                        rule_content=ro.get("rule_content", ""),
                        mitre_ttps=ro.get("mitre_ttps", []),
                    )

            # Skip empty rules
            if not ro.rule_content or not ro.name:
                continue

            name_key = (ro.name or "").strip().lower()
            content_key = hashlib.sha256(
                (ro.rule_content or "").encode("utf-8")
            ).hexdigest()
            dedup_key = (name_key, content_key)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            mitre = ro.mitre_ttps if getattr(ro, "mitre_ttps", None) else []
            rule = DetectionRule(
                name=ro.name,
                description=ro.description,
                author=author,
                references=[reference],
                mitre_ttps=mitre,
                rule_content=sanitize_rule_content(ro.rule_content),
                format=rule_format,
            )
            finalized.append(rule)

        return finalized
