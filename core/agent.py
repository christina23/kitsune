"""
Core Threat Detection Agent implementation
"""

import os
import time
import hashlib
from typing import TYPE_CHECKING, Dict, List, Optional, Literal

if TYPE_CHECKING:
    from .intel_store import ThreatIntelStore
from pathlib import Path

import yaml as _yaml
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_community.document_loaders import WebBaseLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain.output_parsers import OutputFixingParser
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from .models import (
    ThreatIntelligence,
    DetectionRule,
    AgentState,
    RuleOutput,
    RulesBundle,
    CoverageGap,
    RuleValidationResult,
)
from .config import Settings
from .llm_factory import LLMFactory
from .utils import (
    extract_json_from_text,
    fix_json_formatting,
    sanitize_rule_content,
    determine_author,
    safe_filename,
)
from .prompts import (
    THREAT_INTEL_EXTRACTION_PROMPT,
    SPL_GENERATION_PROMPT,
    SIGMA_GENERATION_PROMPT,
    JSON_FORMAT_INSTRUCTIONS_ANTHROPIC,
)
from .ioc_parser import validate_and_enrich_iocs, validate_ttps
from .coverage import analyze_gaps, _tlsh_distance, _tlsh_hash, TLSH_THRESHOLD
from .sigma_repo import get_baseline_repo


def _compute_ioc_hash(iocs) -> str:
    """Canonical SHA-256 of all IOC values, sorted and normalized."""
    all_values = sorted(
        v.lower().strip()
        for vs in iocs.to_dict().values()
        for v in vs
        if v.strip()
    )
    return hashlib.sha256("|".join(all_values).encode()).hexdigest()[:32]


def _filter_baseline_duplicates(
    generated: List[DetectionRule],
    combined_store_rules: List[Dict],
) -> List[DetectionRule]:
    """Return only generated rules that are not near-duplicates of baseline/store rules.

    Uses TLSH fuzzy hashing with the same threshold as Phase 1 coverage analysis.
    Rules with no computable TLSH hash (too short) pass through unconditionally.
    """
    baseline_hashes = [
        h for sr in combined_store_rules
        if (h := sr.get("tlsh_hash") or _tlsh_hash(sr.get("rule_content", "")))
    ]

    novel: List[DetectionRule] = []
    for rule in generated:
        rule_hash = _tlsh_hash(rule.rule_content)
        if not rule_hash or not baseline_hashes:
            novel.append(rule)
            continue
        is_dup = any(
            (d := _tlsh_distance(rule_hash, bh)) is not None and d < TLSH_THRESHOLD
            for bh in baseline_hashes
        )
        if is_dup:
            print(f"[dedup] Skipping '{rule.name}' — duplicate of baseline rule")
        else:
            novel.append(rule)
    return novel


# ── Rule format config ─────────────────────────────────────────────────────

_RULE_GENERATOR_CONFIG = {
    "sigma": {
        "prompt_template": SIGMA_GENERATION_PROMPT,
        "system_message": (
            "You are a threat detection expert"
            " specializing in Sigma rule development"
            " for enterprise security operations."
        ),
    },
    "spl": {
        "prompt_template": SPL_GENERATION_PROMPT,
        "system_message": (
            "You are a principal detection engineer"
            " with deep expertise in threat hunting"
            " and Splunk SPL. Create sophisticated,"
            " context-aware detection rules."
        ),
    },
}


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
        store: Optional["ThreatIntelStore"] = None,
        **llm_kwargs,
    ):
        self.store = store
        self._last_state: Optional[AgentState] = None
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
                raw = getattr(response, "content", None) or str(response)
                # Claude with extended thinking returns content as a list of
                # blocks: [{"type": "thinking", ...}, {"type": "text", ...}]
                # Extract only the text blocks.
                if isinstance(raw, list):
                    response_text = "\n".join(
                        b.get("text", "") if isinstance(b, dict) else str(b)
                        for b in raw
                        if not (isinstance(b, dict) and b.get("type") == "thinking")
                    )
                else:
                    response_text = raw
                if not response_text.strip():
                    raise ValueError("Empty response from LLM")

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
        if state.get("threat_intel") is None:
            return "end"
        return state.get("rule_format", "spl")

    def _create_workflow(self) -> StateGraph:
        """Create the LangGraph workflow.

        Order: fetch → extract → analyze_coverage (Phase 1) →
               generate_rules → validate_rules → await_review → END
        """
        workflow = StateGraph(AgentState)
        workflow.add_node("fetch_content", self._fetch_content)
        workflow.add_node("extract_threat_intel", self._extract_threat_intel)
        workflow.add_node("analyze_coverage", self._analyze_coverage)
        workflow.add_node("generate_sigma_rules", self._generate_sigma_rules)
        workflow.add_node("generate_spl_rules", self._generate_spl_rules)
        workflow.add_node("validate_rules", self._validate_rules)
        workflow.add_node("await_review", self._await_review)
        workflow.set_entry_point("fetch_content")
        workflow.add_edge("fetch_content", "extract_threat_intel")
        workflow.add_edge("extract_threat_intel", "analyze_coverage")
        workflow.add_conditional_edges(
            "analyze_coverage",
            self._route_to_rule_generator,
            {
                "sigma": "generate_sigma_rules",
                "spl": "generate_spl_rules",
                "end": END,
            },
        )
        workflow.add_edge("generate_sigma_rules", "validate_rules")
        workflow.add_edge("generate_spl_rules", "validate_rules")
        workflow.add_edge("validate_rules", "await_review")
        workflow.add_edge("await_review", END)
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
            state.setdefault("errors", []).append(f"fetch: {e}")
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

            # Validate, normalize, and regex-enrich IOCs
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

            if self.store:
                try:
                    self.store.ingest_threat_intel(
                        threat_intel, source_url=state["url"]
                    )
                except Exception as store_err:
                    print(
                        f"[store] Ingest failed (non-fatal): {store_err}"
                    )

        except Exception as e:
            print(f"Threat intel extraction failed: {str(e)}")
            state["error"] = f"Failed to extract threat intelligence: {str(e)}"
            state.setdefault("errors", []).append(f"extract: {e}")
            state["threat_intel"] = None

        return state

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
            "errors": [],
            "_store_rules_cache": [],
            "validated_rules": [],
            "review_status": None,
            "review_feedback": None,
        }
        import uuid as _uuid
        config = {
            "configurable": {
                "thread_id": f"threat-detection-{_uuid.uuid4().hex[:12]}"
            }
        }

        try:
            result = self.app.invoke(initial_state, config)
            self._last_state = result
            if result.get("error"):
                print(f"Error: {result['error']}")
            return result.get("detection_rules", [])
        except Exception as e:
            print(f"Workflow execution failed: {str(e)}")
            return []

    def resume_after_review(
        self,
        thread_id: str,
        decision: Literal["approved", "rejected"],
        feedback: Optional[str] = None,
        rule_edits: Optional[Dict[str, str]] = None,
    ) -> Optional[AgentState]:
        """Resume the pipeline after a review decision.

        If approved, ingests rules to store. If rule_edits provided,
        updates rule content before proceeding.
        Returns the updated state, or None on error.
        """
        if not self._last_state:
            return None

        state = self._last_state
        state["review_status"] = decision
        state["review_feedback"] = feedback

        if decision == "approved":
            # Apply rule edits if provided
            if rule_edits:
                for rule in state.get("detection_rules", []):
                    if rule.name in rule_edits:
                        rule.rule_content = rule_edits[rule.name]

            # Ingest approved rules to store
            if self.store and state.get("detection_rules"):
                actor = (
                    (state["threat_intel"].threat_actor or "")
                    if state.get("threat_intel")
                    else ""
                )
                ioc_hash = ""
                intel = state.get("threat_intel")
                if intel and intel.iocs and not intel.iocs.is_empty():
                    ioc_hash = _compute_ioc_hash(intel.iocs)

                novel = _filter_baseline_duplicates(
                    state["detection_rules"],
                    state.get("_store_rules_cache", []),
                )
                if novel:
                    try:
                        self.store.ingest_rules(
                            novel,
                            source_url=state["url"],
                            threat_actor=actor,
                            ioc_hash=ioc_hash,
                        )
                    except Exception as store_err:
                        print(f"[store] Rule ingest failed: {store_err}")

        self._last_state = state
        return state

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

    # ── Consolidated rule generation ─────────────────────────────────────────

    def _generate_rules(
        self,
        state: AgentState,
        rule_format: Literal["sigma", "spl"],
    ) -> AgentState:
        """Generate detection rules in the specified format.

        Shared logic for both sigma and spl generation — IOC dedup check,
        LLM call, finalization, Phase 2 coverage update, and store ingest.
        """
        if not state.get("threat_intel"):
            state["detection_rules"] = []
            state["error"] = (
                "No threat intelligence available for rule generation"
            )
            return state

        intel = state["threat_intel"]
        author = determine_author(state["url"], intel.threat_actor)
        config = _RULE_GENERATOR_CONFIG[rule_format]

        # IOC dedup check: skip generation if rules for this IOC set already exist
        ioc_hash = (
            _compute_ioc_hash(intel.iocs)
            if intel.iocs and not intel.iocs.is_empty()
            else ""
        )
        if ioc_hash and self.store and self.store.rules_exist_for_ioc_hash(ioc_hash):
            existing = self.store.get_rules_by_ioc_hash(ioc_hash)
            import json as _json
            matching = [
                r for r in existing
                if r.get("format", rule_format) == rule_format and r.get("rule_content")
            ]
            if matching:
                print(
                    f"[store] Rules exist for IOC set ({ioc_hash[:8]}…),"
                    f" skipping {rule_format.upper()} generation"
                )
                state["detection_rules"] = [
                    DetectionRule(
                        name=r["name"],
                        description="(retrieved from store)",
                        author="",
                        references=[],
                        mitre_ttps=_json.loads(r.get("ttps", "[]")),
                        rule_content=r.get("rule_content", ""),
                        format=rule_format,
                    )
                    for r in matching
                ]
                self._phase2_coverage_update(state)
                return state

        prompt_content = config["prompt_template"].format(
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
                SystemMessage(content=config["system_message"]),
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
                rule_format=rule_format,
                reference=state["url"],
                author=author,
            )
            print(f"Generated {len(state['detection_rules'])} {rule_format.upper()} rules")

            # Phase 2: update coverage gaps with the new rules
            self._phase2_coverage_update(state)

        except Exception as e:
            print(f"{rule_format.upper()} rule generation failed: {str(e)}")
            state["error"] = f"Failed to generate {rule_format.upper()} rules: {str(e)}"
            state.setdefault("errors", []).append(f"generate_{rule_format}: {e}")
            state["detection_rules"] = []

        return state

    def _generate_spl_rules(self, state: AgentState) -> AgentState:
        """Generate Splunk SPL detection rules"""
        return self._generate_rules(state, "spl")

    def _generate_sigma_rules(self, state: AgentState) -> AgentState:
        """Generate Sigma detection rules"""
        return self._generate_rules(state, "sigma")

    # ── Validation node ──────────────────────────────────────────────────────

    def _validate_rules(self, state: AgentState) -> AgentState:
        """Validate generated rules before review.

        Performs:
        - YAML parse check for sigma rules (title, logsource, detection)
        - TTP consistency: rule TTPs should match extracted threat intel
        - Content safety check against forbidden terms
        - Detection quality checks (behavioral depth, cardinality, false positives)
        """
        rules = state.get("detection_rules", [])
        intel = state.get("threat_intel")
        intel_ttps = set()
        if intel and intel.techniques:
            intel_ttps = {t.id.upper() for t in intel.techniques}

        validated: List[dict] = []

        for rule in rules:
            issues: List[str] = []

            # YAML structure check (sigma rules only)
            parsed_sigma = None
            if rule.format == "sigma":
                try:
                    parsed_sigma = _yaml.safe_load(rule.rule_content)
                    if not isinstance(parsed_sigma, dict):
                        issues.append("Rule content is not valid YAML dict")
                        parsed_sigma = None
                    else:
                        for required_key in ("title", "logsource", "detection"):
                            if required_key not in parsed_sigma:
                                issues.append(f"Missing required sigma key: {required_key}")
                except _yaml.YAMLError as exc:
                    issues.append(f"YAML parse error: {exc}")

            # TTP consistency: rule's claimed TTPs should overlap with intel
            if intel_ttps and rule.mitre_ttps:
                rule_ttps = {t.upper() for t in rule.mitre_ttps}
                if not rule_ttps & intel_ttps:
                    issues.append(
                        f"Rule TTPs {rule.mitre_ttps} do not overlap with "
                        f"extracted intel TTPs"
                    )

            # Content safety check
            content_lower = rule.rule_content.lower()
            for term in Settings.FORBIDDEN_TERMS:
                if term.lower() in content_lower:
                    issues.append(f"Contains forbidden term: '{term}'")

            # ── Detection quality checks ────────────────────────────────
            self._check_detection_quality(rule, parsed_sigma, issues)

            # Determine verdict
            if any("YAML parse error" in i or "not valid YAML" in i for i in issues):
                verdict = "fail"
            elif issues:
                verdict = "needs_review"
            else:
                verdict = "pass"

            validated.append(
                RuleValidationResult(
                    rule=rule, verdict=verdict, issues=issues,
                ).model_dump()
            )

        state["validated_rules"] = validated

        # Summary
        pass_count = sum(1 for v in validated if v["verdict"] == "pass")
        review_count = sum(1 for v in validated if v["verdict"] == "needs_review")
        fail_count = sum(1 for v in validated if v["verdict"] == "fail")
        print(
            f"[VALIDATE] {len(validated)} rules: "
            f"{pass_count} passed, {review_count} needs review, {fail_count} failed"
        )

        return state

    @staticmethod
    def _check_detection_quality(
        rule: DetectionRule,
        parsed_sigma: Optional[dict],
        issues: List[str],
    ) -> None:
        """Signal detection theory quality checks.

        Flags potential problems but does not block — detection engineers
        make the final call during review.
        """
        content = rule.rule_content
        content_lower = content.lower()

        # 1. Atomic-only detection: flag rules that match only on static
        #    IOC values (IPs, hashes, domains) without behavioral context
        _ioc_patterns = ("src_ip=", "dest_ip=", "ip=", "hash=", "md5=",
                         "sha256=", "domain=", "SourceIp:", "DestinationIp:")
        _behavioral_keywords = ("stats ", "count", "| rare", "| outlier",
                                "timeframe:", "| bucket", "| streamstats",
                                "group-by", "near", "temporal", "| where",
                                "condition:", "aggregate")
        has_ioc_match = any(p.lower() in content_lower for p in _ioc_patterns)
        has_behavioral = any(k.lower() in content_lower for k in _behavioral_keywords)
        if has_ioc_match and not has_behavioral:
            issues.append(
                "Quality: rule matches only on atomic IOCs without behavioral "
                "context — consider adding aggregation or temporal logic"
            )

        # 2. Missing false-positive exclusion (sigma rules)
        if parsed_sigma and isinstance(parsed_sigma, dict):
            if "falsepositives" not in parsed_sigma:
                issues.append(
                    "Quality: missing 'falsepositives' section — add expected "
                    "benign triggers to help analysts triage"
                )
            # Check for filter selections in detection block
            detection = parsed_sigma.get("detection", {})
            if isinstance(detection, dict):
                has_filter = any(
                    k.startswith("filter") for k in detection.keys()
                )
                if not has_filter:
                    issues.append(
                        "Quality: no filter_* selection in detection block — "
                        "consider adding exclusions for known benign patterns"
                    )

        # 3. SPL rules: check for entity scoping (stats ... by <entity>)
        if rule.format == "spl":
            if "stats " in content_lower and " by " not in content_lower:
                issues.append(
                    "Quality: stats command without 'by' clause — add entity "
                    "scoping (user, host, src_ip) for actionable alerts"
                )
            # Check for time windowing
            time_keywords = ("span=", "earliest=", "latest=", "bucket _time",
                             "streamstats window=")
            if not any(k in content_lower for k in time_keywords):
                issues.append(
                    "Quality: no temporal windowing — consider adding span= "
                    "or bucket to detect bursts within a time window"
                )

    # ── Review node ──────────────────────────────────────────────────────────

    def _await_review(self, state: AgentState) -> AgentState:
        """Set review_status to pending_review. Pipeline pauses here.

        The API or CLI will resume after an engineer reviews the rules.
        """
        if state.get("detection_rules"):
            state["review_status"] = "pending_review"
        else:
            # Nothing to review — skip
            state["review_status"] = None
        return state

    # ── Coverage analysis ────────────────────────────────────────────────────

    def _analyze_coverage(self, state: AgentState) -> AgentState:
        """Phase 1 coverage: compare extracted techniques vs store rules with TLSH."""
        techniques = getattr(state.get("threat_intel"), "techniques", []) or []

        # Query store for existing rules covering each technique
        store_rules: List[Dict] = []
        if self.store:
            seen_keys: set = set()
            for tech in techniques:
                for r in self.store.query_rules(ttp=tech.id, limit=20):
                    key = r.get("rule_id", r.get("name", ""))
                    if key not in seen_keys:
                        seen_keys.add(key)
                        store_rules.append(r)

        # Prepend baseline corpus so Phase 1 checks it even when Redis is empty
        baseline_dicts = get_baseline_repo().rules_as_store_dicts()
        if baseline_dicts:
            print(f"[COVERAGE Phase 1] +{len(baseline_dicts)} baseline corpus rules")
            store_rules = baseline_dicts + store_rules

        # Cache so Phase 2 can reuse without re-querying (includes baseline)
        state["_store_rules_cache"] = store_rules

        # Phase 1: TLSH-enabled, no generated rules yet
        gaps = analyze_gaps(
            techniques,
            generated_rules=[],
            store_rules=store_rules,
            use_tlsh=True,
        )
        state["coverage_gaps"] = gaps

        if gaps:
            print(f"\n[COVERAGE Phase 1] {len(gaps)} gap(s) vs store (TLSH enabled):")
            for g in gaps:
                fuzzy = " ~fuzzy" if g.fuzzy_match else ""
                print(f"  [{g.priority.upper()}] {g.technique_id} ({g.tactic}){fuzzy}")
        else:
            print("[COVERAGE Phase 1] All techniques have existing store coverage.")

        return state

    def _phase2_coverage_update(self, state: AgentState) -> None:
        """Phase 2: update coverage gaps after rule generation (exact TTP match, no TLSH)."""
        techniques = getattr(state.get("threat_intel"), "techniques", []) or []
        generated = state.get("detection_rules", [])
        store_rules = state.get("_store_rules_cache", [])

        pre_count = len(state.get("coverage_gaps", []))
        updated_gaps = analyze_gaps(
            techniques,
            generated,
            store_rules=store_rules,
            use_tlsh=False,
        )
        state["coverage_gaps"] = updated_gaps
        filled = max(0, pre_count - len(updated_gaps))
        print(
            f"[COVERAGE Phase 2] {len(updated_gaps)} gap(s) remaining"
            f" ({filled} filled by new rules)"
        )

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
