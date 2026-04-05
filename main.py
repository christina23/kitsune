"""
Main entry point for the Threat Detection Agent
"""

import argparse
import json
import os
import pprint
import sys
import traceback
from typing import List, Optional
from pathlib import Path
from dotenv import load_dotenv

from core.agent import ThreatDetectionAgent
from core.config import RedisConfig, Settings
from core.intel_store import ThreatIntelStore, create_store
from core.enrichment import enrich_rule, get_coverage_trends
from core.models import DetectionRule
from core.utils import parse_providers_from_env, safe_filename


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kitsune Threat Detection Agent"
    )
    parser.add_argument(
        "--mode",
        choices=["run", "query", "trends", "actor-summary", "enrich-rule", "flush"],
        default="run",
        help="Operation mode (default: run)",
    )
    parser.add_argument(
        "--actor",
        default=None,
        help="Threat actor name for query / actor-summary modes",
    )
    parser.add_argument(
        "--ttp",
        default=None,
        help="MITRE TTP ID for query mode (e.g. T1059)",
    )
    parser.add_argument(
        "--ioc-type",
        default=None,
        dest="ioc_type",
        help="IOC type filter for query mode: ip, domain, hash, file, url",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top trending TTPs to show (default: 10)",
    )
    parser.add_argument(
        "--rule-name",
        default=None,
        dest="rule_name",
        help="Rule name for enrich-rule mode",
    )
    return parser.parse_args()


def _require_store(store: Optional[ThreatIntelStore], mode: str) -> None:
    if store is None:
        print(
            f"[error] Mode '{mode}' requires Redis."
            " Set REDIS_URL and ensure Redis is reachable."
        )
        sys.exit(1)


def run_query_mode(
    args: argparse.Namespace, store: Optional[ThreatIntelStore]
) -> None:
    """Handle non-pipeline query modes."""
    if args.mode == "flush":
        _require_store(store, "flush")
        deleted = store.flush()
        print(f"[flush] Deleted {deleted} key(s) from the store.")
        return

    if args.mode == "trends":
        _require_store(store, "trends")
        print(get_coverage_trends(store, top_n=args.top))

    elif args.mode == "query":
        _require_store(store, "query")
        if not args.actor and not args.ttp:
            print("[error] --mode query requires --actor and/or --ttp")
            sys.exit(1)
        iocs = store.query_iocs(
            actor=args.actor, ttp=args.ttp, ioc_type=args.ioc_type
        )
        rules = store.query_rules(actor=args.actor, ttp=args.ttp)
        print(f"IOCs ({len(iocs)}):")
        for ioc in iocs:
            print(f"  [{ioc.get('type')}] {ioc.get('value')}")
        print(f"\nRules ({len(rules)}):")
        for r in rules:
            print(f"  {r.get('name')}  [{r.get('format')}]")

    elif args.mode == "actor-summary":
        _require_store(store, "actor-summary")
        if not args.actor:
            print("[error] --mode actor-summary requires --actor")
            sys.exit(1)
        summary = store.get_actor_summary(args.actor)
        print(f"Actor: {summary['actor']}")
        print(f"Total IOCs: {summary['total_iocs']}")
        print(f"Total rules: {summary['total_rules']}")
        print(f"IOC breakdown: {summary['ioc_counts']}")
        print(f"TTPs: {', '.join(summary['ttps']) or 'none'}")
        print(f"Campaigns: {', '.join(summary['campaigns']) or 'none'}")

    elif args.mode == "enrich-rule":
        _require_store(store, "enrich-rule")
        if not args.rule_name:
            print("[error] --mode enrich-rule requires --rule-name")
            sys.exit(1)
        rules = store.query_rules()
        match = next(
            (
                r
                for r in rules
                if r.get("name", "").lower() == args.rule_name.lower()
            ),
            None,
        )
        if not match:
            print(f"[error] Rule '{args.rule_name}' not found in store.")
            sys.exit(1)
        rule = DetectionRule(
            name=match["name"],
            description="",
            author="",
            references=[match.get("source_url", "")],
            mitre_ttps=json.loads(match.get("ttps", "[]")),
            rule_content="",
            format=match["format"],
        )
        enriched = enrich_rule(rule, store)
        pprint.pprint(enriched)


def process_provider(
    provider: str,
    url: str,
    rule_formats: List[str],
    store: Optional[ThreatIntelStore] = None,
) -> None:
    """
    Process a single provider to generate detection rules

    Args:
        provider: LLM provider name
        url: URL to extract threat intelligence from
        rule_formats: List of rule formats to generate (spl, sigma)
        store: Optional persistent intel store
    """
    print(f"\n{'='*60}")
    print(f"Generating rules with provider: {provider.upper()}")
    print(f"{'='*60}")

    try:
        agent = ThreatDetectionAgent(llm_provider=provider, store=store)

        for fmt in rule_formats:
            print(f"\n[{provider.upper()}] Generating {fmt.upper()} rules...")
            rules = agent.generate_detections(url, rule_format=fmt)

            if not rules:
                print(
                    f"[{provider.upper()}] No rules generated"
                    f" for {fmt.upper()}"
                )
                continue

            # Save rules to files
            outdir = Path(Settings.OUTPUT_DIR) / provider
            outdir.mkdir(parents=True, exist_ok=True)

            paths = []
            for rule in rules:
                fname = f"{safe_filename(rule.name)}.txt"
                fpath = outdir / fname
                with fpath.open("w", encoding="utf-8") as f:
                    f.write(agent.format_rule_output(rule))
                paths.append(fpath)

            print(
                f"[{provider.upper()}] Wrote {len(paths)}"
                f" {fmt.upper()} rule file(s) to {outdir}:"
            )
            for p in paths:
                print(f"  - {p.name}")

    except Exception as e:
        print(f"[{provider.upper()}] CRITICAL ERROR: {str(e)}")
        if os.getenv("DEBUG", "").lower() == "true":
            traceback.print_exc()


def main():
    """Main entry point"""
    load_dotenv()
    args = parse_args()

    redis_cfg = RedisConfig()
    store = create_store(redis_cfg.url) if redis_cfg.enabled else None

    if args.mode != "run":
        run_query_mode(args, store)
        return

    # ── Pipeline mode ─────────────────────────────────────────────────────────
    url = os.getenv(
        "INTEL_URL",
        "https://cloud.google.com/blog/topics/threat-intelligence/"
        "data-theft-salesforce-instances-via-salesloft-drift",
    )

    rule_format_env = (os.getenv("RULE_FORMAT", "sigma")).lower()
    rule_formats = ["spl", "sigma"] if rule_format_env == "both" else [
        rule_format_env
    ]
    providers = parse_providers_from_env()

    print(f"{'='*60}")
    print("THREAT DETECTION AGENT")
    print(f"{'='*60}")
    print(f"Using providers: {', '.join(providers)}")
    print(f"Processing URL: {url}")
    print(f"Rule formats: {', '.join(rule_formats)}")
    if store:
        print("Persistent store: enabled")
    else:
        print("Persistent store: disabled (set REDIS_URL to enable)")

    for provider in providers:
        process_provider(provider, url, rule_formats, store=store)

    print(f"\n{'='*60}")
    print("RULE GENERATION COMPLETE!")
    print(f"{'='*60}")
    print(f"Output directory: {Settings.OUTPUT_DIR}/")
    print("Check each provider subdirectory for generated rules.")


if __name__ == "__main__":
    main()
