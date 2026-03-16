"""
Main entry point for the Threat Detection Agent
"""

import os
import traceback
from typing import List
from pathlib import Path
from dotenv import load_dotenv

from agent import ThreatDetectionAgent
from utils import parse_providers_from_env, safe_filename
from config import Settings


def process_provider(provider: str, url: str, rule_formats: List[str]) -> None:
    """
    Process a single provider to generate detection rules

    Args:
        provider: LLM provider name
        url: URL to extract threat intelligence from
        rule_formats: List of rule formats to generate (spl, sigma)
    """
    print(f"\n{'='*60}")
    print(f"Generating rules with provider: {provider.upper()}")
    print(f"{'='*60}")

    try:
        agent = ThreatDetectionAgent(llm_provider=provider)

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
    # Load environment variables
    load_dotenv()

    # Get configuration from environment
    url = os.getenv(
        "INTEL_URL",
        "https://cloud.google.com/blog/topics/threat-intelligence/"
        "data-theft-salesforce-instances-via-salesloft-drift",
    )

    # RULE_FORMAT: "spl" | "sigma" | "both"
    rule_format_env = (os.getenv("RULE_FORMAT", "spl")).lower()

    # Determine which formats to generate
    if rule_format_env == "both":
        rule_formats = ["spl", "sigma"]
    else:
        rule_formats = [rule_format_env]

    # Get list of providers to use
    providers = parse_providers_from_env()

    # Display configuration
    print(f"{'='*60}")
    print("THREAT DETECTION AGENT")
    print(f"{'='*60}")
    print(f"Using providers: {', '.join(providers)}")
    print(f"Processing URL: {url}")
    print(f"Rule formats: {', '.join(rule_formats)}")

    # Process each provider
    for provider in providers:
        process_provider(provider, url, rule_formats)

    # Summary
    print(f"\n{'='*60}")
    print("RULE GENERATION COMPLETE!")
    print(f"{'='*60}")
    print(f"Output directory: {Settings.OUTPUT_DIR}/")
    print("Check each provider subdirectory for generated rules.")


if __name__ == "__main__":
    main()
