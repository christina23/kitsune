"""
GitHub PR integration for proposing accepted sigma rules upstream.

Requires: PyGithub>=2.1.0  (pip install PyGithub)
Config:   GITHUB_TOKEN, GITHUB_REPO (owner/repo), GITHUB_BRANCH (default: main)

All functionality degrades gracefully when GITHUB_TOKEN is not set —
get_github_client() returns None and callers should return HTTP 503.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import date
from typing import Dict, List, Optional

from .config import GitHubConfig
from .models import DetectionRule

log = logging.getLogger(__name__)


def _safe_branch_component(value: str) -> str:
    """Strip characters that are invalid in git branch names."""
    return re.sub(r"[^a-zA-Z0-9._-]", "-", value)[:40].strip("-")


def _rule_filename(rule: DetectionRule, actor: Optional[str] = None) -> str:
    """Produce a safe path for the rule inside the PR: rules/{actor}/{name}.yml"""
    actor_dir = _safe_branch_component(actor or "kitsune")
    rule_name = _safe_branch_component(rule.name)
    return f"rules/{actor_dir}/{rule_name}.yml"


def _build_pr_body(
    rules: List[DetectionRule],
    coverage_gap_context: Optional[List[Dict]],
) -> str:
    lines = [
        "## Proposed sigma rules\n",
        "| Rule | TTPs | Format |",
        "|------|------|--------|",
    ]
    for r in rules:
        ttps = ", ".join(r.mitre_ttps) or "—"
        lines.append(f"| {r.name} | {ttps} | {r.format} |")

    if coverage_gap_context:
        lines += [
            "",
            "## Coverage gap context\n",
            "| Technique | Priority | Reason |",
            "|-----------|----------|--------|",
        ]
        for gap in coverage_gap_context:
            lines.append(
                f"| {gap.get('technique_id','')} "
                f"| {gap.get('priority','')} "
                f"| {gap.get('reason','')} |"
            )

    lines += [
        "",
        "---",
        "_Proposed automatically by [kitsune](https://github.com/christina23/kitsune)_",
    ]
    return "\n".join(lines)


class GitHubPRClient:
    """Thin wrapper around PyGithub for the sigma-rule PR workflow."""

    def __init__(self, token: str, repo_slug: str, base_branch: str = "main") -> None:
        try:
            from github import Github
        except ImportError:
            raise ImportError(
                "PyGithub is required for GitHub PR integration. "
                "Install it with: pip install PyGithub"
            )
        self._gh = Github(token)
        self._repo = self._gh.get_repo(repo_slug)
        self._base_branch = base_branch

    def propose_rules(
        self,
        rules: List[DetectionRule],
        threat_actor: Optional[str] = None,
        coverage_gap_context: Optional[List[Dict]] = None,
    ) -> str:
        """Create a branch, commit rule .yml files, open a PR. Returns the PR URL."""
        today = date.today().strftime("%Y%m%d")
        actor_slug = _safe_branch_component(threat_actor or "unknown")
        content_hash = hashlib.sha256(
            "".join(r.name for r in rules).encode()
        ).hexdigest()[:8]
        branch_name = f"kitsune/rules/{actor_slug}-{today}-{content_hash}"

        # Get base branch SHA
        base_ref = self._repo.get_branch(self._base_branch)
        base_sha = base_ref.commit.sha

        # Create the branch
        self._repo.create_git_ref(f"refs/heads/{branch_name}", base_sha)

        # Commit each rule file
        for rule in rules:
            path = _rule_filename(rule, threat_actor)
            self._repo.create_file(
                path=path,
                message=f"kitsune: add {rule.name}",
                content=rule.rule_content,
                branch=branch_name,
            )

        # Open the PR
        actor_label = threat_actor or "unknown actor"
        pr = self._repo.create_pull(
            title=f"kitsune: new sigma rules from {actor_label} ({date.today().isoformat()})",
            body=_build_pr_body(rules, coverage_gap_context),
            head=branch_name,
            base=self._base_branch,
        )
        log.info("PR created: %s", pr.html_url)
        return pr.html_url

    def get_merged_pr_rules(
        self, since_timestamp: Optional[float] = None
    ) -> List[DetectionRule]:
        """Return DetectionRule objects extracted from merged kitsune: PRs.

        Fetches all closed PRs with title prefix "kitsune:" and extracts
        any .yml files from the merge commit.
        """
        import yaml
        import time

        rules: List[DetectionRule] = []
        pulls = self._repo.get_pulls(state="closed", base=self._base_branch)

        for pr in pulls:
            if not pr.title.startswith("kitsune:"):
                continue
            if not pr.merged:
                continue
            if since_timestamp and pr.merged_at.timestamp() < since_timestamp:
                continue

            for f in pr.get_files():
                if not f.filename.endswith(".yml"):
                    continue
                try:
                    contents = self._repo.get_contents(f.filename, ref=pr.merge_commit_sha)
                    raw = contents.decoded_content.decode()
                    data = yaml.safe_load(raw)
                    if not data or not isinstance(data, dict) or not data.get("title"):
                        continue
                    ttps = [
                        tag.replace("attack.", "").upper()
                        for tag in data.get("tags", [])
                        if tag.lower().startswith("attack.t")
                    ]
                    rules.append(DetectionRule(
                        name=data["title"],
                        description=data.get("description", ""),
                        author=data.get("author", "kitsune"),
                        references=data.get("references", [pr.html_url]),
                        mitre_ttps=ttps,
                        rule_content=raw,
                        format="sigma",
                    ))
                except Exception as exc:
                    log.warning("Could not extract rule from %s: %s", f.filename, exc)

        return rules


def get_github_client() -> Optional[GitHubPRClient]:
    """Return a configured GitHubPRClient, or None if integration is not set up."""
    if not GitHubConfig.is_enabled():
        log.warning(
            "GitHub integration disabled: set GITHUB_TOKEN and GITHUB_REPO to enable."
        )
        return None
    try:
        return GitHubPRClient(
            token=GitHubConfig.GITHUB_TOKEN,
            repo_slug=GitHubConfig.GITHUB_REPO,
            base_branch=GitHubConfig.GITHUB_BRANCH,
        )
    except ImportError as exc:
        log.warning("GitHub integration unavailable: %s", exc)
        return None
