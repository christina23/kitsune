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
from datetime import date, datetime
from functools import lru_cache
from typing import Dict, List, Optional

import yaml

from .config import GitHubConfig
from .models import DetectionRule

log = logging.getLogger(__name__)

KITSUNE_PR_LABEL = "kitsune-generated"


@lru_cache(maxsize=1)
def get_github_author_name() -> Optional[str]:
    """Return the display name (or login) of the user behind GITHUB_TOKEN.

    Cached for the lifetime of the process. Returns None if no token is
    configured or the API call fails.
    """
    token = GitHubConfig.GITHUB_TOKEN
    if not token:
        return None
    try:
        from github import Auth, Github
        gh = Github(auth=Auth.Token(token))
        user = gh.get_user()
        return (user.name or "").strip() or user.login
    except Exception as e:
        log.warning("get_github_author_name: could not resolve user: %s", e)
        return None


def _safe_branch_component(value: str) -> str:
    """Strip characters that are invalid in git branch names."""
    return re.sub(r"[^a-zA-Z0-9._-]", "-", value)[:40].strip("-")


def _theme_slug(threat_actor: Optional[str], rules: List[DetectionRule]) -> str:
    """Derive a 5-word-max kebab-case theme for the branch name.

    Prefers the threat-actor name; falls back to salient words drawn
    from rule names when no actor is known.
    """
    # Source words: actor name preferred, else distilled from rule names.
    if threat_actor:
        source = threat_actor
    else:
        source = " ".join(r.name for r in rules[:3])

    # Tokenise: letters/digits only, drop noise words, kebab-join.
    tokens = re.findall(r"[A-Za-z0-9]+", source.lower())
    noise = {"the", "a", "an", "and", "or", "of", "for", "to", "in", "on",
             "with", "via", "rule", "rules", "detection", "activity"}
    meaningful = [t for t in tokens if t not in noise and len(t) > 1]
    if not meaningful:
        meaningful = tokens or ["kitsune"]
    theme = "-".join(meaningful[:5])
    # Cap length (branch refs have practical limits).
    return theme[:60].strip("-") or "kitsune"


def _rule_filename(rule: DetectionRule, actor: Optional[str] = None) -> str:
    """Produce a safe path for the rule inside the PR: rules/{actor}/{name}.yml"""
    actor_dir = _safe_branch_component(actor or "kitsune")
    rule_name = _safe_branch_component(rule.name)
    return f"rules/{actor_dir}/{rule_name}.yml"


def _build_pr_body(
    rules: List[DetectionRule],
    coverage_gap_context: Optional[List[Dict]],
    review_summary: Optional[Dict] = None,
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

    if review_summary:
        lines += [
            "",
            "## Review summary\n",
            f"- **Decision:** {review_summary.get('decision', 'approved')}",
            f"- **Reviewed at:** {review_summary.get('reviewed_at', datetime.now().isoformat())}",
        ]
        if review_summary.get("feedback"):
            lines.append(f"- **Feedback:** {review_summary['feedback']}")
        validation = review_summary.get("validation_summary")
        if validation:
            lines.append(
                f"- **Validation:** {validation.get('passed', 0)} passed, "
                f"{validation.get('needs_review', 0)} needs review, "
                f"{validation.get('failed', 0)} failed"
            )

    lines += [
        "",
        "---",
        "_Generated automatically by [Kitsune](https://github.com/christina23/kitsune)_",
    ]
    return "\n".join(lines)


class GitHubPRClient:
    """Thin wrapper around PyGithub for the sigma-rule PR workflow."""

    def __init__(self, token: str, repo_slug: str, base_branch: str = "main") -> None:
        try:
            from github import Auth, Github
        except ImportError:
            raise ImportError(
                "PyGithub is required for GitHub PR integration. "
                "Install it with: pip install PyGithub"
            )
        self._gh = Github(auth=Auth.Token(token))
        self._repo = self._gh.get_repo(repo_slug)
        self._base_branch = base_branch

    def propose_rules(
        self,
        rules: List[DetectionRule],
        threat_actor: Optional[str] = None,
        coverage_gap_context: Optional[List[Dict]] = None,
        review_approved: bool = False,
        review_summary: Optional[Dict] = None,
    ) -> str:
        """Create a branch, commit rule .yml files, open a draft PR.

        Returns the PR URL.

        Args:
            review_approved: Must be True to proceed. Raises ValueError
                if False, enforcing that rules have been reviewed.
        """
        if not review_approved:
            raise ValueError(
                "Cannot propose rules without review approval. "
                "Set review_approved=True after the review step."
            )

        from github import InputGitTreeElement

        # Branch naming: feature/added-{N}-rules-for-{theme}-{shorthash}
        # The short hash keeps branches unique across same-day re-runs.
        theme = _theme_slug(threat_actor, rules)
        content_hash = hashlib.sha256(
            "".join(r.name for r in rules).encode()
        ).hexdigest()[:6]
        branch_name = (
            f"feature/added-{len(rules)}-rules-for-{theme}-{content_hash}"
        )

        # Get base branch commit
        base_ref = self._repo.get_branch(self._base_branch)
        base_commit = self._repo.get_commit(base_ref.commit.sha)
        base_tree = base_commit.commit.tree

        # Create the branch at base
        self._repo.create_git_ref(
            f"refs/heads/{branch_name}", base_commit.sha
        )

        # Build one tree containing every rule file, then one commit.
        tree_elements = [
            InputGitTreeElement(
                path=_rule_filename(rule, threat_actor),
                mode="100644",
                type="blob",
                content=rule.rule_content,
            )
            for rule in rules
        ]
        new_tree = self._repo.create_git_tree(tree_elements, base_tree)

        actor_label = threat_actor or "unknown actor"
        commit_title = (
            f"Add {len(rules)} detection rule"
            f"{'s' if len(rules) != 1 else ''} for {actor_label}"
        )
        commit_body = "\n".join(f"- {r.name}" for r in rules)
        new_commit = self._repo.create_git_commit(
            message=f"{commit_title}\n\n{commit_body}",
            tree=new_tree,
            parents=[base_commit.commit],
        )
        # Move the branch ref to the new commit
        self._repo.get_git_ref(f"heads/{branch_name}").edit(new_commit.sha)

        # Open as draft PR
        pr = self._repo.create_pull(
            title=(
                f"Detection rules for {actor_label} "
                f"({date.today().isoformat()})"
            ),
            body=_build_pr_body(rules, coverage_gap_context, review_summary),
            head=branch_name,
            base=self._base_branch,
            draft=True,
        )
        self._ensure_label_applied(pr, KITSUNE_PR_LABEL)
        log.info("Draft PR created: %s", pr.html_url)
        return pr.html_url

    def _ensure_label_applied(self, pr, label_name: str) -> None:
        """Apply `label_name` to `pr`, creating the repo label if missing."""
        try:
            pr.add_to_labels(label_name)
            return
        except Exception as e:
            log.info(
                "Label %r not present, creating: %s", label_name, e
            )
        try:
            self._repo.create_label(
                name=label_name,
                color="8957e5",  # Kitsune purple
                description="PR opened automatically by kitsune",
            )
            pr.add_to_labels(label_name)
        except Exception as e:
            log.warning(
                "Could not apply label %r to PR #%s: %s",
                label_name, pr.number, e,
            )

    def get_merged_pr_rules(
        self, since_timestamp: Optional[float] = None
    ) -> List[DetectionRule]:
        """Return DetectionRule objects from merged kitsune-authored PRs.

        Identifies kitsune PRs by the `kitsune-generated` label, with a
        legacy fallback on the historical "kitsune:"/"[Kitsune]:" title
        prefixes for PRs merged before labels were used.
        """
        rules: List[DetectionRule] = []
        pulls = self._repo.get_pulls(state="closed", base=self._base_branch)

        for pr in pulls:
            has_label = any(
                lbl.name == KITSUNE_PR_LABEL for lbl in pr.labels
            )
            legacy_prefix = pr.title.startswith(
                ("[Kitsune]:", "kitsune:")
            )
            if not (has_label or legacy_prefix):
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
