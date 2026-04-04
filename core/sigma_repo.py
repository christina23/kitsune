"""
Baseline sigma rule corpus loader.

Loads .yml sigma rules from a local directory and/or a GitHub repository
into an in-memory cache. The cache is prepended to store_rules during
Phase 1 coverage analysis so that every analyze job checks new LLM-generated
rules against the full known-good baseline — even when Redis is empty.

Private repos are supported via SIGMA_REPO_TOKEN (PAT or deploy key).

Usage (called once at API startup):
    from core.sigma_repo import initialize_baseline_repo
    initialize_baseline_repo(local_path="/path/to/rules")

Usage in the pipeline:
    from core.sigma_repo import get_baseline_repo
    baseline_dicts = get_baseline_repo().rules_as_store_dicts()
"""

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional
from urllib.parse import urlparse

import yaml

from .coverage import _tlsh_hash
from .models import DetectionRule

if TYPE_CHECKING:
    from .intel_store import ThreatIntelStore

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_ttps(sigma: dict) -> List[str]:
    """Extract MITRE ATT&CK technique IDs from a sigma rule's tags field."""
    return [
        tag.replace("attack.", "").upper()
        for tag in sigma.get("tags", [])
        if tag.lower().startswith("attack.t")
    ]


def _sigma_to_rule(sigma: dict, raw: str) -> Optional[DetectionRule]:
    """Convert a parsed sigma YAML dict + raw text to a DetectionRule.

    Returns None if the dict is missing a title (malformed rule).
    """
    if not sigma.get("title"):
        return None
    return DetectionRule(
        name=sigma["title"],
        description=sigma.get("description", ""),
        author=sigma.get("author", ""),
        references=sigma.get("references", []),
        mitre_ttps=_extract_ttps(sigma),
        rule_content=raw,
        format="sigma",
    )


def _load_yml_dir(directory: Path) -> List[DetectionRule]:
    """Recursively load all .yml sigma rules under a directory."""
    rules: List[DetectionRule] = []
    for yml in sorted(directory.rglob("*.yml")):
        try:
            raw = yml.read_text()
            data = yaml.safe_load(raw)
            if data and isinstance(data, dict):
                rule = _sigma_to_rule(data, raw)
                if rule:
                    rules.append(rule)
        except Exception as exc:
            log.warning("Skipping %s: %s", yml, exc)
    return rules


def _load_yml_files(file_paths: List[Path]) -> List[DetectionRule]:
    """Load specific .yml files and return parsed DetectionRules."""
    rules: List[DetectionRule] = []
    for yml in file_paths:
        try:
            if not yml.exists() or not yml.suffix == ".yml":
                continue
            raw = yml.read_text()
            data = yaml.safe_load(raw)
            if data and isinstance(data, dict):
                rule = _sigma_to_rule(data, raw)
                if rule:
                    rules.append(rule)
        except Exception as exc:
            log.warning("Skipping %s: %s", yml, exc)
    return rules


def _auth_url(repo_url: str, token: Optional[str]) -> str:
    """Insert PAT token into a GitHub HTTPS URL for authentication."""
    if not token:
        return repo_url
    parsed = urlparse(repo_url)
    if parsed.scheme != "https":
        return repo_url
    authed = parsed._replace(netloc=f"{token}@{parsed.hostname}")
    return authed.geturl()


def _clone_or_pull(
    repo_url: str,
    cache_dir: Path,
    branch: str = "main",
    token: Optional[str] = None,
) -> tuple[Path, Optional[str], Optional[str]]:
    """Clone repo_url into cache_dir, or git-pull if it already exists.

    Returns (repo_path, old_head_sha, new_head_sha).
    old_head_sha is None on fresh clones.

    Requires gitpython (pip install gitpython).
    """
    try:
        import git
    except ImportError:
        raise ImportError(
            "gitpython is required to use SIGMA_REPO_URL. "
            "Install it with: pip install gitpython"
        )

    authed_url = _auth_url(repo_url, token)

    if cache_dir.exists():
        repo = git.Repo(cache_dir)
        old_head = repo.head.commit.hexsha
        # Update remote URL in case token changed
        repo.remotes.origin.set_url(authed_url)
        repo.remotes.origin.pull(branch)
        new_head = repo.head.commit.hexsha
        return cache_dir, old_head, new_head
    else:
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        repo = git.Repo.clone_from(authed_url, cache_dir, branch=branch)
        new_head = repo.head.commit.hexsha
        return cache_dir, None, new_head


def _get_changed_yml_files(
    cache_dir: Path, old_sha: str, new_sha: str,
) -> List[Path]:
    """Return paths of .yml files changed between two commits."""
    import git

    repo = git.Repo(cache_dir)
    diff = repo.commit(old_sha).diff(repo.commit(new_sha))
    changed: List[Path] = []
    for d in diff:
        path = d.b_path or d.a_path
        if path and path.endswith(".yml"):
            full = cache_dir / path
            changed.append(full)
    return changed


# ---------------------------------------------------------------------------
# BaselineSigmaRepo
# ---------------------------------------------------------------------------

class BaselineSigmaRepo:
    """In-memory cache of baseline sigma rules.

    Rules are loaded once at startup (or on explicit reload) from a local
    directory and/or a cloned GitHub repo. Supports incremental sync
    and Redis-backed caching for fast cold starts.
    """

    def __init__(self) -> None:
        self._rules: List[DetectionRule] = []
        self._store_dicts: List[Dict] = []
        self._loaded_at: Optional[float] = None
        self._local_path: Optional[str] = None
        self._repo_url: Optional[str] = None
        self._branch: str = "main"
        self._token: Optional[str] = None
        self._last_head_sha: Optional[str] = None

    def load(
        self,
        local_path: Optional[str] = None,
        repo_url: Optional[str] = None,
        branch: str = "main",
        token: Optional[str] = None,
        store: Optional["ThreatIntelStore"] = None,
    ) -> None:
        """Load rules from local_path and/or clone/pull repo_url.

        If a store is provided, attempts Redis-backed cache hydration
        when the sync SHA matches (skip full file parse).
        Replaces the in-memory cache atomically on completion.
        """
        self._local_path = local_path
        self._repo_url = repo_url
        self._branch = branch
        self._token = token
        rules: List[DetectionRule] = []

        if repo_url:
            cache = Path.home() / ".cache" / "kitsune" / "sigma_repo"

            # Check if Redis has a warm cache we can use
            if store and cache.exists():
                cached_sha = store.get_baseline_sync_sha()
                try:
                    import git
                    repo = git.Repo(cache)
                    current_sha = repo.head.commit.hexsha
                    if cached_sha and cached_sha == current_sha:
                        log.info("Baseline cache hit — SHA %s matches Redis", cached_sha[:8])
                        # Still do the pull to check for updates
                        cloned, old_head, new_head = _clone_or_pull(
                            repo_url, cache, branch, token,
                        )
                        if old_head == new_head:
                            # No changes — use cached rules from filesystem (fast)
                            rules += _load_yml_dir(cloned)
                            self._last_head_sha = new_head
                        else:
                            # Changed — incremental load
                            changed_files = _get_changed_yml_files(cloned, old_head, new_head)
                            if changed_files:
                                rules += _load_yml_dir(cloned)
                            else:
                                rules += _load_yml_dir(cloned)
                            self._last_head_sha = new_head
                    else:
                        cloned, old_head, new_head = _clone_or_pull(
                            repo_url, cache, branch, token,
                        )
                        rules += _load_yml_dir(cloned)
                        self._last_head_sha = new_head
                except Exception:
                    cloned, old_head, new_head = _clone_or_pull(
                        repo_url, cache, branch, token,
                    )
                    rules += _load_yml_dir(cloned)
                    self._last_head_sha = new_head
            else:
                cloned, old_head, new_head = _clone_or_pull(
                    repo_url, cache, branch, token,
                )
                rules += _load_yml_dir(cloned)
                self._last_head_sha = new_head

        if local_path:
            rules += _load_yml_dir(Path(local_path))

        self._rules = rules
        self._store_dicts = [self._to_store_dict(r) for r in rules]
        self._loaded_at = time.time()
        log.info(
            "Baseline loaded: %d rules, %d unique TTPs",
            len(rules),
            len(self.ttps_covered),
        )
        print(
            f"[baseline] Loaded {len(rules)} rules "
            f"({len(self.ttps_covered)} unique TTPs)"
        )

        # Sync to Redis if store is available
        if store and self._last_head_sha:
            self.sync_to_redis(store)

    def reload(self) -> int:
        """Re-run load() with the previously configured paths.

        Returns the number of rules loaded.
        """
        self.load(
            self._local_path,
            self._repo_url,
            self._branch,
            self._token,
        )
        return len(self._rules)

    def sync_to_redis(self, store: "ThreatIntelStore") -> int:
        """Sync all baseline rules to Redis for persistent caching.

        Returns the number of rules synced.
        """
        synced = 0
        source = self._local_path or self._repo_url or ""
        for rule in self._rules:
            try:
                store.ingest_baseline_rule(rule, source=source)
                synced += 1
            except Exception as exc:
                log.warning("Failed to sync baseline rule '%s': %s", rule.name, exc)

        if self._last_head_sha:
            store.set_baseline_sync_sha(self._last_head_sha)

        log.info("Synced %d baseline rules to Redis", synced)
        return synced

    def _to_store_dict(self, rule: DetectionRule) -> Dict:
        """Convert a DetectionRule to the dict format used by query_rules()."""
        uid = hashlib.sha256(
            (rule.name + rule.rule_content).encode()
        ).hexdigest()[:16]
        return {
            "rule_id": f"baseline:{uid}",
            "name": rule.name,
            "format": "sigma",
            "ttps": json.dumps(rule.mitre_ttps),
            "rule_content": rule.rule_content,
            "tlsh_hash": _tlsh_hash(rule.rule_content),
            "threat_actor": "",
            "source_url": self._local_path or self._repo_url or "",
            "created_at": "0",
        }

    def rules_as_store_dicts(self) -> List[Dict]:
        """Return a stable copy of baseline rules in store-dict format.

        Returns a new list on each call so the pipeline sees a consistent
        snapshot even if reload() is called concurrently.
        """
        return list(self._store_dicts)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def loaded_at(self) -> Optional[float]:
        return self._loaded_at

    @property
    def ttps_covered(self) -> List[str]:
        ttps: set = set()
        for r in self._rules:
            ttps.update(r.mitre_ttps)
        return sorted(ttps)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_repo: Optional[BaselineSigmaRepo] = None


def get_baseline_repo() -> BaselineSigmaRepo:
    """Return the module-level singleton, creating an empty one if needed."""
    global _repo
    if _repo is None:
        _repo = BaselineSigmaRepo()
    return _repo


def initialize_baseline_repo(
    local_path: Optional[str] = None,
    repo_url: Optional[str] = None,
    branch: str = "main",
    token: Optional[str] = None,
    store: Optional["ThreatIntelStore"] = None,
) -> BaselineSigmaRepo:
    """Create (or replace) the singleton and load rules.

    Called once at API startup. Safe to call again for a hot reload.
    """
    global _repo
    _repo = BaselineSigmaRepo()
    if local_path or repo_url:
        _repo.load(local_path, repo_url, branch, token, store)
    return _repo
