"""
Kitsune REST API — query the Redis threat intel store.

Run with:
    uvicorn api:app --reload --port 8000

Swagger UI:  http://localhost:8000/docs
Redoc:       http://localhost:8000/redoc
"""

import json
import os
import re
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from dotenv import load_dotenv
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

load_dotenv()

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.dirname(__file__))
from core.intel_store import create_store
from core.models import DetectionRule
from core.sigma_repo import (
    MITRE_TACTICS,
    get_baseline_repo,
    initialize_baseline_repo,
)
from core.mitre_tactics import tactics_for as _tactics_for_ttp
from core.config import BaselineRepoConfig, GitHubConfig

_API_DESCRIPTION = """\
Kitsune is a threat-intelligence pipeline that ingests reports, extracts IOCs
and MITRE ATT&CK techniques, generates detection rules (Sigma / SPL), and
stores everything in Redis for search and analysis.

### Quickstart

| Action | Endpoint |
|--------|----------|
| Run the pipeline on a report URL | `POST /analyze` |
| Poll pipeline progress | `GET /tasks/{task_id}` |
| Natural-language search | `POST /ask` |
| Browse IOCs | `GET /iocs` |
| Browse detection rules | `GET /rules` |
| Coverage matrix | `GET /coverage` |
"""

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize shared store once (singleton connection pool)
    app.state.store = create_store()
    initialize_baseline_repo(
        local_path=BaselineRepoConfig.SIGMA_REPO_PATH,
        repo_url=BaselineRepoConfig.SIGMA_REPO_URL,
        branch=BaselineRepoConfig.SIGMA_REPO_BRANCH,
        token=BaselineRepoConfig.SIGMA_REPO_TOKEN,
        store=app.state.store,
    )
    yield


app = FastAPI(
    title="Kitsune",
    description=_API_DESCRIPTION,
    version="0.2.0",
    contact={"name": "Kitsune", "url": "https://github.com/christina23/kitsune"},
    docs_url=None,   # disabled; custom Swagger served at /docs
    redoc_url=None,  # disabled; Scalar served at /scalar
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Health", "description": "Service health and connectivity checks."},
        {"name": "Pipeline", "description": "Submit threat report URLs for analysis and poll task status."},
        {"name": "Search", "description": "Natural-language search powered by AI."},
        {"name": "Actors", "description": "Browse and inspect tracked threat actors."},
        {"name": "IOCs", "description": "Query indicators of compromise — IPs, domains, hashes, URLs, files."},
        {"name": "Detection Rules", "description": "Search and update Sigma / SPL detection rules."},
        {"name": "Analytics", "description": "Trending TTPs and per-technique coverage reports."},
        {"name": "Baseline", "description": "Manage the baseline sigma rule corpus and propose rules upstream via GitHub PRs."},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["*"],
)


# ── Custom Swagger UI with dark-mode toggle ───────────────────────────────────

_DARK_CSS = """
body.dark { background: #0d1117; }
body.dark .swagger-ui { background: #0d1117; color: #e6edf3; }
body.dark .swagger-ui .topbar { background: #161b22; border-bottom: 1px solid #30363d; }
body.dark .swagger-ui .topbar a { color: #79c0ff; }

/* Info / title block */
body.dark .swagger-ui .info { background: transparent; }
body.dark .swagger-ui .info .title { color: #e6edf3; }
body.dark .swagger-ui .info p,
body.dark .swagger-ui .info li { color: #a8c8e8; }
body.dark .swagger-ui .info a { color: #79c0ff; }
body.dark .swagger-ui .info .base-url { color: #adbac7; }

/* Servers / scheme bar */
body.dark .swagger-ui .scheme-container { background: #161b22; box-shadow: none; border-bottom: 1px solid #30363d; }

/* Section tag headers (Actors, IOCs, etc.) */
body.dark .swagger-ui .opblock-tag { color: #a8c8e8; border-bottom: 1px solid #30363d; }
body.dark .swagger-ui .opblock-tag small { color: #a8c8e8; }
body.dark .swagger-ui .opblock-tag:hover { background: #1c2128; }

/* Operation blocks */
body.dark .swagger-ui .opblock { border-color: #30363d; background: #161b22; }
body.dark .swagger-ui .opblock .opblock-summary { border-color: #30363d; }
body.dark .swagger-ui .opblock .opblock-summary-path,
body.dark .swagger-ui .opblock .opblock-summary-path__deprecated { color: #e6edf3; }
body.dark .swagger-ui .opblock .opblock-summary-description { color: #a8c8e8; }

/* GET */
body.dark .swagger-ui .opblock.opblock-get { background: #111d2e; border-color: #2d5a9e; }
body.dark .swagger-ui .opblock.opblock-get .opblock-summary { border-color: #2d5a9e; }
body.dark .swagger-ui .opblock.opblock-get .opblock-summary-method { background: #1f6feb; }
/* POST */
body.dark .swagger-ui .opblock.opblock-post { background: #0f2218; border-color: #2ea043; }
body.dark .swagger-ui .opblock.opblock-post .opblock-summary-method { background: #238636; }
/* DELETE */
body.dark .swagger-ui .opblock.opblock-delete { background: #200d0e; border-color: #8e2a2a; }
body.dark .swagger-ui .opblock.opblock-delete .opblock-summary-method { background: #da3633; }

/* Expanded body */
body.dark .swagger-ui .opblock-body { background: #0d1117; }
body.dark .swagger-ui .opblock-description-wrapper p,
body.dark .swagger-ui .opblock-external-docs-wrapper p,
body.dark .swagger-ui .opblock-title_normal p { color: #a8c8e8; }

/* Tables */
body.dark .swagger-ui table thead tr th,
body.dark .swagger-ui table thead tr td { color: #adbac7; border-bottom: 1px solid #30363d; }
body.dark .swagger-ui table tbody tr td { color: #cdd9e5; border-bottom: 1px solid #21262d; }

/* Parameters */
body.dark .swagger-ui .parameter__name { color: #e6edf3; }
body.dark .swagger-ui .parameter__type { color: #79c0ff; }
body.dark .swagger-ui .parameter__deprecated { color: #f85149; }
body.dark .swagger-ui .parameter__in { color: #adbac7; font-style: italic; }

/* Form inputs */
body.dark .swagger-ui input[type=text],
body.dark .swagger-ui input[type=password],
body.dark .swagger-ui input[type=email],
body.dark .swagger-ui textarea,
body.dark .swagger-ui select {
    background: #1c2128; color: #e6edf3;
    border: 1px solid #30363d; border-radius: 4px;
}

/* Buttons */
body.dark .swagger-ui .btn { color: #cdd9e5; border-color: #30363d; background: #21262d; }
body.dark .swagger-ui .btn:hover { background: #30363d; color: #e6edf3; }
body.dark .swagger-ui .btn.execute { background: #1f6feb; border-color: #1f6feb; color: #fff; }
body.dark .swagger-ui .btn.execute:hover { background: #388bfd; }
body.dark .swagger-ui .btn.cancel { background: #da3633; border-color: #da3633; color: #fff; }

/* Responses */
body.dark .swagger-ui .responses-inner h4,
body.dark .swagger-ui .responses-inner h5 { color: #e6edf3; }
body.dark .swagger-ui .response-col_status { color: #e6edf3; }
body.dark .swagger-ui .response-col_description { color: #cdd9e5; }
body.dark .swagger-ui .response-col_description p { color: #cdd9e5; }

/* Code / syntax */
body.dark .swagger-ui .highlight-code { background: #161b22 !important; }
body.dark .swagger-ui .microlight { background: #161b22 !important; color: #e6edf3 !important; }

/* Models */
body.dark .swagger-ui section.models { border: 1px solid #30363d; }
body.dark .swagger-ui section.models h4 { color: #e6edf3; }
body.dark .swagger-ui .model-box { background: #161b22; }
body.dark .swagger-ui .model { color: #cdd9e5; }
body.dark .swagger-ui .model-title { color: #79c0ff; }
body.dark .swagger-ui .prop-type { color: #79c0ff; }
body.dark .swagger-ui .prop-format { color: #adbac7; }
body.dark .swagger-ui span.token { color: #79c0ff !important; }

/* Markdown */
body.dark .swagger-ui .markdown p,
body.dark .swagger-ui .markdown li { color: #cdd9e5; }
body.dark .swagger-ui .markdown code { background: #1c2128; color: #e6edf3; border-radius: 3px; padding: 0 4px; }

/* Auth / dialogs */
body.dark .swagger-ui .auth-wrapper { background: #161b22; }
body.dark .swagger-ui .dialog-ux .modal-ux { background: #161b22; border: 1px solid #30363d; }
body.dark .swagger-ui .dialog-ux .modal-ux-header { border-bottom: 1px solid #30363d; }
body.dark .swagger-ui .dialog-ux .modal-ux-header h3 { color: #e6edf3; }
"""

_TOGGLE_JS = """
(function () {
  const KEY = 'kitsune-docs-theme';
  const btn = document.createElement('button');
  btn.id = 'theme-toggle';
  btn.title = 'Toggle dark / light mode';
  btn.style.cssText = [
    'position:fixed', 'top:12px', 'right:18px', 'z-index:9999',
    'background:transparent', 'border:1px solid #30363d', 'border-radius:20px',
    'padding:4px 10px', 'font-size:17px', 'cursor:pointer',
    'line-height:1.4', 'transition:background .15s',
  ].join(';');

  function applyTheme(dark) {
    document.body.classList.toggle('dark', dark);
    btn.textContent = dark ? '☀️' : '🌙';
    btn.style.background = dark ? '#21262d' : '#f0f0f0';
    localStorage.setItem(KEY, dark ? 'dark' : 'light');
  }

  btn.addEventListener('click', function () {
    applyTheme(!document.body.classList.contains('dark'));
  });

  // Apply saved preference immediately, default to dark
  const saved = localStorage.getItem(KEY);
  applyTheme(saved !== 'light');

  // Wait for SwaggerUI to mount before appending the button
  function mount() {
    const topbar = document.querySelector('.topbar') || document.body;
    topbar.appendChild(btn);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount);
  } else {
    mount();
  }
})();
"""


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui() -> HTMLResponse:
    base: HTMLResponse = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " — API Docs",
        swagger_ui_parameters={"defaultModelsExpandDepth": -1},
    )
    html = base.body.decode()

    # Inject fox favicon into <head>
    fox_favicon = (
        "<link rel='icon' href=\"data:image/svg+xml,"
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
        "<text y='.9em' font-size='90'>🦊</text></svg>\">"
    )
    html = html.replace("</head>", fox_favicon + "</head>")

    # Inject dark-mode CSS and toggle JS just before </body>
    injection = f"<style>{_DARK_CSS}</style><script>{_TOGGLE_JS}</script>"
    html = html.replace("</body>", injection + "</body>")
    return HTMLResponse(html)


_SCALAR_CUSTOM_CSS = """
/* ── Base ─────────────────────────────────── */
body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }

.dark-mode,
.scalar-app {
  --scalar-background-1: #0d1117;
  --scalar-background-2: #161b22;
  --scalar-background-3: #1c2128;
  --scalar-background-accent: #1a3a5c;

  --scalar-color-1: #e6edf3;
  --scalar-color-2: #adbac7;
  --scalar-color-3: #8b949e;
  --scalar-color-accent: #e05c4b;

  --scalar-border-color: #21262d;

  --scalar-color-green: #3fb950;
  --scalar-color-blue: #79c0ff;
  --scalar-color-orange: #ffa657;
  --scalar-color-red: #ff7b7b;
  --scalar-color-purple: #d2a8ff;

  --scalar-button-1: #e05c4b;
  --scalar-button-1-hover: #c94d3d;
  --scalar-button-1-color: #ffffff;

  --scalar-sidebar-background-1: #0d1117;
  --scalar-sidebar-color-1: #e6edf3;
  --scalar-sidebar-color-2: #8b949e;
  --scalar-sidebar-color-active: #e05c4b;
  --scalar-sidebar-border-color: #21262d;
  --scalar-sidebar-search-background: #161b22;
  --scalar-sidebar-search-border-color: #30363d;
  --scalar-sidebar-search-color: #e6edf3;
}

/* ── Code blocks ──────────────────────────── */
pre, code {
  font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
  font-size: 0.82rem;
}

/* ── Smooth scrolling ─────────────────────── */
html { scroll-behavior: smooth; }
"""


@app.get("/scalar", include_in_schema=False)
async def scalar_ui() -> HTMLResponse:
    fox_favicon = (
        "data:image/svg+xml,"
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
        "<text y='.9em' font-size='90'>🦊</text></svg>"
    )

    scalar_config = {
        "theme": "none",
        "layout": "modern",
        "darkMode": True,
        "defaultHttpClient": {"targetKey": "python", "clientKey": "requests"},
        "hiddenClients": {
            "ruby": True,
            "php": True,
        },
        "hideModels": False,
        "defaultOpenAllTags": True,
        "metaData": {"title": "Kitsune API Reference"},
        "customCss": _SCALAR_CUSTOM_CSS,
    }

    config_json = json.dumps(scalar_config)

    html = f"""<!doctype html>
<html>
  <head>
    <title>{app.title} — API Reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="icon" href="{fox_favicon}">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  </head>
  <body>
    <script id="api-reference"></script>
    <script>
      var defined = document.getElementById('api-reference');
      defined.dataset.url = '{app.openapi_url}';
      defined.dataset.configuration = JSON.stringify({config_json});
    </script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>"""
    return HTMLResponse(html)


# ── Pydantic response models ──────────────────────────────────────────────────


class IOCRecord(BaseModel):
    type: str
    value: str
    first_seen: Optional[str] = None  # ISO 8601 UTC
    last_seen: Optional[str] = None  # ISO 8601 UTC
    threat_actors: List[str] = []
    campaigns: List[str] = []
    ttps: List[str] = []
    source_urls: List[str] = []


class RuleRecord(BaseModel):
    rule_id: Optional[str] = None
    name: str
    format: str
    rule_content: Optional[str] = None
    ttps: List[str] = []
    threat_actor: Optional[str] = None
    source_url: Optional[str] = None
    created_at: Optional[str] = None  # ISO 8601 UTC


def _epoch_to_iso(v) -> Optional[str]:
    """Convert a Unix epoch (str/float) to ISO 8601 UTC (e.g. 2026-04-04T17:14:29Z)."""
    if v is None or v == "":
        return None
    try:
        ts = float(v)
    except (TypeError, ValueError):
        # Already a string timestamp — pass through
        return str(v)
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _decode_list(v) -> List[str]:
    """Decode a JSON-encoded list string from Redis; return [] on any failure."""
    if not v:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    try:
        out = json.loads(v)
        if isinstance(out, list):
            return [str(x) for x in out]
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return []


def _normalize_ioc_record(rec: Dict) -> Dict:
    return {
        "type": rec.get("type", ""),
        "value": rec.get("value", ""),
        "first_seen": _epoch_to_iso(rec.get("first_seen")),
        "last_seen": _epoch_to_iso(rec.get("last_seen")),
        "threat_actors": _decode_list(rec.get("threat_actors")),
        "campaigns": _decode_list(rec.get("campaigns")),
        "ttps": _decode_list(rec.get("ttps")),
        "source_urls": _decode_list(rec.get("source_urls")),
    }


def _normalize_rule_record(rec: Dict) -> Dict:
    return {
        "rule_id": rec.get("rule_id"),
        "name": rec.get("name", ""),
        "format": rec.get("format", ""),
        "rule_content": rec.get("rule_content"),
        "ttps": _decode_list(rec.get("ttps")),
        "threat_actor": rec.get("threat_actor"),
        "source_url": rec.get("source_url"),
        "created_at": _epoch_to_iso(rec.get("created_at")),
    }


class TrendingTTP(BaseModel):
    ttp_id: str
    count: int


class CoverageEntry(BaseModel):
    ttp_id: str
    has_iocs: bool
    has_rules: bool
    ioc_count: int
    rule_count: int


class ActorSummary(BaseModel):
    actor: str
    total_iocs: int
    total_rules: int
    ioc_counts: Dict[str, int]
    ttps: List[str]
    campaigns: List[str]


class HealthResponse(BaseModel):
    status: str
    redis: str


# ── Pipeline models ───────────────────────────────────────────────────────────


class AnalyzeRequest(BaseModel):
    url: str
    rule_format: Literal["sigma", "spl"] = "spl"
    llm_provider: str = "anthropic"
    improvement_guidance: Optional[str] = None


class IOCSummary(BaseModel):
    ips: List[str] = []
    domains: List[str] = []
    hashes: List[str] = []
    files: List[str] = []
    urls: List[str] = []


class CoverageGapResponse(BaseModel):
    technique_id: str
    tactic: str
    priority: str
    reason: str
    data_sources: List[str]
    fuzzy_match: bool = False
    fuzzy_score: Optional[float] = None


class FullRuleRecord(BaseModel):
    rule_id: Optional[str] = None
    name: str
    format: str
    rule_content: Optional[str] = None
    ttps: Optional[str] = None
    threat_actor: Optional[str] = None
    source_url: Optional[str] = None
    created_at: Optional[str] = None


class AnalyzeResponse(BaseModel):
    threat_actor: Optional[str] = None
    campaign_name: Optional[str] = None
    iocs: IOCSummary = IOCSummary()
    rules: List[FullRuleRecord] = []
    coverage_gaps: List[CoverageGapResponse] = []
    error: Optional[str] = None


class RuleUpdateRequest(BaseModel):
    rule_content: str


class AnalyzeStartResponse(BaseModel):
    task_id: str
    status: str = "running"


class TaskStatusResponse(BaseModel):
    task_id: str
    status: Literal["running", "done", "error", "pending_review"]
    step: Optional[str] = None
    result: Optional[AnalyzeResponse] = None
    error: Optional[str] = None
    review_status: Optional[str] = None


# ── In-memory task store ──────────────────────────────────────────────────────
# Maps task_id → {"status", "step", "result", "error"}
# Tasks are held for the lifetime of the server process.

_tasks: Dict[str, Dict[str, Any]] = {}
_tasks_lock = threading.Lock()


def _set_task(task_id: str, **kwargs: Any) -> None:
    with _tasks_lock:
        _tasks[task_id].update(kwargs)


def _run_pipeline_task(task_id: str, req: "AnalyzeRequest", store=None) -> None:
    """Background thread: run the full pipeline and write results to _tasks."""
    try:
        _set_task(task_id, step="Loading store…")
        if store is None:
            store = create_store()

        _set_task(task_id, step="Initializing agent…")
        from core.agent import ThreatDetectionAgent

        agent = ThreatDetectionAgent(llm_provider=req.llm_provider, store=store)

        _set_task(task_id, step="Pipeline running…")
        rules = agent.generate_detections(
            req.url,
            req.rule_format,
            improvement_guidance=req.improvement_guidance,
            step_callback=lambda label: _set_task(task_id, step=label),
        )

        state = agent._last_state or {}
        intel = state.get("threat_intel")
        gaps = state.get("coverage_gaps", [])
        review_status = state.get("review_status")

        iocs = IOCSummary(**(intel.iocs.to_dict() if intel and intel.iocs else {}))
        rule_records = [
            FullRuleRecord(
                name=r.name,
                format=r.format,
                rule_content=r.rule_content,
                ttps=json.dumps(r.mitre_ttps),
                source_url=req.url,
            )
            for r in rules
        ]
        gap_records = [
            CoverageGapResponse(
                technique_id=g.technique_id,
                tactic=g.tactic,
                priority=g.priority,
                reason=g.reason,
                data_sources=g.data_sources,
                fuzzy_match=g.fuzzy_match,
                fuzzy_score=g.fuzzy_score,
            )
            for g in gaps
        ]
        result = AnalyzeResponse(
            threat_actor=intel.threat_actor if intel else None,
            campaign_name=intel.campaign_name if intel else None,
            iocs=iocs,
            rules=rule_records,
            coverage_gaps=gap_records,
        )

        # Determine task status based on review
        if review_status == "pending_review":
            _set_task(
                task_id,
                status="pending_review",
                step="Awaiting review",
                result=result.model_dump(),
                review_status="pending_review",
                agent=agent,
                validated_rules=state.get("validated_rules", []),
            )
        else:
            _set_task(task_id, status="done", step="Complete", result=result.model_dump())

    except Exception as exc:
        _set_task(task_id, status="error", step="Failed", error=str(exc))


# ── Dependency ────────────────────────────────────────────────────────────────


def get_store():
    # Prefer the shared store initialized in lifespan
    store = getattr(app.state, "store", None) or create_store()
    if store is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Redis store unavailable. "
                "Set REDIS_URL in your environment (e.g. redis://localhost:6379)."
            ),
        )
    return store


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/", response_model=HealthResponse, tags=["Health"])
def health_check():
    """Returns API status and Redis connectivity."""
    store = create_store()
    redis_status = "connected" if store is not None else "unavailable"
    return {"status": "ok", "redis": redis_status}


@app.get("/stats", tags=["Analytics"])
def store_stats():
    """Aggregate counts for the store — distinct IOCs, actors, and rules.

    `rules_sigma` is the number of rules that live in the kitsune-sigma
    repo (baseline rules loaded from SIGMA_REPO_URL plus rules synced
    back from merged PRs). `rules_ai_generated` is the subset that
    carries the `kitsune.generated` tag — i.e., authored by kitsune.
    """
    store = get_store()
    all_rules = store.query_rules(limit=100000)

    rules_sigma = 0
    rules_ai = 0
    for r in all_rules:
        rid = r.get("rule_id") or ""
        src_url = r.get("source_url") or ""
        in_kitsune_sigma = (
            ":baseline:" in rid or src_url.startswith("github:")
        )
        if not in_kitsune_sigma:
            continue
        rules_sigma += 1
        if "kitsune.generated" in (r.get("rule_content") or ""):
            rules_ai += 1

    return {
        "iocs": store.count_iocs(),
        "actors": len(store._r.smembers(store._actors_key())),
        "rules_sigma": rules_sigma,
        "rules_ai_generated": rules_ai,
    }


@app.get("/actors", response_model=List[str], tags=["Actors"])
def list_actors():
    """
    Return all threat actors that have been ingested into the store.
    """
    store = get_store()
    actors = store._r.smembers(store._actors_key())
    return sorted(actors)


@app.get("/actors/{actor_name}/summary", response_model=ActorSummary, tags=["Actors"])
def actor_summary(actor_name: str):
    """
    Return a summary for a specific threat actor:
    IOC type breakdown, associated TTPs, and campaigns.

    **Example:** `/actors/apt28/summary`
    """
    store = get_store()
    result = store.get_actor_summary(actor_name)
    if result["total_iocs"] == 0 and result["total_rules"] == 0:
        raise HTTPException(status_code=404, detail=f"Actor '{actor_name}' not found.")
    return result


@app.get("/iocs", response_model=List[IOCRecord], tags=["IOCs"])
def query_iocs(
    actor: Optional[str] = Query(None, description="Filter by threat actor name"),
    ttp: Optional[str] = Query(None, description="Filter by MITRE ATT&CK technique ID (e.g. T1059)"),
    ioc_type: Optional[str] = Query(
        None,
        description="Filter by IOC type",
        enum=["ip", "domain", "hash", "file", "url"],
    ),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results to return"),
):
    """
    Query IOCs from the threat intel store.

    Filters can be combined — e.g. actor + ttp returns the intersection.

    **Example:** `/iocs?actor=apt28&ttp=T1059&limit=25`
    """
    store = get_store()
    results = store.query_iocs(actor=actor, ttp=ttp, ioc_type=ioc_type, limit=limit)
    return [_normalize_ioc_record(r) for r in results]


@app.get("/rules", response_model=List[RuleRecord], tags=["Detection Rules"])
def query_rules(
    actor: Optional[str] = Query(None, description="Filter by threat actor name"),
    ttp: Optional[str] = Query(None, description="Filter by MITRE ATT&CK technique ID"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results to return"),
):
    """
    Query detection rules (Sigma / SPL) from the store.

    **Example:** `/rules?ttp=T1059&limit=10`
    """
    store = get_store()
    results = store.query_rules(actor=actor, ttp=ttp, limit=limit)
    return [_normalize_rule_record(r) for r in results]


@app.get("/trends", response_model=List[TrendingTTP], tags=["Analytics"])
def trending_ttps(
    top: int = Query(10, ge=1, le=100, description="Number of top TTPs to return"),
):
    """
    Return the top-N MITRE ATT&CK techniques by ingestion frequency.

    **Example:** `/trends?top=20`
    """
    store = get_store()
    return store.get_trending_ttps(n=top)


@app.get("/coverage", response_model=List[CoverageEntry], tags=["Analytics"])
def coverage_summary():
    """
    Per-TTP coverage report: whether each technique has associated IOCs
    and/or detection rules in the store.
    """
    store = get_store()
    raw = store.get_coverage_summary()
    return [{"ttp_id": ttp_id, **data} for ttp_id, data in sorted(raw.items())]


def _build_coverage_matrix() -> Dict[str, Any]:
    """Merge baseline-repo tactic data with store coverage.

    Returns a structure with per-tactic rollups, flat technique list
    with tactics attached, and totals.
    """
    store = get_store()
    store_cov = store.get_coverage_summary()  # {ttp: {has_iocs, has_rules, ioc_count, rule_count}}
    baseline_cov = get_baseline_repo().technique_coverage()  # {ttp: {rule_count, tactics}}

    # Union of all TTPs we know about, with merged fields.
    all_ttps = set(store_cov) | set(baseline_cov)
    techniques: List[Dict[str, Any]] = []
    for ttp in sorted(all_ttps):
        s = store_cov.get(ttp, {})
        b = baseline_cov.get(ttp, {})
        # Prefer tactics from sigma tags; fall back to MITRE lookup.
        tactics = b.get("tactics") or _tactics_for_ttp(ttp)
        techniques.append({
            "ttp_id": ttp,
            "tactics": tactics,
            "rule_count": int(s.get("rule_count", 0) or b.get("rule_count", 0) or 0),
            "ioc_count": int(s.get("ioc_count", 0) or 0),
            "has_rules": bool(s.get("has_rules") or b.get("rule_count", 0)),
            "has_iocs": bool(s.get("has_iocs")),
        })

    # Per-tactic rollups
    by_tactic: Dict[str, Dict[str, Any]] = {
        t: {
            "tactic": t,
            "covered": 0,
            "total_tracked": 0,
            "uncovered_with_iocs": [],
        }
        for t in MITRE_TACTICS
    }
    # "unknown" bucket for techniques without a tactic tag
    by_tactic["unknown"] = {
        "tactic": "unknown",
        "covered": 0,
        "total_tracked": 0,
        "uncovered_with_iocs": [],
    }

    for t in techniques:
        tactics = t["tactics"] or ["unknown"]
        for tac in tactics:
            if tac not in by_tactic:
                continue
            by_tactic[tac]["total_tracked"] += 1
            if t["has_rules"]:
                by_tactic[tac]["covered"] += 1
            if t["has_iocs"] and not t["has_rules"]:
                by_tactic[tac]["uncovered_with_iocs"].append({
                    "ttp_id": t["ttp_id"],
                    "ioc_count": t["ioc_count"],
                })

    totals = {
        "with_rules": sum(1 for t in techniques if t["has_rules"]),
        "iocs_only": sum(
            1 for t in techniques if t["has_iocs"] and not t["has_rules"]
        ),
        "uncovered": sum(
            1 for t in techniques
            if not t["has_rules"] and not t["has_iocs"]
        ),
        "total_tracked": len(techniques),
    }

    return {
        "techniques": techniques,
        "by_tactic": [
            v for v in by_tactic.values() if v["total_tracked"] > 0
        ],
        "totals": totals,
    }


@app.get("/coverage/by-tactic", tags=["Analytics"])
def coverage_by_tactic():
    """Per-MITRE-tactic coverage rollup with uncovered gap TTPs."""
    return _build_coverage_matrix()


@app.get("/coverage/navigator", tags=["Analytics"])
def coverage_navigator_layer():
    """
    Return a MITRE ATT&CK Navigator layer JSON describing current coverage.

    Open in Navigator via:
      https://mitre-attack.github.io/attack-navigator/#layerURL={this-url}
    """
    matrix = _build_coverage_matrix()
    max_rules = max((t["rule_count"] for t in matrix["techniques"]), default=1) or 1

    nav_techniques: List[Dict[str, Any]] = []
    for t in matrix["techniques"]:
        if t["has_rules"]:
            nav_techniques.append({
                "techniqueID": t["ttp_id"],
                "score": t["rule_count"],
                "comment": (
                    f"{t['rule_count']} rule(s)"
                    + (f", {t['ioc_count']} IOCs" if t["ioc_count"] else "")
                ),
                "enabled": True,
            })
        elif t["has_iocs"]:
            # Gap: IOCs observed, no rules. Flagged in a separate color band.
            nav_techniques.append({
                "techniqueID": t["ttp_id"],
                "score": -1,
                "color": "#f8bbd0",  # pastel coral/pink
                "comment": f"GAP: {t['ioc_count']} IOCs, no rules",
                "enabled": True,
            })

    return {
        "name": "Kitsune Coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "sorting": 3,  # 3 = sort descending by technique score
        "description": (
            "Kitsune detection coverage heatmap. Green-shaded techniques "
            "have rules (darker = more rules). Red techniques have IOCs "
            "observed but no detection rule."
        ),
        "techniques": nav_techniques,
        "gradient": {
            # Sage → deep forest, widened for visible contrast across
            # the skewed rule-count distribution.
            "colors": ["#3d7a4f", "#1f5530", "#0f3520", "#07200f"],
            "minValue": 1,
            "maxValue": max_rules,
        },
        "legendItems": [
            {"label": "Has detection rules", "color": "#1b4d2e"},
            {"label": "Gap: IOCs, no rules", "color": "#f8bbd0"},
        ],
    }


def _navigator_view_url(request: Request) -> str:
    """Build a MITRE Navigator URL that auto-loads the layer from our API."""
    base = str(request.base_url).rstrip("/")
    layer_url = f"{base}/coverage/navigator"
    return (
        "https://mitre-attack.github.io/attack-navigator/#layerURL="
        + quote(layer_url, safe="")
    )


@app.post("/analyze", response_model=AnalyzeStartResponse, tags=["Pipeline"])
def analyze_url(req: AnalyzeRequest):
    """
    Start the Kitsune pipeline for a threat report URL and return immediately.

    The pipeline runs in a background thread:
    1. Fetch and parse page content
    2. Extract IOCs and MITRE ATT&CK techniques
    3. **Phase 1 coverage** — compare vs store rules with TLSH fuzzy matching
    4. Generate detection rules targeting the identified gaps
    5. **Phase 2 coverage** — update gaps to reflect newly generated rules

    Returns a `task_id` immediately. Poll `GET /tasks/{task_id}` to get results.

    **Example:** `POST /analyze` with body `{"url": "https://...", "rule_format": "spl"}`
    """
    task_id = uuid.uuid4().hex[:12]
    with _tasks_lock:
        _tasks[task_id] = {
            "status": "running",
            "step": "Queued",
            "result": None,
            "error": None,
            "review_status": None,
        }
    store = getattr(app.state, "store", None)
    thread = threading.Thread(
        target=_run_pipeline_task, args=(task_id, req, store), daemon=True
    )
    thread.start()
    return AnalyzeStartResponse(task_id=task_id)


@app.get("/tasks/{task_id}", response_model=TaskStatusResponse, tags=["Pipeline"])
def get_task_status(task_id: str):
    """
    Poll the status of a running pipeline task.

    - `status: "running"` — pipeline is still executing; check `step` for current stage
    - `status: "done"` — pipeline complete; `result` contains the full `AnalyzeResponse`
    - `status: "error"` — pipeline failed; `error` contains the message

    Poll every 3–5 seconds until status is `"done"` or `"error"`.
    """
    with _tasks_lock:
        task = _tasks.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found.")
    # Filter out internal fields not in the response model
    response_fields = {
        k: v for k, v in task.items()
        if k in TaskStatusResponse.model_fields
    }
    return TaskStatusResponse(task_id=task_id, **response_fields)


# ── Review workflow ──────────────────────────────────────────────────────────


class ReviewRuleRecord(BaseModel):
    name: str
    format: str
    rule_content: str
    mitre_ttps: List[str] = []
    verdict: str = "pass"
    issues: List[str] = []


class ReviewResponse(BaseModel):
    task_id: str
    review_status: str
    rules: List[ReviewRuleRecord] = []


class ReviewDecision(BaseModel):
    decision: Literal["approved", "rejected"]
    feedback: Optional[str] = None
    rule_edits: Optional[Dict[str, str]] = None  # rule_name -> edited content
    included_rule_names: Optional[List[str]] = None  # if set, only these rules are kept


class ReviewDecisionResponse(BaseModel):
    task_id: str
    decision: str
    rules_ingested: int = 0
    pr_url: Optional[str] = None
    pr_error: Optional[str] = None


@app.get("/tasks/{task_id}/review", response_model=ReviewResponse, tags=["Pipeline"])
def get_review(task_id: str):
    """
    Get generated rules with validation verdicts for engineer review.

    Only available when task status is `pending_review`.
    Returns each rule with its validation verdict (pass/fail/needs_review)
    and any issues found.
    """
    with _tasks_lock:
        task = _tasks.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found.")
    if task.get("review_status") != "pending_review":
        raise HTTPException(
            status_code=400,
            detail=f"Task is not awaiting review (status: {task.get('status')}).",
        )

    validated = task.get("validated_rules", [])
    rules = []
    for v in validated:
        rule_data = v.get("rule", {})
        rules.append(ReviewRuleRecord(
            name=rule_data.get("name", ""),
            format=rule_data.get("format", "sigma"),
            rule_content=rule_data.get("rule_content", ""),
            mitre_ttps=rule_data.get("mitre_ttps", []),
            verdict=v.get("verdict", "pass"),
            issues=v.get("issues", []),
        ))

    return ReviewResponse(
        task_id=task_id,
        review_status="pending_review",
        rules=rules,
    )


@app.post("/tasks/{task_id}/review", response_model=ReviewDecisionResponse, tags=["Pipeline"])
def submit_review(task_id: str, req: ReviewDecision):
    """
    Submit a review decision for generated rules.

    - `approved` — rules are ingested to the store and become available for PR proposal
    - `rejected` — rules are discarded

    Optionally include `rule_edits` (mapping of rule name to edited content)
    to modify rules before approval. Include `feedback` for audit trail.
    """
    with _tasks_lock:
        task = _tasks.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found.")
    if task.get("review_status") != "pending_review":
        raise HTTPException(
            status_code=400,
            detail=f"Task is not awaiting review (status: {task.get('status')}).",
        )

    agent = task.get("agent")
    rules_ingested = 0
    approved_rules: List = []
    threat_actor_name: Optional[str] = None

    if agent:
        state = agent.resume_after_review(
            decision=req.decision,
            feedback=req.feedback,
            rule_edits=req.rule_edits,
        )
        if state and req.decision == "approved":
            approved_rules = state.get("detection_rules", [])
            # Filter to only rules the user kept checked in the UI.
            if req.included_rule_names is not None:
                keep = {n for n in req.included_rule_names}
                approved_rules = [r for r in approved_rules if r.name in keep]
            rules_ingested = len(approved_rules)
            intel = state.get("threat_intel")
            if intel:
                threat_actor_name = intel.threat_actor

    # Auto-create draft PR for approved rules
    pr_url: Optional[str] = None
    pr_error: Optional[str] = None
    if req.decision == "approved" and not approved_rules:
        pr_error = "No rules selected — nothing to propose."
    if req.decision == "approved" and approved_rules:
        from core.github_pr import get_github_client

        try:
            gh = get_github_client()
        except Exception as exc:
            gh = None
            pr_error = f"GitHub client init failed: {exc}"

        if gh is None and not pr_error:
            pr_error = (
                "GitHub integration not configured. "
                f"GITHUB_TOKEN set: {bool(GitHubConfig.GITHUB_TOKEN)}, "
                f"GITHUB_REPO set: {bool(GitHubConfig.GITHUB_REPO)}."
            )
        elif gh is not None:
            validated = task.get("validated_rules", [])
            review_summary = {
                "decision": "approved",
                "reviewed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "validation_summary": {
                    "passed": sum(1 for v in validated if v.get("verdict") == "pass"),
                    "needs_review": sum(1 for v in validated if v.get("verdict") == "needs_review"),
                    "failed": sum(1 for v in validated if v.get("verdict") == "fail"),
                },
                "feedback": req.feedback or "",
            }
            try:
                pr_url = gh.propose_rules(
                    approved_rules,
                    threat_actor=threat_actor_name,
                    review_approved=True,
                    review_summary=review_summary,
                )
            except Exception as exc:
                pr_error = f"PR creation failed: {exc}"

    # Update task status
    new_status = "done"
    _set_task(
        task_id,
        status=new_status,
        step=f"Review: {req.decision}",
        review_status=req.decision,
        pr_url=pr_url,
    )

    return ReviewDecisionResponse(
        task_id=task_id,
        decision=req.decision,
        rules_ingested=rules_ingested,
        pr_url=pr_url,
        pr_error=pr_error,
    )


# ── AI Search ────────────────────────────────────────────────────────────────

_ASK_TOOLS = [
    {
        "name": "list_actors",
        "description": "List all known threat actors in the store.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_actor_summary",
        "description": "Get a detailed summary for a specific threat actor including IOC breakdown, TTPs, and campaigns.",
        "input_schema": {
            "type": "object",
            "properties": {"actor_name": {"type": "string", "description": "The threat actor name"}},
            "required": ["actor_name"],
        },
    },
    {
        "name": "get_trending_ttps",
        "description": "Get the top N most frequently seen MITRE ATT&CK techniques (TTPs). Use this for questions about popular, common, or trending TTPs.",
        "input_schema": {
            "type": "object",
            "properties": {"top": {"type": "integer", "description": "Number of top TTPs to return", "default": 10}},
        },
    },
    {
        "name": "search_iocs",
        "description": "Search for IOCs (indicators of compromise: IPs, domains, hashes, URLs, files). Can filter by actor, TTP, or IOC type.",
        "input_schema": {
            "type": "object",
            "properties": {
                "actor": {"type": "string", "description": "Filter by threat actor name"},
                "ttp": {"type": "string", "description": "Filter by MITRE ATT&CK technique ID (e.g. T1059)"},
                "ioc_type": {"type": "string", "enum": ["ip", "domain", "hash", "file", "url"], "description": "Filter by IOC type"},
                "limit": {"type": "integer", "description": "Max results", "default": 50},
            },
        },
    },
    {
        "name": "search_rules",
        "description": "Search for detection rules (Sigma/SPL). Results are sorted by creation time (newest first). Each rule includes created_at (UTC datetime) and link (GitHub repo URL or source report URL). Can filter by actor or TTP.",
        "input_schema": {
            "type": "object",
            "properties": {
                "actor": {"type": "string", "description": "Filter by threat actor name"},
                "ttp": {"type": "string", "description": "Filter by MITRE ATT&CK technique ID"},
                "limit": {"type": "integer", "description": "Max results", "default": 25},
            },
        },
    },
    {
        "name": "get_coverage",
        "description": "Get the coverage matrix showing which MITRE ATT&CK techniques have IOCs and/or detection rules in the store.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_coverage_matrix",
        "description": (
            "Get the MITRE ATT&CK coverage heatmap broken down by tactic, "
            "plus a link to view/download the full Navigator layer. Use "
            "this for any query about the coverage matrix, heatmap, or "
            "coverage visualization, OR for queries about the most "
            "critical gaps / uncovered techniques."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
]

_ASK_SYSTEM = (
    "You are a threat intelligence search assistant for the Kitsune platform. "
    "Given a user query, determine which tool to call and with what parameters. "
    "Always use exactly one tool — never answer from your own knowledge. "
    "The store contains both baseline detection rules (from a sigma corpus) and "
    "pipeline-generated rules. When the user asks about what rules exist, coverage, "
    "or rule counts, prefer get_coverage — it includes all rules (baseline + generated). "
    "Use search_rules only when the user wants to see specific rule content filtered by actor or TTP. "
    "For queries about the coverage matrix, heatmap, visualization, or the "
    "most critical gaps / uncovered techniques, use get_coverage_matrix. "
    "If the user asks about TTPs, techniques, or MITRE ATT&CK generally, "
    "prefer get_trending_ttps or get_coverage. "
    "If the user asks about actors or threat groups, prefer list_actors or get_actor_summary. "
    "For queries about recently created or newest rules, use search_rules with no filters — "
    "the results are ordered by recency. "
    "For queries about newly added reports or threat actors, use list_actors."
)


def _execute_ask_tool(
    store, tool_name: str, tool_input: dict, navigator_url: str = ""
) -> Any:
    """Execute a tool call against the store and return raw data."""
    if tool_name == "list_actors":
        actors = store._r.smembers(store._actors_key())
        return sorted(actors)

    elif tool_name == "get_actor_summary":
        return store.get_actor_summary(tool_input["actor_name"])

    elif tool_name == "get_trending_ttps":
        return store.get_trending_ttps(n=tool_input.get("top", 10))

    elif tool_name == "search_iocs":
        return store.query_iocs(
            actor=tool_input.get("actor"),
            ttp=tool_input.get("ttp"),
            ioc_type=tool_input.get("ioc_type"),
            limit=tool_input.get("limit", 50),
        )

    elif tool_name == "search_rules":
        from core.github_pr import _safe_branch_component

        # Hard cap at 20 — avoids overlong tables in the AMA bubble.
        rules = store.query_rules(
            actor=tool_input.get("actor"),
            ttp=tool_input.get("ttp"),
            limit=min(tool_input.get("limit", 20) or 20, 20),
        )
        # Resolve repo URL for building file links. Normalize SSH form
        # (git@github.com:owner/repo[.git]) to the HTTPS browse URL.
        _raw_repo = (BaselineRepoConfig.SIGMA_REPO_URL or "").strip()
        _ssh_match = re.match(
            r"git@([^:]+):(.+?)(?:\.git)?/?$", _raw_repo
        )
        if _ssh_match:
            repo_url = f"https://{_ssh_match.group(1)}/{_ssh_match.group(2)}"
        else:
            repo_url = _raw_repo.rstrip("/").removesuffix(".git")
        repo_branch = BaselineRepoConfig.SIGMA_REPO_BRANCH or "main"

        for r in rules:
            # Convert epoch to human-readable UTC
            ts = r.get("created_at")
            if ts:
                try:
                    r["created_at"] = datetime.utcfromtimestamp(float(ts)).strftime(
                        "%Y-%m-%d %H:%M UTC"
                    )
                except (ValueError, TypeError):
                    pass

            # Flatten ttps to a comma-separated string so the LLM renders
            # "T1012, T1059" instead of the raw ["T1012","T1059"] JSON.
            raw_ttps = r.get("ttps")
            if isinstance(raw_ttps, str):
                try:
                    raw_ttps = json.loads(raw_ttps)
                except (TypeError, ValueError, json.JSONDecodeError):
                    raw_ttps = [raw_ttps]
            if isinstance(raw_ttps, list):
                r["ttps"] = ", ".join(str(t) for t in raw_ttps)
            elif raw_ttps is None:
                r["ttps"] = ""

            source_file = r.get("source", "")  # baseline rules
            source_url = r.get("source_url", "")  # pipeline/merged rules

            # Build sigma-repo link for the rule name
            rule_url = ""
            if source_file and repo_url:
                # Baseline rule — link to file in repo
                rule_url = f"{repo_url}/blob/{repo_branch}/{source_file}"
            elif source_url.startswith("github:") and repo_url:
                # Merged-PR rule — reconstruct path from kitsune naming
                # convention: rules/{actor_slug}/{name_slug}.yml
                actor_slug = _safe_branch_component(
                    r.get("threat_actor") or "kitsune"
                )
                name_slug = _safe_branch_component(r.get("name") or "")
                if name_slug:
                    rule_url = (
                        f"{repo_url}/blob/{repo_branch}/"
                        f"rules/{actor_slug}/{name_slug}.yml"
                    )

            # Turn name into a markdown link when we have a repo URL
            rule_name = r.get("name") or ""
            if rule_url and rule_name:
                r["name"] = f"[{rule_name}]({rule_url})"

            # Report column: only set when source_url is a real http(s) URL
            if source_url.startswith(("http://", "https://")):
                r["report"] = f"[report]({source_url})"
            else:
                r["report"] = ""

            # Drop bulky rule_content from AMA results
            r.pop("rule_content", None)
            r.pop("tlsh_hash", None)
            r.pop("ioc_hash", None)
        return rules

    elif tool_name == "get_coverage":
        raw = store.get_coverage_summary()
        return [{"ttp_id": tid, **data} for tid, data in sorted(raw.items())]

    elif tool_name == "get_coverage_matrix":
        matrix = _build_coverage_matrix()
        # Flatten by_tactic into a compact list the LLM can render as a table.
        tactic_rows = []
        all_gaps = []
        for entry in matrix["by_tactic"]:
            total = entry["total_tracked"]
            covered = entry["covered"]
            pct = round(100 * covered / total) if total else 0
            tactic_rows.append({
                "tactic": entry["tactic"],
                "covered": covered,
                "total": total,
                "pct": pct,
                "gap_count": len(entry["uncovered_with_iocs"]),
            })
            for g in entry["uncovered_with_iocs"]:
                all_gaps.append({
                    "tactic": entry["tactic"],
                    "ttp_id": g["ttp_id"],
                    "ioc_count": g["ioc_count"],
                })
        # Critical-first: highest IOC volume = most active threat with no rule.
        all_gaps.sort(key=lambda g: (-g["ioc_count"], g["ttp_id"]))
        return {
            "totals": matrix["totals"],
            "by_tactic": tactic_rows,
            "critical_gaps": all_gaps[:15],
            "navigator_url": navigator_url,
        }

    return {"error": f"Unknown tool: {tool_name}"}


class AskRequest(BaseModel):
    query: str


class AskResponse(BaseModel):
    answer: str
    tool_used: Optional[str] = None
    data: Any = None


class BaselineStatsResponse(BaseModel):
    rule_count: int
    ttps_covered: List[str]
    loaded_at: Optional[float] = None
    source_path: Optional[str] = None
    source_url: Optional[str] = None


class ProposePRRequest(BaseModel):
    rule_ids: List[str]
    threat_actor: Optional[str] = None
    task_id: Optional[str] = None  # link to reviewed task for audit trail


class ProposePRResponse(BaseModel):
    pr_url: str
    rule_count: int


class GitHubSyncResponse(BaseModel):
    ingested_count: int
    pr_urls: List[str]


@app.post("/ask", response_model=AskResponse, tags=["Search"])
def ask_query(req: AskRequest, request: Request):
    """
    Natural language search across the threat intel store.

    Uses AI to interpret your question and query the right data.

    **Examples:**
    - `"give me the top 5 TTPs"`
    - `"list all threat actors"`
    - `"show me IOCs for apt28"`
    - `"what detection rules exist for T1059?"`
    - `"which TTPs have no detection rules?"`
    """
    import anthropic

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not set — AI search unavailable.")

    store = get_store()
    client = anthropic.Anthropic(api_key=api_key)

    # Step 1: LLM picks the right tool + params
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=512,
        system=_ASK_SYSTEM,
        tools=_ASK_TOOLS,
        messages=[{"role": "user", "content": req.query}],
    )

    # Find the tool_use block
    tool_block = next((b for b in response.content if b.type == "tool_use"), None)
    if not tool_block:
        return AskResponse(answer="I couldn't determine which data to look up. Try asking about TTPs, actors, IOCs, or detection rules.")

    # Step 2: Execute the tool against the store
    nav_url = _navigator_view_url(request)
    data = _execute_ask_tool(store, tool_block.name, tool_block.input, nav_url)

    # Step 3: Send tool result back to LLM for a natural language summary
    summary_response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system=(
            "You are a threat intelligence analyst summarizing query results. "
            "Be concise and direct. "
            "Formatting rules — you MUST follow these: "
            "(1) For simple lists of strings (actors, TTP IDs, gaps, tags), "
            "render as a markdown bullet list with one item per line "
            "(e.g. `- UNC6748\\n- UNC6353`). Never comma-separate list items "
            "on a single line. "
            "(2) For structured data with multiple fields per row (rules, "
            "IOCs, trending TTPs), use a markdown table. "
            "(3) For detection rules tables: show columns Created "
            "(created_at as-is), Name (use the name field verbatim — it "
            "is already a markdown link when available), TTPs, and "
            "Report (use the report field verbatim — already a markdown "
            "link, or empty). Do NOT add any other columns. "
            "(4) For coverage data (get_coverage): NEVER render the full "
            "per-TTP list as a table. Output EXACTLY two blocks and "
            "nothing else — no intro, no closing commentary, no repeated "
            "lists, no technique descriptions: "
            "(a) a single summary line of totals (e.g. `**142 techniques "
            "tracked** — 98 ✅ with rules, 27 ⚠️ IOCs only, 17 ❌ "
            "uncovered`), then "
            "(b) a bullet list (max 10 items) of gaps where "
            "`has_iocs=true` and `has_rules=false`, formatted as "
            "`- ⚠️ T#### ({ioc_count} IOCs, no rules)`, one per line "
            "with NO blank lines between bullets. If there are zero "
            "gaps, omit block (b) entirely. Do NOT restate the gaps in "
            "prose afterwards. "
            "(5) For coverage matrix data (get_coverage_matrix): output "
            "EXACTLY these blocks and nothing else — no intro paragraph, "
            "no closing commentary, no repeated descriptions: "
            "(a) one summary line of totals from `totals` "
            "(e.g. `**{total_tracked} techniques tracked** — "
            "{with_rules} ✅ with rules, {iocs_only} ⚠️ IOCs only, "
            "{uncovered} ❌ uncovered`). "
            "(b) a markdown table titled `**Coverage by tactic**` with "
            "columns `Tactic | Covered | Gaps` where Covered shows "
            "`{covered}/{total} ({pct}%)` and Gaps shows `gap_count` "
            "(render as `—` when 0). Use rows from `by_tactic` in the "
            "order given. Format the tactic name in Title Case "
            "(e.g. `Credential Access`). "
            "(c) a section `**Most critical gaps**` followed by a bullet "
            "list from `critical_gaps` (up to 10 items), formatted as "
            "`- ⚠️ **T####** — {tactic_title_case} ({ioc_count} IOCs, "
            "no rules)`. One per line, no blank lines between. Skip this "
            "block entirely if `critical_gaps` is empty. "
            "(d) one final line: "
            "`🗺️ [Open full heatmap in MITRE ATT&CK Navigator]"
            "({navigator_url})`. "
            "(6) If the data is empty, say so clearly."
        ),
        tools=_ASK_TOOLS,
        messages=[
            {"role": "user", "content": req.query},
            {"role": "assistant", "content": response.content},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tool_block.id, "content": json.dumps(data, default=str)}]},
        ],
    )

    answer = "".join(b.text for b in summary_response.content if b.type == "text")

    return AskResponse(answer=answer, tool_used=tool_block.name, data=data)


@app.put("/rules/{rule_id:path}", tags=["Detection Rules"])
def update_rule(rule_id: str, req: RuleUpdateRequest):
    """
    Update the `rule_content` for a stored detection rule.

    Use the `rule_id` returned by `GET /rules` or `POST /analyze`.

    **Example:** `PUT /rules/kitsune:rule:abc123` with body `{"rule_content": "..."}`
    """
    store = get_store()
    if not store.update_rule(rule_id, req.rule_content):
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")
    return {"status": "updated"}


# ── Baseline corpus endpoints ────────────────────────────────────────────────

@app.get("/baseline/stats", response_model=BaselineStatsResponse, tags=["Baseline"])
def baseline_stats():
    """
    Return statistics about the loaded baseline sigma rule corpus.

    Shows rule count, unique TTPs covered, when it was last loaded,
    and the configured source path / URL.
    """
    repo = get_baseline_repo()
    return BaselineStatsResponse(
        rule_count=repo.rule_count,
        ttps_covered=repo.ttps_covered,
        loaded_at=repo.loaded_at,
        source_path=BaselineRepoConfig.SIGMA_REPO_PATH,
        source_url=BaselineRepoConfig.SIGMA_REPO_URL,
    )


@app.post("/baseline/reload", response_model=BaselineStatsResponse, tags=["Baseline"])
def baseline_reload():
    """
    Force a reload of the baseline corpus from disk and/or GitHub.

    Safe to call while the pipeline is running — the old cache remains
    in use until the new load completes.
    """
    repo = initialize_baseline_repo(
        local_path=BaselineRepoConfig.SIGMA_REPO_PATH,
        repo_url=BaselineRepoConfig.SIGMA_REPO_URL,
        branch=BaselineRepoConfig.SIGMA_REPO_BRANCH,
        token=BaselineRepoConfig.SIGMA_REPO_TOKEN,
        store=getattr(app.state, "store", None),
    )
    return BaselineStatsResponse(
        rule_count=repo.rule_count,
        ttps_covered=repo.ttps_covered,
        loaded_at=repo.loaded_at,
        source_path=BaselineRepoConfig.SIGMA_REPO_PATH,
        source_url=BaselineRepoConfig.SIGMA_REPO_URL,
    )


@app.post("/rules/propose-pr", response_model=ProposePRResponse, tags=["Baseline"])
def propose_pr(req: ProposePRRequest):
    """
    Open a GitHub PR proposing the specified rules for inclusion in the
    baseline repository.

    Requires `GITHUB_TOKEN` and `GITHUB_REPO` to be configured.
    Returns HTTP 503 if GitHub integration is not enabled.
    """
    from core.github_pr import get_github_client

    gh = get_github_client()
    if gh is None:
        raise HTTPException(
            status_code=503,
            detail="GitHub integration not configured. Set GITHUB_TOKEN and GITHUB_REPO.",
        )

    store = get_store()
    rules_to_propose: List[DetectionRule] = []
    for rule_id in req.rule_ids:
        data = store._r.hgetall(rule_id)
        if data:
            rules_to_propose.append(
                DetectionRule(
                    name=data.get("name", rule_id),
                    description=data.get("description", ""),
                    author=data.get("threat_actor", "kitsune"),
                    references=[data.get("source_url", "")],
                    mitre_ttps=json.loads(data.get("ttps", "[]")),
                    rule_content=data.get("rule_content", ""),
                    format=data.get("format", "sigma"),
                )
            )

    if not rules_to_propose:
        raise HTTPException(status_code=404, detail="No rules found for the provided IDs.")

    # Build review summary for PR body if linked to a reviewed task
    review_summary = None
    if req.task_id:
        with _tasks_lock:
            task = _tasks.get(req.task_id)
        if task and task.get("review_status") != "approved":
            raise HTTPException(
                status_code=400,
                detail="Rules must be reviewed and approved before creating a PR.",
            )
        if task:
            validated = task.get("validated_rules", [])
            review_summary = {
                "decision": "approved",
                "reviewed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "validation_summary": {
                    "passed": sum(1 for v in validated if v.get("verdict") == "pass"),
                    "needs_review": sum(1 for v in validated if v.get("verdict") == "needs_review"),
                    "failed": sum(1 for v in validated if v.get("verdict") == "fail"),
                },
            }

    pr_url = gh.propose_rules(
        rules_to_propose,
        threat_actor=req.threat_actor,
        review_approved=True,
        review_summary=review_summary,
    )
    return ProposePRResponse(pr_url=pr_url, rule_count=len(rules_to_propose))


@app.get("/github/sync", response_model=GitHubSyncResponse, tags=["Baseline"])
def github_sync():
    """
    Pull merged kitsune PRs from GitHub, ingest their rules into Redis,
    and reload the baseline corpus.

    Newly merged rules become part of the baseline for all future analyze jobs.
    Requires `GITHUB_TOKEN` and `GITHUB_REPO` to be configured.
    """
    from core.github_pr import get_github_client

    gh = get_github_client()
    if gh is None:
        raise HTTPException(
            status_code=503,
            detail="GitHub integration not configured. Set GITHUB_TOKEN and GITHUB_REPO.",
        )

    store = get_store()
    merged_rules = gh.get_merged_pr_rules()
    ingested = 0

    for rule in merged_rules:
        try:
            store.ingest_rules(
                [rule],
                source_url=f"github:{GitHubConfig.GITHUB_REPO}",
                threat_actor="",
                ioc_hash="",
            )
            ingested += 1
        except Exception as exc:
            print(f"[github/sync] Failed to ingest '{rule.name}': {exc}")

    # Reload baseline so synced rules appear immediately
    initialize_baseline_repo(
        local_path=BaselineRepoConfig.SIGMA_REPO_PATH,
        repo_url=BaselineRepoConfig.SIGMA_REPO_URL,
    )

    return GitHubSyncResponse(ingested_count=ingested, pr_urls=[])
