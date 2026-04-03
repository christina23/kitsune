"""
Kitsune REST API — query the Redis threat intel store.

Run with:
    uvicorn api:app --reload --port 8000

Swagger UI:  http://localhost:8000/docs
Redoc:       http://localhost:8000/redoc
"""

import json
import os
import sys
import threading
import uuid
from typing import Any, Dict, List, Literal, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

load_dotenv()

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.dirname(__file__))
from core.intel_store import create_store

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

app = FastAPI(
    title="Kitsune",
    description=_API_DESCRIPTION,
    version="0.2.0",
    contact={"name": "Kitsune", "url": "https://github.com/christina23/kitsune"},
    docs_url=None,   # disabled; custom Swagger served at /docs
    redoc_url=None,  # disabled; Scalar served at /scalar
    openapi_tags=[
        {"name": "Health", "description": "Service health and connectivity checks."},
        {"name": "Pipeline", "description": "Submit threat report URLs for analysis and poll task status."},
        {"name": "Search", "description": "Natural-language search powered by AI."},
        {"name": "Actors", "description": "Browse and inspect tracked threat actors."},
        {"name": "IOCs", "description": "Query indicators of compromise — IPs, domains, hashes, URLs, files."},
        {"name": "Detection Rules", "description": "Search and update Sigma / SPL detection rules."},
        {"name": "Analytics", "description": "Trending TTPs and per-technique coverage reports."},
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
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    threat_actors: Optional[str] = None  # JSON-encoded list
    campaigns: Optional[str] = None
    ttps: Optional[str] = None
    source_urls: Optional[str] = None


class RuleRecord(BaseModel):
    rule_id: Optional[str] = None
    name: str
    format: str
    rule_content: Optional[str] = None
    ttps: Optional[str] = None  # JSON-encoded list
    threat_actor: Optional[str] = None
    source_url: Optional[str] = None
    created_at: Optional[str] = None


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
    status: Literal["running", "done", "error"]
    step: Optional[str] = None
    result: Optional[AnalyzeResponse] = None
    error: Optional[str] = None


# ── In-memory task store ──────────────────────────────────────────────────────
# Maps task_id → {"status", "step", "result", "error"}
# Tasks are held for the lifetime of the server process.

_tasks: Dict[str, Dict[str, Any]] = {}
_tasks_lock = threading.Lock()


def _set_task(task_id: str, **kwargs: Any) -> None:
    with _tasks_lock:
        _tasks[task_id].update(kwargs)


def _run_pipeline_task(task_id: str, req: "AnalyzeRequest") -> None:
    """Background thread: run the full pipeline and write results to _tasks."""
    try:
        _set_task(task_id, step="Loading store…")
        store = create_store()

        _set_task(task_id, step="Initialising agent…")
        from core.agent import ThreatDetectionAgent

        agent = ThreatDetectionAgent(llm_provider=req.llm_provider, store=store)

        # The pipeline runs sequentially inside generate_detections.
        # We update `step` at major milestones visible to the UI.
        _set_task(task_id, step="Fetching & parsing URL…")

        # Monkey-patch the agent's internal steps to surface progress
        _orig_fetch = agent._fetch_content
        _orig_extract = agent._extract_threat_intel
        _orig_coverage = agent._analyze_coverage
        _orig_spl = agent._generate_spl_rules
        _orig_sigma = agent._generate_sigma_rules

        def _traced(fn, label):
            def _wrapper(state):
                _set_task(task_id, step=label)
                return fn(state)
            return _wrapper

        agent._fetch_content = _traced(_orig_fetch, "Fetching URL content…")
        agent._extract_threat_intel = _traced(_orig_extract, "Extracting IOCs & TTPs…")
        agent._analyze_coverage = _traced(_orig_coverage, "Phase 1 coverage analysis…")
        agent._generate_spl_rules = _traced(_orig_spl, "Generating SPL rules…")
        agent._generate_sigma_rules = _traced(_orig_sigma, "Generating Sigma rules…")
        # Rebuild workflow with the patched methods
        agent.workflow = agent._create_workflow()
        from langgraph.checkpoint.memory import MemorySaver
        agent.app = agent.workflow.compile(checkpointer=MemorySaver())

        _set_task(task_id, step="Pipeline running…")
        rules = agent.generate_detections(req.url, req.rule_format)

        state = agent._last_state or {}
        intel = state.get("threat_intel")
        gaps = state.get("coverage_gaps", [])

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
        _set_task(task_id, status="done", step="Complete", result=result.model_dump())

    except Exception as exc:
        _set_task(task_id, status="error", step="Failed", error=str(exc))


# ── Dependency ────────────────────────────────────────────────────────────────


def get_store():
    store = create_store()
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
    return results


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
    return results


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
        }
    thread = threading.Thread(
        target=_run_pipeline_task, args=(task_id, req), daemon=True
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
    return TaskStatusResponse(task_id=task_id, **task)


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
        "description": "Search for detection rules (Sigma/SPL). Can filter by actor or TTP.",
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
]

_ASK_SYSTEM = (
    "You are a threat intelligence search assistant for the Kitsune platform. "
    "Given a user query, determine which tool to call and with what parameters. "
    "Always use exactly one tool — never answer from your own knowledge. "
    "If the user asks about TTPs, techniques, or MITRE ATT&CK, prefer get_trending_ttps or get_coverage. "
    "If the user asks about actors or threat groups, prefer list_actors or get_actor_summary."
)


def _execute_ask_tool(store, tool_name: str, tool_input: dict) -> Any:
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
        return store.query_rules(
            actor=tool_input.get("actor"),
            ttp=tool_input.get("ttp"),
            limit=tool_input.get("limit", 25),
        )

    elif tool_name == "get_coverage":
        raw = store.get_coverage_summary()
        return [{"ttp_id": tid, **data} for tid, data in sorted(raw.items())]

    return {"error": f"Unknown tool: {tool_name}"}


class AskRequest(BaseModel):
    query: str


class AskResponse(BaseModel):
    answer: str
    tool_used: Optional[str] = None
    data: Any = None


@app.post("/ask", response_model=AskResponse, tags=["Search"])
def ask_query(req: AskRequest):
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
    data = _execute_ask_tool(store, tool_block.name, tool_block.input)

    # Step 3: Send tool result back to LLM for a natural language summary
    summary_response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        system=(
            "You are a threat intelligence analyst summarizing query results. "
            "Be concise and direct. Use markdown tables or bullet points for structured data. "
            "If the data is empty, say so clearly."
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
