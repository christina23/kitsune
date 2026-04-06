"""
Kitsune — Streamlit frontend for the Redis threat intel store.

Run with:
    streamlit run app.py

Requires the Kitsune API to be running at http://localhost:8000
(or set KITSUNE_API_URL env var to override).
"""

import json
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
import streamlit as st

API_URL = os.getenv("KITSUNE_API_URL", "http://localhost:8000").rstrip("/")

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Kitsune",
    page_icon="🦊",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Global CSS ────────────────────────────────────────────────────────────────

st.markdown(
    """
<style>
/* ── Base chrome ─────────────────────────────── */
[data-testid="stAppViewContainer"] { background: #0d1117; }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stSidebar"] { display: none !important; }
[data-testid="stSidebarCollapsedControl"] { display: none !important; }

/* ── Main content padding ────────────────────── */
.block-container { padding-top: 1.8rem; padding-bottom: 3rem; }

/* ── Hide default Streamlit footer ───────────── */
footer { visibility: hidden; }

/* ── Expanders ───────────────────────────────── */
[data-testid="stExpander"] {
    border: 1px solid #21262d !important;
    border-radius: 8px !important;
    background: #161b22 !important;
    margin-bottom: 0.6rem;
}
[data-testid="stExpander"] summary {
    font-weight: 600;
    font-size: 0.9rem;
    color: #c9d1d9;
}

/* ── Metric cards ────────────────────────────── */
[data-testid="stMetric"] {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 0.8rem 1rem;
}
[data-testid="stMetricLabel"] { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
[data-testid="stMetricValue"] { font-size: 1.4rem; font-weight: 700; color: #e6edf3; }

/* ── Buttons ─────────────────────────────────── */
[data-testid="stBaseButton-primary"] {
    background: #e05c4b !important;
    border: none !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    letter-spacing: 0.02em;
    color: #ffffff !important;
}
[data-testid="stBaseButton-primary"]:hover { background: #c94d3d !important; color: #ffffff !important; }
[data-testid="stBaseButton-primary"] p { color: #ffffff !important; }
[data-testid="stBaseButton-secondary"] {
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
    color: #8b949e !important;
}

/* ── Inputs ──────────────────────────────────── */
[data-testid="stTextInput"] input,
[data-testid="stSelectbox"] div[data-baseweb],
[data-testid="stNumberInput"] input {
    background: #0d1117 !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
    color: #e6edf3 !important;
}

/* ── Progress bar ────────────────────────────── */
[data-testid="stProgressBar"] > div > div {
    background: linear-gradient(90deg, #e05c4b, #ff8c7a);
    border-radius: 4px;
}

/* ── Dataframes ──────────────────────────────── */
[data-testid="stDataFrame"] { border-radius: 8px; overflow: hidden; }

/* ── Divider ─────────────────────────────────── */
hr { border-color: #21262d; }

/* ── Alert / info boxes ──────────────────────── */
[data-testid="stAlert"] { border-radius: 8px; }

/* ── Section headers ─────────────────────────── */
.section-header {
    font-size: 0.78rem;
    font-weight: 700;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 1.4rem 0 0.6rem;
    padding-bottom: 0.35rem;
    border-bottom: 1px solid #21262d;
}
</style>
""",
    unsafe_allow_html=True,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def _http_detail(e: requests.exceptions.HTTPError) -> str:
    try:
        return e.response.json().get("detail", "")
    except Exception:
        return ""


def _get(endpoint: str, params: Optional[Dict] = None) -> Any:
    try:
        resp = requests.get(f"{API_URL}{endpoint}", params=params, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error(f"Cannot reach API at **{API_URL}**. Is `uvicorn api:app --port 8000` running?")
        return None
    except requests.exceptions.HTTPError as e:
        st.error(f"API error {e.response.status_code}: {_http_detail(e) or str(e)}")
        return None


def _post(endpoint: str, payload: Dict) -> Any:
    try:
        resp = requests.post(f"{API_URL}{endpoint}", json=payload, timeout=120)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error(f"Cannot reach API at **{API_URL}**. Is `uvicorn api:app --port 8000` running?")
        return None
    except requests.exceptions.HTTPError as e:
        st.error(f"API error {e.response.status_code}: {_http_detail(e) or str(e)}")
        return None


def _put(endpoint: str, payload: Dict) -> Any:
    try:
        resp = requests.put(f"{API_URL}{endpoint}", json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error(f"Cannot reach API at **{API_URL}**.")
        return None
    except requests.exceptions.HTTPError as e:
        st.error(f"API error {e.response.status_code}: {_http_detail(e) or str(e)}")
        return None


def _md_to_html(text: str) -> str:
    """Minimal markdown-to-HTML for the /ask answer bubble.

    Streamlit's markdown parser does not re-process markdown inside a
    raw HTML `<div>`, so we convert the two constructs the summary LLM
    is asked to emit — bullet lists and tables — into HTML inline.
    Everything else is passed through with `\\n` → `<br>`.
    """
    if not text:
        return ""
    # Convert markdown links [text](url) → <a href="url">text</a> first,
    # so they render inside table cells and plain text alike.
    text = re.sub(
        r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
        r'<a href="\2" target="_blank" style="color:#79c0ff;">\1</a>',
        text,
    )
    # Inline emphasis: **bold** and *italic* (bold first to avoid
    # greedy single-asterisk matches eating the double-asterisk pair).
    text = re.sub(r"\*\*([^*\n]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(
        r"(?<![*\w])\*([^*\n]+)\*(?!\w)", r"<em>\1</em>", text
    )
    # Inline `code`
    text = re.sub(
        r"`([^`\n]+)`",
        r'<code style="background:#21262d; padding:1px 5px; '
        r'border-radius:4px; font-size:0.82em;">\1</code>',
        text,
    )
    lines = text.split("\n")
    out: List[str] = []
    in_ul = False
    in_table = False
    table_header_seen = False

    def _close_ul():
        nonlocal in_ul
        if in_ul:
            out.append("</ul>")
            in_ul = False

    def _close_table():
        nonlocal in_table, table_header_seen
        if in_table:
            out.append("</table>")
            in_table = False
            table_header_seen = False

    table_style = (
        "border-collapse:collapse; margin:0.4em 0; font-size:0.82rem;"
    )
    th_style = (
        "text-align:left; padding:4px 10px; "
        "border-bottom:1px solid #30363d; color:#8b949e; font-weight:600;"
    )
    td_style = (
        "padding:4px 10px; border-bottom:1px solid #21262d; color:#c9d1d9;"
    )

    for raw in lines:
        line = raw.rstrip()
        stripped = line.lstrip()
        # Markdown table row (very simple detection)
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            # Skip the separator row (|---|---|)
            if all(set(c) <= set("-: ") for c in cells) and cells:
                table_header_seen = True
                continue
            _close_ul()
            if not in_table:
                out.append(f"<table style=\"{table_style}\">")
                in_table = True
            tag = "th" if not table_header_seen else "td"
            style = th_style if tag == "th" else td_style
            out.append(
                "<tr>"
                + "".join(f"<{tag} style=\"{style}\">{c}</{tag}>" for c in cells)
                + "</tr>"
            )
            if tag == "th":
                table_header_seen = True
            continue
        # Bullet list item
        if stripped.startswith(("- ", "* ")):
            _close_table()
            if not in_ul:
                out.append(
                    "<ul style=\"margin:0.3em 0; padding-left:1.2em;\">"
                )
                in_ul = True
            out.append(f"<li>{stripped[2:]}</li>")
            continue
        # Non-list, non-table line
        _close_ul()
        _close_table()
        if line:
            out.append(line)
        else:
            out.append("<br>")

    _close_ul()
    _close_table()
    # Join with <br> between content lines. Skip only when adjacent to
    # true block-level tags (ul/table) — inline tags like <strong>,
    # <em>, <code>, <a> should still get line breaks between them.
    _block_prefixes = ("<ul", "</ul", "<table", "</table", "<tr", "</tr")

    def _is_block(piece: str) -> bool:
        return piece.startswith(_block_prefixes)

    html_parts: List[str] = []
    for i, piece in enumerate(out):
        html_parts.append(piece)
        next_piece = out[i + 1] if i + 1 < len(out) else ""
        if (
            piece
            and not _is_block(piece)
            and next_piece
            and not _is_block(next_piece)
            and piece != "<br>"
            and next_piece != "<br>"
        ):
            html_parts.append("<br>")
    # Collapse runs of 2+ <br> into a single <br> to avoid double spacing
    # when the LLM emits blank lines between bullets/paragraphs.
    html = "".join(html_parts)
    html = re.sub(r"(?:<br>\s*){2,}", "<br>", html)
    return html


def _fmt_ts(ts: Optional[str]) -> str:
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError):
        return ts


def _parse_json_list(raw) -> List[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    try:
        out = json.loads(raw)
        return out if isinstance(out, list) else [str(out)]
    except (json.JSONDecodeError, TypeError):
        return [str(raw)]


def _pill(text: str, bg: str, fg: str = "#fff") -> str:
    return (
        f'<span style="background:{bg}; color:{fg}; border-radius:20px; '
        f'padding:2px 9px; font-size:0.72rem; font-weight:600; '
        f'letter-spacing:0.03em; display:inline-block; margin:1px 2px;">'
        f'{text}</span>'
    )


def _ttp_badge(ttp: str) -> str:
    return _pill(ttp, "#1a4a7a", "#79c0ff")


def _actor_badge(actor: str) -> str:
    return _pill(actor, "#3d1f6b", "#d2a8ff")


def _fmt_badge(fmt: str) -> str:
    colors = {"spl": ("#1a3a5c", "#79c0ff"), "sigma": ("#2d1b4e", "#c9a8ff")}
    bg, fg = colors.get(fmt.lower(), ("#21262d", "#8b949e"))
    return _pill(fmt.upper(), bg, fg)


def _priority_badge(priority: str) -> str:
    colors = {
        "high": ("#4a1010", "#ff7b7b"),
        "medium": ("#4a2e00", "#ffa657"),
        "low": ("#1c2128", "#8b949e"),
    }
    bg, fg = colors.get(priority.lower(), ("#1c2128", "#8b949e"))
    return _pill(priority.upper(), bg, fg)


def _relative_time(ts_str: str) -> str:
    """Convert an ISO 8601 UTC (or epoch) timestamp to a human-readable relative time."""
    if not ts_str:
        return ""
    ts: float
    try:
        ts = float(ts_str)
    except (ValueError, TypeError):
        try:
            s = ts_str.replace("Z", "+00:00")
            ts = datetime.fromisoformat(s).timestamp()
        except (ValueError, TypeError):
            return ""
    delta = time.time() - ts
    if delta < 60:
        return "just now"
    elif delta < 3600:
        return f"{int(delta // 60)}m ago"
    elif delta < 86400:
        return f"{int(delta // 3600)}h ago"
    elif delta < 604800:
        return f"{int(delta // 86400)}d ago"
    else:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")


def _ioc_type_badge(ioc_type: str) -> str:
    colors = {
        "ip": ("#0d2d45", "#56d4fb"),
        "domain": ("#0d3320", "#56e89e"),
        "hash": ("#2d2000", "#e3b341"),
        "url": ("#2d1b00", "#ffa657"),
        "file": ("#1c1c2e", "#c9a8ff"),
    }
    bg, fg = colors.get(ioc_type.lower(), ("#21262d", "#8b949e"))
    return _pill(ioc_type.upper(), bg, fg)


# ── Cached dashboard data ────────────────────────────────────────────────────


@st.cache_data(ttl=30)
def _load_actors() -> List[str]:
    try:
        resp = requests.get(f"{API_URL}/actors", timeout=5)
        resp.raise_for_status()
        return resp.json() or []
    except Exception:
        return []


@st.cache_data(ttl=30)
def _load_trends(n: int = 8) -> List[Dict]:
    try:
        resp = requests.get(f"{API_URL}/trends", params={"top": n}, timeout=5)
        resp.raise_for_status()
        return resp.json() or []
    except Exception:
        return []


@st.cache_data(ttl=30)
def _load_coverage() -> List[Dict]:
    try:
        resp = requests.get(f"{API_URL}/coverage", timeout=5)
        resp.raise_for_status()
        return resp.json() or []
    except Exception:
        return []


# ── Header ────────────────────────────────────────────────────────────────────

# Redis status (fetch once, reuse below)
_health = _get("/")
_redis_ok = _health.get("redis") == "connected" if _health else False
_redis_dot = "🟢" if _redis_ok else "🔴"

st.markdown(
    f"""
<div style="display:flex; align-items:center; gap:0.75rem; margin-bottom:0.25rem;">
  <span style="font-size:2rem; line-height:1;">🦊</span>
  <div>
    <div style="font-size:1.5rem; font-weight:800; letter-spacing:-0.01em;
                color:#e6edf3; line-height:1.1;">
      KITSUNE
    </div>
    <div style="font-size:0.78rem; color:#8b949e; letter-spacing:0.06em;
                text-transform:uppercase; font-weight:500;">
      Threat Intelligence Platform
    </div>
  </div>
  <div style="margin-left:auto; display:flex; align-items:center; gap:0.5rem;">
    <span style="font-size:0.72rem; color:#8b949e;">
      {_redis_dot} Redis
    </span>
    <a href="{API_URL}/scalar" target="_blank"
       style="background:#1a3a5c; color:#79c0ff; padding:0.35rem 0.8rem;
              border-radius:6px; text-decoration:none; font-weight:600;
              font-size:0.78rem;">
      ✦ API Docs
    </a>
    <a href="{API_URL}/docs" target="_blank"
       style="background:#161b22; color:#8b949e; border:1px solid #30363d;
              padding:0.35rem 0.8rem; border-radius:6px; text-decoration:none;
              font-weight:600; font-size:0.78rem;">
      ⚡ Swagger
    </a>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

st.markdown(
    '<hr style="margin:0.5rem 0 1rem; border-color:#21262d;">',
    unsafe_allow_html=True,
)

# ── Pipeline Input Bar (always visible) ───────────────────────────────────────

with st.container(border=True):
    col_url, col_fmt, col_llm, col_btn = st.columns([5, 1.5, 1.5, 1])
    with col_url:
        pipeline_url = st.text_input(
            "URL",
            placeholder="Paste a threat report URL…",
            key="pipeline_url",
            label_visibility="collapsed",
        )
    with col_fmt:
        pipeline_fmt = st.selectbox("Format", ["sigma", "spl"], key="pipeline_fmt", label_visibility="collapsed")
    with col_llm:
        pipeline_llm = st.selectbox("LLM", ["anthropic", "openai"], key="pipeline_llm", label_visibility="collapsed")
    with col_btn:
        run_pipeline = st.button("▶ Analyze", type="primary", key="btn_pipeline", use_container_width=True)

if run_pipeline:
    if not pipeline_url.strip():
        st.warning("Please enter a URL.")
    else:
        resp = _post("/analyze", {
            "url": pipeline_url.strip(),
            "rule_format": pipeline_fmt,
            "llm_provider": pipeline_llm,
        })
        if resp and resp.get("task_id"):
            st.session_state["pipeline_task_id"] = resp["task_id"]
            st.session_state["pipeline_result"] = None
            # Remember params so "Regenerate" can re-run the same job.
            st.session_state["last_pipeline_params"] = {
                "url": pipeline_url.strip(),
                "rule_format": pipeline_fmt,
                "llm_provider": pipeline_llm,
            }
            st.rerun()

# ── Pipeline Polling (fragment — sidebar stays stable) ────────────────────────


@st.fragment
def _poll_pipeline():
    task_id = st.session_state.get("pipeline_task_id")
    if not task_id or st.session_state.get("pipeline_result"):
        return
    task = _get(f"/tasks/{task_id}")
    if not task:
        return
    if task["status"] == "done":
        st.session_state["pipeline_result"] = task.get("result", {})
        st.session_state["pipeline_task_id"] = None
        st.rerun()
    elif task["status"] == "pending_review" or task.get("review_status") == "pending_review":
        # Hand off to the review panel
        st.session_state["review_task_id"] = task_id
        st.session_state["pipeline_task_id"] = None
        st.rerun()
    elif task["status"] == "error":
        st.error(f"Pipeline failed: {task.get('error', 'unknown error')}")
        st.session_state["pipeline_task_id"] = None
    else:
        step = task.get("step", "Running…")
        _STEPS = [
            "Fetching URL content…",
            "Extracting IOCs & TTPs…",
            "Phase 1 coverage analysis…",
            "Generating SPL rules…",
            "Generating Sigma rules…",
            "Validating rules…",
            "Complete",
        ]
        idx = _STEPS.index(step) if step in _STEPS else 0
        progress = min(idx / max(len(_STEPS) - 1, 1), 0.95)
        st.progress(progress, text=f"**{step}**")
        time.sleep(3)
        st.rerun()


_poll_pipeline()

# ── Review Panel ─────────────────────────────────────────────────────────────

review_task_id = st.session_state.get("review_task_id")
if review_task_id and not st.session_state.get("pipeline_result"):
    review_data = _get(f"/tasks/{review_task_id}/review")
    if review_data and review_data.get("rules"):
        st.markdown(
            '<div class="section-header">Review Generated Rules</div>',
            unsafe_allow_html=True,
        )
        st.info(
            f"**{len(review_data['rules'])} rule(s)** are awaiting your review. "
            "Inspect each rule, optionally edit, then approve or reject."
        )

        # Show validation summary
        verdicts = [r.get("verdict", "pass") for r in review_data["rules"]]
        pass_count = verdicts.count("pass")
        review_count = verdicts.count("needs_review")
        fail_count = verdicts.count("fail")
        v_cols = st.columns(3)
        v_cols[0].metric("Passed", pass_count)
        v_cols[1].metric("Needs Review", review_count)
        v_cols[2].metric("Failed", fail_count)

        # Show each rule for review — all checked by default; uncheck to exclude.
        rule_edits: Dict[str, str] = {}
        included_names: List[str] = []
        for i, rule in enumerate(review_data["rules"]):
            verdict = rule.get("verdict", "pass")
            issues = rule.get("issues", [])
            badge_colors = {
                "pass": ("#0f2d18", "#3fb950"),
                "needs_review": ("#2d1b00", "#ffa657"),
                "fail": ("#4a1010", "#ff7b7b"),
            }
            bg, fg = badge_colors.get(verdict, ("#21262d", "#8b949e"))
            verdict_badge = _pill(verdict.upper(), bg, fg)

            include_col, expander_col = st.columns([0.5, 11])
            with include_col:
                include = st.checkbox(
                    "Include",
                    value=True,
                    key=f"review_include_{i}",
                    label_visibility="collapsed",
                )
            if include:
                included_names.append(rule["name"])
            with expander_col:
                with st.expander(
                    f"[{rule.get('format', 'sigma').upper()}] {rule['name']} — {verdict}",
                    expanded=(verdict != "pass"),
                ):
                    st.markdown(
                        f"{verdict_badge} **{rule['name']}**",
                        unsafe_allow_html=True,
                    )
                    if issues:
                        for issue in issues:
                            st.warning(issue)

                    ttps = rule.get("mitre_ttps", [])
                    if ttps:
                        st.markdown(
                            " ".join(_ttp_badge(t) for t in ttps[:6]),
                            unsafe_allow_html=True,
                        )

                    edited = st.text_area(
                        "Rule content",
                        value=rule.get("rule_content", ""),
                        height=240,
                        key=f"review_edit_{i}",
                        label_visibility="collapsed",
                    )
                    if edited != rule.get("rule_content", ""):
                        rule_edits[rule["name"]] = edited

        # Review action buttons
        st.markdown("<div style='height:0.8rem;'></div>", unsafe_allow_html=True)
        feedback = st.text_area(
            "What should be improved? (optional)",
            placeholder=(
                "e.g. tighten the filter for admin tools, add temporal "
                "windowing on the logon failures, drop the atomic IOC rule…"
            ),
            key="review_feedback",
            height=80,
            help=(
                "On Regenerate, this is sent to the LLM to steer the new "
                "rules. On Create PR, it is saved to the audit trail."
            ),
        )

        st.caption(
            f"{len(included_names)} of {len(review_data['rules'])} rule(s) selected for PR."
        )
        btn_cols = st.columns([1.2, 1.2, 4])
        with btn_cols[0]:
            create_pr_disabled = len(included_names) == 0
            if st.button(
                "Create PR",
                type="primary",
                key="btn_create_pr",
                use_container_width=True,
                disabled=create_pr_disabled,
            ):
                payload: Dict[str, Any] = {
                    "decision": "approved",
                    "included_rule_names": included_names,
                }
                if feedback:
                    payload["feedback"] = feedback
                if rule_edits:
                    payload["rule_edits"] = rule_edits
                with st.spinner("Opening draft PR…"):
                    resp = _post(f"/tasks/{review_task_id}/review", payload)
                    if resp:
                        pr_url = resp.get("pr_url")
                        if pr_url:
                            st.session_state["last_pr_url"] = pr_url
                        # Fetch the final result so the report section
                        # renders on the post-rerun page.
                        task = _get(f"/tasks/{review_task_id}")
                        if task and task.get("result"):
                            st.session_state["pipeline_result"] = task["result"]
                if resp:
                    pr_error = resp.get("pr_error")
                    if not resp.get("pr_url"):
                        # Always surface *something* — no silent failures.
                        st.error(
                            "PR not created: "
                            + (pr_error or "unknown reason (check API logs)")
                        )
                    st.session_state["review_task_id"] = None
                    st.rerun()

        with btn_cols[1]:
            last_params = st.session_state.get("last_pipeline_params")
            if st.button(
                "Regenerate",
                key="btn_regenerate",
                use_container_width=True,
                disabled=not last_params,
                help="Discard these rules and re-run the pipeline on the same URL.",
            ):
                # First, clear the pending-review task server-side.
                payload = {"decision": "rejected"}
                if feedback:
                    payload["feedback"] = feedback
                _post(f"/tasks/{review_task_id}/review", payload)
                # Then kick off a fresh pipeline run with the original
                # params, steered by the engineer's improvement guidance.
                if last_params:
                    regen_params = dict(last_params)
                    if feedback:
                        regen_params["improvement_guidance"] = feedback
                    new_resp = _post("/analyze", regen_params)
                    if new_resp and new_resp.get("task_id"):
                        st.session_state["pipeline_task_id"] = new_resp["task_id"]
                        st.session_state["pipeline_result"] = None
                st.session_state["review_task_id"] = None
                st.rerun()


# ── Main Content ──────────────────────────────────────────────────────────────

# Persistent PR link banner — shows across all views until dismissed, so
# users always see the draft PR link after clicking Create PR, regardless
# of which view the post-click rerun lands on.
_pr_url_banner = st.session_state.get("last_pr_url")
if _pr_url_banner:
    banner_cols = st.columns([10, 1])
    with banner_cols[0]:
        st.success(f"Draft PR opened: [{_pr_url_banner}]({_pr_url_banner})")
    with banner_cols[1]:
        if st.button("✕", key="btn_dismiss_pr_banner", help="Dismiss"):
            st.session_state.pop("last_pr_url", None)
            st.rerun()

pipeline_result = st.session_state.get("pipeline_result")

if pipeline_result and not pipeline_result.get("error"):
    # ══════════════════════════════════════════════════════════════════════════
    #  PIPELINE REPORT — continuous scroll
    # ══════════════════════════════════════════════════════════════════════════
    if pipeline_result.get("error"):
        st.error(f"Pipeline error: {pipeline_result['error']}")
    else:
        iocs_data = pipeline_result.get("iocs", {})
        total_iocs = sum(len(v) for v in iocs_data.values() if isinstance(v, list))
        gaps = pipeline_result.get("coverage_gaps", [])
        rules = pipeline_result.get("rules", [])
        exact_gaps = [g for g in gaps if not g.get("fuzzy_match")]
        fuzzy_gaps = [g for g in gaps if g.get("fuzzy_match")]

        # ── Summary strip ────────────────────────────────────────────────────
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Threat Actor", pipeline_result.get("threat_actor") or "Unknown")
        c2.metric("IOCs Extracted", total_iocs)
        c3.metric("Rules Generated", len(rules))
        c4.metric(
            "Coverage Gaps",
            len(exact_gaps),
            delta=f"{len(fuzzy_gaps)} fuzzy" if fuzzy_gaps else None,
        )

        # ── Extracted IOCs (directly visible) ─────────────────────────────────
        # Fetch enriched IOC data from Redis (has first_seen timestamps)
        _actor = pipeline_result.get("threat_actor") or ""
        _enriched_iocs: Dict[str, Dict] = {}
        if _actor:
            try:
                _ioc_resp = requests.get(
                    f"{API_URL}/iocs", params={"actor": _actor, "limit": 200}, timeout=5
                )
                if _ioc_resp.ok:
                    for rec in _ioc_resp.json():
                        _enriched_iocs[rec.get("value", "")] = rec
            except Exception:
                pass

        st.markdown(
            '<div class="section-header">Extracted IOCs</div>',
            unsafe_allow_html=True,
        )
        if total_iocs == 0:
            st.caption("No IOCs extracted from this report.")
        else:
            active_types = [k for k, v in iocs_data.items() if v]
            ioc_cols = st.columns(min(len(active_types), 3))
            for col_idx, ioc_type in enumerate(active_types):
                values = iocs_data[ioc_type]
                with ioc_cols[col_idx % len(ioc_cols)]:
                    st.markdown(
                        f"{_ioc_type_badge(ioc_type)} "
                        f'<span style="color:#8b949e; font-size:0.85rem;">x{len(values)}</span>',
                        unsafe_allow_html=True,
                    )
                    for v in values[:10]:
                        enriched = _enriched_iocs.get(v, {})
                        ts = enriched.get("first_seen", "")
                        ts_label = _relative_time(ts) if ts else "just now"
                        st.markdown(
                            f'<div style="display:flex; align-items:baseline; gap:0.5rem;">'
                            f'<code style="font-size:0.85rem; color:#c9d1d9; '
                            f'word-break:break-all;">{v}</code>'
                            f'<span style="font-size:0.7rem; color:#484f58; '
                            f'white-space:nowrap;">{ts_label}</span></div>',
                            unsafe_allow_html=True,
                        )
                    if len(values) > 10:
                        st.caption(f"+ {len(values) - 10} more")
            st.caption("IOCs expire after 90 days")

        # ── Coverage Gaps (directly visible) ──────────────────────────────────
        gap_label = f"Coverage Gaps — {len(exact_gaps)} exact"
        if fuzzy_gaps:
            gap_label += f", {len(fuzzy_gaps)} fuzzy"
        st.markdown(
            f'<div class="section-header">{gap_label}</div>',
            unsafe_allow_html=True,
        )
        if not gaps:
            st.markdown(
                '<div style="color:#3fb950; font-size:0.88rem; padding:0.3rem 0;">'
                '✓ All techniques covered after rule generation.</div>',
                unsafe_allow_html=True,
            )
        else:
            rows = []
            for g in gaps:
                rows.append({
                    "TTP": g["technique_id"],
                    "Tactic": g["tactic"],
                    "Priority": g["priority"].upper(),
                    "Fuzzy": "~" if g.get("fuzzy_match") else "",
                    "TLSH Dist": int(g["fuzzy_score"]) if g.get("fuzzy_score") is not None else "",
                    "Data Sources": ", ".join(g.get("data_sources", [])[:2]),
                })
            st.dataframe(rows, use_container_width=True, hide_index=True)

        # ── Detection Rules (each rule collapsible) ───────────────────────────
        st.markdown(
            f'<div class="section-header">Detection Rules — {len(rules)} generated</div>',
            unsafe_allow_html=True,
        )
        if not rules:
            st.caption("No rules generated.")
        else:
            for i, rule in enumerate(rules):
                fmt = rule.get("format", "")
                name = rule.get("name", f"Rule {i + 1}")
                ttp_list = _parse_json_list(rule.get("ttps"))

                rule_header = (
                    f"{_fmt_badge(fmt)} "
                    f'<span style="font-weight:600; color:#e6edf3; font-size:0.88rem;">{name}</span>'
                )
                if ttp_list:
                    rule_header += "  " + " ".join(_ttp_badge(t) for t in ttp_list[:4])
                    if len(ttp_list) > 4:
                        rule_header += _pill(f"+{len(ttp_list)-4}", "#21262d", "#8b949e")

                with st.expander(f"[{fmt.upper()}] {name}", expanded=False):
                    st.markdown(rule_header, unsafe_allow_html=True)
                    st.markdown('<div style="height:0.4rem;"></div>', unsafe_allow_html=True)
                    edited = st.text_area(
                        "rule_content",
                        value=rule.get("rule_content", ""),
                        height=240,
                        key=f"rule_edit_{i}",
                        label_visibility="collapsed",
                    )
                    save_col, status_col = st.columns([1, 5])
                    with save_col:
                        if st.button("💾 Save", key=f"save_{i}"):
                            rule_id = rule.get("rule_id")
                            if rule_id:
                                resp = _put(f"/rules/{rule_id}", {"rule_content": edited})
                                with status_col:
                                    if resp:
                                        st.success("Saved.")
                                    else:
                                        st.error("Save failed.")
                            else:
                                with status_col:
                                    st.warning("No store ID — connect Redis to persist.")

        # ── Clear button ──────────────────────────────────────────────────────
        st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)
        if st.button("✕ Clear Results", key="btn_clear"):
            st.session_state["pipeline_result"] = None
            st.session_state.pop("last_pr_url", None)
            st.rerun()

elif pipeline_result and pipeline_result.get("error"):
    st.error(f"Pipeline error: {pipeline_result['error']}")
    if st.button("✕ Dismiss", key="btn_dismiss_err"):
        st.session_state["pipeline_result"] = None
        st.rerun()

else:
    # ══════════════════════════════════════════════════════════════════════════
    #  LANDING — AI Search front-and-center
    # ══════════════════════════════════════════════════════════════════════════

    # Metric strip
    actors = _load_actors()
    coverage = _load_coverage()

    # Aggregate counts from the API /stats endpoint.
    _stats: Dict[str, int] = {}
    try:
        _stats_resp = requests.get(f"{API_URL}/stats", timeout=5)
        _stats_resp.raise_for_status()
        _stats = _stats_resp.json() or {}
    except Exception:
        pass

    total_iocs = int(_stats.get("iocs") or 0) or sum(
        e.get("ioc_count", 0) for e in coverage
    )
    rules_sigma = int(_stats.get("rules_sigma") or 0)
    rules_ai = int(_stats.get("rules_ai_generated") or 0)

    # Still need merged_actors for the Actors Tracked delta.
    merged_actors: set = set()
    try:
        _rules_resp = requests.get(
            f"{API_URL}/rules", params={"limit": 1000}, timeout=5
        )
        _rules_resp.raise_for_status()
        for r in _rules_resp.json() or []:
            if (r.get("source_url") or "").startswith("github:"):
                _a = (r.get("threat_actor") or "").strip()
                if _a:
                    merged_actors.add(_a.lower())
    except Exception:
        pass

    c1, c2, c3 = st.columns(3)
    c1.metric(
        "Actors Tracked",
        len(actors),
        delta=f"+{len(merged_actors)} merged" if merged_actors else None,
    )
    c2.metric(
        "IOCs Tracked",
        total_iocs,
    )
    c3.metric(
        "Detection Rules",
        rules_sigma,
        delta=f"{rules_ai} AI-generated" if rules_ai else None,
    )

    st.markdown("<div style='height:1.2rem;'></div>", unsafe_allow_html=True)

    # ── AI Search ────────────────────────────────────────────────────────────
    st.markdown(
        '<div style="text-align:center; margin-bottom:0.3rem;">'
        '<span style="font-size:1.1rem; font-weight:700; color:#e6edf3;">'
        'Ask anything about your threat intel'
        '</span></div>',
        unsafe_allow_html=True,
    )

    # Example query chips (clickable buttons)
    _EXAMPLES = [
        "Top 10 TTPs covered",
        "Show coverage matrix",
        "Recently created rules",
        "Newly added reports",
        "Which actors are tracked?",
        "Most critical TTP gaps",
    ]

    # CSS to style chip buttons
    st.markdown(
        """
<style>
/* Chip-style buttons row */
div[data-testid="stHorizontalBlock"].chip-row button {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 16px !important;
    color: #8b949e !important;
    font-size: 0.72rem !important;
    padding: 4px 14px !important;
    font-weight: 500 !important;
}
div[data-testid="stHorizontalBlock"].chip-row button:hover {
    background: #1a3a5c !important;
    border-color: #79c0ff !important;
    color: #79c0ff !important;
}
div[data-testid="stHorizontalBlock"].chip-row button p {
    color: inherit !important;
    font-size: 0.72rem !important;
}
</style>
""",
        unsafe_allow_html=True,
    )

    # Initialize chat history and pending query
    if "ask_history" not in st.session_state:
        st.session_state["ask_history"] = []

    chip_cols = st.columns(len(_EXAMPLES))
    for idx, ex in enumerate(_EXAMPLES):
        with chip_cols[idx]:
            if st.button(ex, key=f"chip_{idx}", use_container_width=True):
                st.session_state["_pending_query"] = ex

    # Search input bar
    ask_left, ask_right = st.columns([6, 1])
    with ask_left:
        ask_query = st.text_input(
            "Search",
            placeholder="e.g. give me the top 5 TTPs, show all IOCs for apt28...",
            key="ask_input",
            label_visibility="collapsed",
        )
    with ask_right:
        ask_submit = st.button("Ask", type="primary", key="btn_ask", use_container_width=True)

    # Determine which query to run: typed + Ask, or clicked chip
    _pending = st.session_state.pop("_pending_query", None)
    _active_query = _pending or (ask_query.strip() if ask_submit else None)

    if _active_query:
        with st.spinner("Thinking..."):
            resp = _post("/ask", {"query": _active_query})
            if resp:
                st.session_state["ask_history"].insert(0, {
                    "query": _active_query,
                    "answer": resp.get("answer", "No answer returned."),
                    "tool": resp.get("tool_used"),
                    "data": resp.get("data"),
                })
            else:
                st.session_state["ask_history"].insert(0, {
                    "query": _active_query,
                    "answer": "Failed to get a response. Check API connection.",
                    "tool": None,
                    "data": None,
                })

    # Render conversation history
    for i, entry in enumerate(st.session_state.get("ask_history", [])):
        st.markdown(
            f'<div style="display:flex; justify-content:flex-end; margin:0.6rem 0 0.2rem;">'
            f'<div style="background:#1a3a5c; border-radius:14px 14px 2px 14px; '
            f'padding:10px 16px; max-width:70%; font-size:0.85rem; color:#79c0ff;">'
            f'{entry["query"]}</div></div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'<div style="background:#161b22; border:1px solid #21262d; border-radius:2px 14px 14px 14px; '
            f'padding:14px 18px; margin:0.2rem 0 0.1rem; font-size:0.85rem; color:#c9d1d9; '
            f'line-height:1.6;">{_md_to_html(entry["answer"])}</div>',
            unsafe_allow_html=True,
        )
        if entry.get("tool"):
            st.markdown(
                f'<div style="font-size:0.65rem; color:#484f58; margin:0 0 0.6rem 4px;">'
                f'via {entry["tool"]}</div>',
                unsafe_allow_html=True,
            )

    # Clear history button (only if there's history)
    if st.session_state.get("ask_history"):
        if st.button("Clear history", key="btn_ask_clear"):
            st.session_state["ask_history"] = []
            st.rerun()

