"""
Kitsune Search UI — Streamlit frontend for the Redis threat intel store.

Run with:
    streamlit run ui.py

Requires the Kitsune API to be running at http://localhost:8000
(or set KITSUNE_API_URL env var to override).
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
import streamlit as st

API_URL = os.getenv("KITSUNE_API_URL", "http://localhost:8000").rstrip("/")

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Kitsune Threat Intel",
    page_icon="🦊",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Header ────────────────────────────────────────────────────────────────────

header_left, header_right = st.columns([6, 1])
with header_left:
    st.title("🦊 Kitsune Threat Intel Search")
    st.caption("Query IOCs, detection rules, and threat actor data from the Redis store.")
with header_right:
    st.markdown(
        f"""
        <div style="text-align:right; padding-top:1.4rem;">
            <a href="{API_URL}/docs" target="_blank"
               style="background:#ff4b4b; color:white; padding:0.45rem 1rem;
                      border-radius:6px; text-decoration:none; font-weight:600;
                      font-size:0.9rem;">
                📄 API Docs
            </a>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.divider()

# ── Helpers ───────────────────────────────────────────────────────────────────


def _get(endpoint: str, params: Optional[Dict] = None) -> Any:
    """Call the Kitsune API and return parsed JSON, or None on error."""
    try:
        resp = requests.get(f"{API_URL}{endpoint}", params=params, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error(
            f"Cannot reach API at **{API_URL}**. "
            "Is `uvicorn api:app --port 8000` running?"
        )
        return None
    except requests.exceptions.HTTPError as e:
        detail = ""
        try:
            detail = e.response.json().get("detail", "")
        except Exception:
            pass
        st.error(f"API error {e.response.status_code}: {detail or str(e)}")
        return None


def _fmt_ts(ts: Optional[str]) -> str:
    """Convert a Unix timestamp string to a readable date."""
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError):
        return ts


def _parse_json_list(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return [raw]


def _badge(text: str, color: str = "#444") -> str:
    return (
        f'<span style="background:{color}; color:white; border-radius:4px; '
        f'padding:2px 7px; font-size:0.78rem; margin:1px 2px; '
        f'display:inline-block;">{text}</span>'
    )


def _ttp_badge(ttp: str) -> str:
    return _badge(ttp, "#1a6fb5")


def _actor_badge(actor: str) -> str:
    return _badge(actor, "#6b3fa0")


# ── Redis health indicator in sidebar ────────────────────────────────────────

health = _get("/")
if health:
    redis_ok = health.get("redis") == "connected"
    st.sidebar.markdown(
        f"**Redis:** {'🟢 Connected' if redis_ok else '🔴 Unavailable'}"
    )
    st.sidebar.markdown(f"**API:** {API_URL}")

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_ioc, tab_rules, tab_actors, tab_trends, tab_coverage = st.tabs(
    ["🔍 IOC Search", "📋 Detection Rules", "👤 Actor Summary", "📈 Trends", "🗺️ Coverage"]
)

# ── IOC Search ────────────────────────────────────────────────────────────────

with tab_ioc:
    st.subheader("IOC Search")
    col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
    with col1:
        ioc_actor = st.text_input("Threat Actor", placeholder="e.g. apt28", key="ioc_actor")
    with col2:
        ioc_ttp = st.text_input("TTP (MITRE)", placeholder="e.g. T1059", key="ioc_ttp")
    with col3:
        ioc_type = st.selectbox(
            "IOC Type",
            ["(all)", "ip", "domain", "hash", "file", "url"],
            key="ioc_type",
        )
    with col4:
        ioc_limit = st.number_input("Limit", min_value=1, max_value=1000, value=50, key="ioc_limit")

    if st.button("Search IOCs", type="primary", key="btn_ioc"):
        params: Dict[str, Any] = {"limit": ioc_limit}
        if ioc_actor.strip():
            params["actor"] = ioc_actor.strip()
        if ioc_ttp.strip():
            params["ttp"] = ioc_ttp.strip().upper()
        if ioc_type != "(all)":
            params["ioc_type"] = ioc_type

        with st.spinner("Querying…"):
            data = _get("/iocs", params)

        if data is not None:
            if not data:
                st.info("No IOCs found for the given filters.")
            else:
                st.success(f"Found **{len(data)}** IOC(s)")
                rows = []
                for ioc in data:
                    rows.append(
                        {
                            "Type": ioc.get("type", ""),
                            "Value": ioc.get("value", ""),
                            "First Seen": _fmt_ts(ioc.get("first_seen")),
                            "Last Seen": _fmt_ts(ioc.get("last_seen")),
                            "Actors": ", ".join(_parse_json_list(ioc.get("threat_actors"))),
                            "TTPs": ", ".join(_parse_json_list(ioc.get("ttps"))),
                            "Campaigns": ", ".join(_parse_json_list(ioc.get("campaigns"))),
                            "Sources": len(_parse_json_list(ioc.get("source_urls"))),
                        }
                    )
                st.dataframe(rows, use_container_width=True)

# ── Detection Rules ───────────────────────────────────────────────────────────

with tab_rules:
    st.subheader("Detection Rule Search")
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        rule_actor = st.text_input("Threat Actor", placeholder="e.g. apt28", key="rule_actor")
    with col2:
        rule_ttp = st.text_input("TTP (MITRE)", placeholder="e.g. T1059", key="rule_ttp")
    with col3:
        rule_limit = st.number_input("Limit", min_value=1, max_value=1000, value=25, key="rule_limit")

    if st.button("Search Rules", type="primary", key="btn_rules"):
        params = {"limit": rule_limit}
        if rule_actor.strip():
            params["actor"] = rule_actor.strip()
        if rule_ttp.strip():
            params["ttp"] = rule_ttp.strip().upper()

        with st.spinner("Querying…"):
            data = _get("/rules", params)

        if data is not None:
            if not data:
                st.info("No rules found for the given filters.")
            else:
                st.success(f"Found **{len(data)}** rule(s)")
                for rule in data:
                    ttps = _parse_json_list(rule.get("ttps"))
                    ttp_html = " ".join(_ttp_badge(t) for t in ttps)
                    with st.expander(
                        f"[{rule.get('format', '').upper()}] {rule.get('name', 'Unknown')}",
                        expanded=False,
                    ):
                        meta_col, _ = st.columns([3, 1])
                        with meta_col:
                            st.markdown(
                                f"**Actor:** {rule.get('threat_actor', '—')}  \n"
                                f"**Created:** {_fmt_ts(rule.get('created_at'))}  \n"
                                f"**Source:** {rule.get('source_url', '—')}  \n"
                                f"**TTPs:** {ttp_html if ttp_html else '—'}",
                                unsafe_allow_html=True,
                            )

# ── Actor Summary ─────────────────────────────────────────────────────────────

with tab_actors:
    st.subheader("Actor Summary")

    # Load actor list for dropdown
    actor_list = _get("/actors") or []
    actor_options = ["(type or select)"] + sorted(actor_list)

    col1, col2 = st.columns([3, 1])
    with col1:
        actor_select = st.selectbox("Select Actor", actor_options, key="actor_select")
        actor_manual = st.text_input(
            "Or type actor name manually", placeholder="e.g. UNC6395", key="actor_manual"
        )
    with col2:
        st.write("")
        st.write("")
        run_actor = st.button("Get Summary", type="primary", key="btn_actor")

    if run_actor:
        chosen = actor_manual.strip() or (
            actor_select if actor_select != "(type or select)" else ""
        )
        if not chosen:
            st.warning("Please select or enter an actor name.")
        else:
            with st.spinner(f"Loading summary for {chosen}…"):
                summary = _get(f"/actors/{requests.utils.quote(chosen)}/summary")
            if summary:
                c1, c2, c3 = st.columns(3)
                c1.metric("Total IOCs", summary.get("total_iocs", 0))
                c2.metric("Detection Rules", summary.get("total_rules", 0))
                c3.metric("Campaigns", len(summary.get("campaigns", [])))

                ttps = summary.get("ttps", [])
                camps = summary.get("campaigns", [])
                ioc_counts = summary.get("ioc_counts", {})

                col_l, col_r = st.columns(2)
                with col_l:
                    st.markdown("**IOC Breakdown**")
                    if ioc_counts:
                        st.bar_chart(ioc_counts)
                    else:
                        st.caption("No IOCs.")

                with col_r:
                    st.markdown("**Associated TTPs**")
                    if ttps:
                        st.markdown(
                            " ".join(_ttp_badge(t) for t in ttps),
                            unsafe_allow_html=True,
                        )
                    else:
                        st.caption("None recorded.")

                    st.markdown("**Campaigns**")
                    if camps:
                        for c in camps:
                            st.markdown(f"- {c}")
                    else:
                        st.caption("None recorded.")

# ── Trending TTPs ─────────────────────────────────────────────────────────────

with tab_trends:
    st.subheader("Trending MITRE ATT&CK Techniques")
    top_n = st.slider("Top N", min_value=5, max_value=50, value=10, key="trend_n")

    if st.button("Load Trends", type="primary", key="btn_trends"):
        with st.spinner("Loading…"):
            trends = _get("/trends", {"top": top_n})
        if trends:
            if not trends:
                st.info("No trend data yet.")
            else:
                chart_data = {t["ttp_id"]: t["count"] for t in trends}
                st.bar_chart(chart_data)
                st.dataframe(
                    [{"TTP": t["ttp_id"], "Frequency": t["count"]} for t in trends],
                    use_container_width=True,
                )

# ── Coverage ──────────────────────────────────────────────────────────────────

with tab_coverage:
    st.subheader("TTP Coverage Report")
    st.caption(
        "Shows which MITRE ATT&CK techniques have associated IOCs and/or "
        "detection rules in the store."
    )

    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        coverage_filter = st.selectbox(
            "Show",
            ["All", "Missing rules", "Missing IOCs", "Fully covered", "No coverage"],
            key="cov_filter",
        )
    with filter_col2:
        st.write("")

    if st.button("Load Coverage", type="primary", key="btn_coverage"):
        with st.spinner("Loading…"):
            coverage = _get("/coverage")
        if coverage:
            if not coverage:
                st.info("No coverage data yet.")
            else:
                # Apply filter
                def _keep(entry: Dict) -> bool:
                    if coverage_filter == "Missing rules":
                        return not entry["has_rules"]
                    if coverage_filter == "Missing IOCs":
                        return not entry["has_iocs"]
                    if coverage_filter == "Fully covered":
                        return entry["has_rules"] and entry["has_iocs"]
                    if coverage_filter == "No coverage":
                        return not entry["has_rules"] and not entry["has_iocs"]
                    return True

                filtered = [e for e in coverage if _keep(e)]
                st.success(
                    f"Showing **{len(filtered)}** of **{len(coverage)}** techniques"
                )
                rows = [
                    {
                        "TTP": e["ttp_id"],
                        "Has IOCs": "✅" if e["has_iocs"] else "❌",
                        "IOC Count": e["ioc_count"],
                        "Has Rules": "✅" if e["has_rules"] else "❌",
                        "Rule Count": e["rule_count"],
                    }
                    for e in filtered
                ]
                st.dataframe(rows, use_container_width=True)
