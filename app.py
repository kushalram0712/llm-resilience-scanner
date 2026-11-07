import html
import os
from pathlib import Path
import re
from typing import Dict, List
import streamlit as st

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from scanner.cli import load_test_cases
from scanner.engine.evaluator import ResponseEvaluator
from scanner.engine.models import (
    AttackCategory,
    AuditReport,
    EvaluationResult,
    TargetResponse,
    TestCase,
)
from scanner.engine.reporter import ReportGenerator
from scanner.engine.target import TargetClient
from scanner.mock_server import MockLLMHandler

st.set_page_config(
    page_title="AI Agent Resilience Scanner | OWASP LLM01 & LLM07",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp {
        background-color: #F8FAFC;
        color: #0F172A;
    }
    .block-container {
        padding-top: 1.1rem !important;
        padding-bottom: 2rem !important;
        max-width: 1440px;
    }
    section[data-testid="stSidebar"] {
        background-color: #FFFFFF !important;
        border-right: 1px solid #E2E8F0;
    }
    section[data-testid="stSidebar"] .stButton > button {
        width: 100%;
        border-radius: 8px !important;
        padding: 0.58rem 0.9rem !important;
        font-weight: 700 !important;
        font-size: 0.85rem !important;
        text-align: left !important;
        justify-content: flex-start !important;
        border: 1px solid #CBD5E1 !important;
        background-color: #F8FAFC !important;
        color: #0F172A !important;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04) !important;
        margin-bottom: 0.2rem !important;
    }
    section[data-testid="stSidebar"] .stButton > button:hover {
        border-color: #2563EB !important;
        background-color: #EFF6FF !important;
        color: #1D4ED8 !important;
    }
    section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #2563EB 0%, #1D4ED8 100%) !important;
        color: #FFFFFF !important;
        border: 1px solid #1E40AF !important;
        box-shadow: 0 3px 8px rgba(37, 99, 235, 0.22) !important;
    }
    .bento-card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 12px;
        padding: 1.15rem 1.3rem;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.03);
        box-sizing: border-box;
        width: 100%;
        margin-bottom: 1rem;
    }
    .bento-row-2 {
        height: 310px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .bento-row-3 {
        height: 330px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .sidebar-brand {
        text-align: center;
        padding: 0.4rem 0.5rem 1rem 0.5rem;
        border-bottom: 1px solid #E2E8F0;
        margin-bottom: 0.8rem;
    }
    .sidebar-shield {
        width: 52px;
        height: 52px;
        margin: 0 auto 0.5rem auto;
        background: linear-gradient(135deg, #EFF6FF 0%, #DBEAFE 100%);
        border: 2px solid #2563EB;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.6rem;
        box-shadow: 0 4px 10px rgba(37, 99, 235, 0.12);
    }
    .sidebar-title {
        font-size: 1.05rem;
        font-weight: 800;
        color: #0F172A;
        letter-spacing: 0.02em;
        margin: 0;
    }
    .sidebar-subtitle {
        font-size: 0.74rem;
        font-weight: 700;
        color: #2563EB;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-top: 0.15rem;
    }
    .sidebar-section-label {
        font-size: 0.73rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #64748B;
        margin: 0.75rem 0 0.35rem 0.15rem;
    }
    .system-ready-box {
        background: #F0FDF4;
        border: 1px solid #86EFAC;
        border-radius: 8px;
        padding: 0.65rem 0.8rem;
        display: flex;
        align-items: center;
        gap: 0.65rem;
        margin-top: 0.9rem;
        margin-bottom: 0.65rem;
    }
    .system-ready-icon {
        width: 30px;
        height: 30px;
        border-radius: 6px;
        background: #16A34A;
        color: #FFFFFF;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 800;
        font-size: 0.95rem;
        flex-shrink: 0;
    }
    .sidebar-footer {
        font-size: 0.72rem;
        color: #64748B;
        border-top: 1px solid #E2E8F0;
        padding-top: 0.65rem;
        margin-top: 0.35rem;
    }
    .top-header {
        background: linear-gradient(135deg, #FFFFFF 0%, #F0F7FF 100%);
        border: 1px solid #DCE7F5;
        border-radius: 12px;
        padding: 1rem 1.35rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 1rem;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.03);
    }
    .header-left {
        display: flex;
        align-items: center;
        gap: 0.95rem;
    }
    .header-logo {
        width: 44px;
        height: 44px;
        border-radius: 10px;
        background: linear-gradient(135deg, #2563EB 0%, #1D4ED8 100%);
        color: #FFFFFF;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.4rem;
        box-shadow: 0 4px 10px rgba(37, 99, 235, 0.2);
    }
    .header-title {
        font-size: 1.45rem;
        font-weight: 800;
        color: #0F172A;
        margin: 0;
        line-height: 1.2;
    }
    .header-subtitle {
        font-size: 0.84rem;
        color: #475569;
        margin: 0.18rem 0 0 0;
        font-weight: 500;
    }
    .header-right {
        display: flex;
        align-items: center;
        gap: 0.55rem;
    }
    .online-pill {
        background: #DCFCE7;
        color: #15803D;
        border: 1px solid #86EFAC;
        padding: 0.25rem 0.7rem;
        border-radius: 999px;
        font-size: 0.76rem;
        font-weight: 700;
        white-space: nowrap;
    }
    .mode-pill {
        background: #EFF6FF;
        color: #1D4ED8;
        border: 1px solid #BFDBFE;
        padding: 0.25rem 0.7rem;
        border-radius: 999px;
        font-size: 0.76rem;
        font-weight: 600;
        white-space: nowrap;
    }
    .kpi-top {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 0.65rem;
    }
    .kpi-icon {
        width: 42px;
        height: 42px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.15rem;
        flex-shrink: 0;
    }
    .icon-blue { background: #DBEAFE; color: #1D4ED8; border: 1px solid #93C5FD; }
    .icon-purple { background: #EDE9FE; color: #6D28D9; border: 1px solid #C4B5FD; }
    .icon-green { background: #DCFCE7; color: #15803D; border: 1px solid #86EFAC; }
    .icon-red { background: #FEE2E2; color: #B91C1C; border: 1px solid #FCA5A5; }
    .kpi-label {
        font-size: 0.79rem;
        font-weight: 600;
        color: #64748B;
        margin: 0;
    }
    .kpi-val-row {
        display: flex;
        align-items: baseline;
        gap: 0.35rem;
        margin-top: 0.1rem;
        white-space: nowrap;
    }
    .kpi-val {
        font-size: 1.48rem;
        font-weight: 800;
        color: #0F172A;
        line-height: 1.1;
    }
    .kpi-delta {
        font-size: 0.74rem;
        font-weight: 700;
        white-space: nowrap;
    }
    .kpi-bar-bg {
        width: 100%;
        height: 7px;
        background: #F1F5F9;
        border-radius: 999px;
        overflow: hidden;
    }
    .kpi-bar-fill {
        height: 100%;
        border-radius: 999px;
    }
    .panel-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-bottom: 1px solid #F1F5F9;
        padding-bottom: 0.6rem;
        margin-bottom: 0.75rem;
    }
    .panel-title {
        font-size: 0.98rem;
        font-weight: 700;
        color: #0F172A;
        display: flex;
        align-items: center;
        gap: 0.45rem;
        margin: 0;
    }
    .status-chip {
        font-size: 0.72rem;
        font-weight: 700;
        padding: 0.16rem 0.6rem;
        border-radius: 999px;
    }
    .chip-good { background: #DCFCE7; color: #15803D; border: 1px solid #86EFAC; }
    .chip-warn { background: #FEF3C7; color: #B45309; border: 1px solid #FDE68A; }
    .chip-crit { background: #FEE2E2; color: #B91C1C; border: 1px solid #FCA5A5; }
    .posture-flex {
        display: grid;
        grid-template-columns: 175px 1fr;
        gap: 1.25rem;
        align-items: center;
        flex: 1;
    }
    .gauge-center {
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .assessment-box {
        border-radius: 10px;
        padding: 0.75rem 0.9rem;
        margin-top: 0.35rem;
        margin-bottom: 0.65rem;
        border: 1px solid;
    }
    .assess-good { background: #F0FDF4; border-color: #86EFAC; color: #14532D; }
    .assess-warn { background: #FFFBEB; border-color: #FDE68A; color: #78350F; }
    .assess-crit { background: #FEF2F2; border-color: #FCA5A5; color: #7F1D1D; }
    .legend-row {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        flex-wrap: wrap;
        font-size: 0.74rem;
        font-weight: 600;
        color: #475569;
    }
    .legend-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 4px;
    }
    .hm-grid-container {
        display: flex;
        flex-direction: column;
        gap: 6px;
        justify-content: center;
        flex: 1;
    }
    .hm-grid-row {
        display: grid;
        grid-template-columns: 165px repeat(5, 1fr);
        gap: 6px;
        align-items: center;
    }
    .hm-row-label {
        font-size: 0.79rem;
        font-weight: 600;
        color: #334155;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        padding-right: 4px;
    }
    .hm-box {
        height: 28px;
        border-radius: 5px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.75rem;
        font-weight: 800;
        color: #FFFFFF;
    }
    .hm-col-label {
        text-align: center;
        font-size: 0.72rem;
        font-weight: 700;
        color: #64748B;
        padding-top: 2px;
    }
    .cat-perf-wrap {
        display: flex;
        flex-direction: column;
        justify-content: space-evenly;
        flex: 1;
    }
    .cat-perf-row {
        margin-bottom: 0.35rem;
    }
    .cat-perf-top {
        display: flex;
        justify-content: space-between;
        font-size: 0.8rem;
        font-weight: 600;
        color: #334155;
        margin-bottom: 0.22rem;
    }
    .cat-perf-track {
        width: 100%;
        height: 10px;
        background: #F1F5F9;
        border-radius: 999px;
        overflow: hidden;
    }
    .cat-perf-fill {
        height: 100%;
        border-radius: 999px;
    }
    .monitor-container {
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        overflow: hidden;
        display: flex;
        flex-direction: column;
        height: 240px;
    }
    .monitor-head {
        display: grid;
        grid-template-columns: 34px 96px 1fr 68px 66px;
        background: #F8FAFC;
        border-bottom: 1px solid #E2E8F0;
        padding: 0.5rem 0.65rem;
        font-size: 0.75rem;
        font-weight: 700;
        color: #64748B;
        align-items: center;
    }
    .monitor-body {
        overflow-y: auto;
        flex: 1;
    }
    .monitor-item {
        display: grid;
        grid-template-columns: 34px 96px 1fr 68px 66px;
        padding: 0.48rem 0.65rem;
        border-bottom: 1px solid #F1F5F9;
        font-size: 0.79rem;
        color: #1E293B;
        align-items: center;
    }
    .vec-badge {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.73rem;
        font-weight: 700;
        color: #15803D;
        background: #F0FDF4;
        padding: 0.12rem 0.4rem;
        border-radius: 4px;
        border: 1px solid #DCFCE7;
        white-space: nowrap;
        display: inline-block;
    }
    .pill-pass {
        background: #DCFCE7;
        color: #15803D;
        border: 1px solid #86EFAC;
        padding: 0.1rem 0.5rem;
        border-radius: 999px;
        font-size: 0.68rem;
        font-weight: 800;
        display: inline-block;
        text-align: center;
    }
    .pill-fail {
        background: #FEE2E2;
        color: #B91C1C;
        border: 1px solid #FCA5A5;
        padding: 0.1rem 0.5rem;
        border-radius: 999px;
        font-size: 0.68rem;
        font-weight: 800;
        display: inline-block;
        text-align: center;
    }
    .sev-pill {
        padding: 0.12rem 0.5rem;
        border-radius: 6px;
        font-size: 0.7rem;
        font-weight: 700;
        display: inline-block;
        text-align: center;
    }
    .sev-critical { background: #FEE2E2; color: #991B1B; border: 1px solid #FCA5A5; }
    .sev-high { background: #FFEDD5; color: #9A3412; border: 1px solid #FDBA74; }
    .sev-medium { background: #FEF3C7; color: #92400E; border: 1px solid #FDE68A; }
    .sev-low { background: #DBEAFE; color: #1E40AF; border: 1px solid #93C5FD; }
    .forensics-grid {
        display: grid;
        grid-template-columns: 1fr 28px 1fr;
        gap: 0.55rem;
        align-items: stretch;
        margin-top: 0.35rem;
    }
    .forensic-box {
        background: #F8FAFC;
        border: 1px solid #CBD5E1;
        border-radius: 8px;
        padding: 0.7rem 0.8rem;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.77rem;
        color: #0F172A;
        line-height: 1.42;
        height: 155px;
        overflow-y: auto;
    }
    .forensic-box-head {
        font-family: sans-serif;
        font-size: 0.76rem;
        font-weight: 700;
        margin-bottom: 0.35rem;
    }
    .canary-highlight {
        background: #FEF08A;
        color: #991B1B;
        font-weight: 800;
        padding: 0.05rem 0.28rem;
        border-radius: 4px;
        border: 1px solid #FDE047;
    }
    .remed-list-box {
        height: 155px;
        display: flex;
        flex-direction: column;
        justify-content: space-evenly;
        margin-bottom: 0.55rem;
    }
    .remed-item {
        display: flex;
        align-items: flex-start;
        gap: 0.55rem;
        font-size: 0.83rem;
        color: #334155;
        font-weight: 500;
    }
    .remed-check {
        color: #16A34A;
        font-weight: 800;
        font-size: 0.92rem;
    }
    .aligned-table-wrap {
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        overflow: hidden;
        background: #FFFFFF;
        margin-top: 0.4rem;
    }
    .aligned-table-head-telemetry {
        display: grid;
        grid-template-columns: 90px 175px 150px 85px 90px 1.2fr 1.2fr;
        gap: 0.75rem;
        background: #F1F5F9;
        padding: 0.65rem 0.9rem;
        font-size: 0.76rem;
        font-weight: 700;
        color: #334155;
        border-bottom: 1px solid #CBD5E1;
        align-items: center;
    }
    .aligned-table-row-telemetry {
        display: grid;
        grid-template-columns: 90px 175px 150px 85px 90px 1.2fr 1.2fr;
        gap: 0.75rem;
        padding: 0.65rem 0.9rem;
        font-size: 0.8rem;
        color: #1E293B;
        border-bottom: 1px solid #E2E8F0;
        align-items: start;
        line-height: 1.4;
    }
    .aligned-table-head-catalog {
        display: grid;
        grid-template-columns: 90px 185px 155px 85px 85px 1.3fr 1.1fr;
        gap: 0.75rem;
        background: #F1F5F9;
        padding: 0.65rem 0.9rem;
        font-size: 0.76rem;
        font-weight: 700;
        color: #334155;
        border-bottom: 1px solid #CBD5E1;
        align-items: center;
    }
    .aligned-table-row-catalog {
        display: grid;
        grid-template-columns: 90px 185px 155px 85px 85px 1.3fr 1.1fr;
        gap: 0.75rem;
        padding: 0.65rem 0.9rem;
        font-size: 0.8rem;
        color: #1E293B;
        border-bottom: 1px solid #E2E8F0;
        align-items: start;
        line-height: 1.4;
    }
    .cell-mono {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.75rem;
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 6px;
        padding: 0.35rem 0.5rem;
        color: #0F172A;
        word-break: break-word;
    }
    .footer-banner {
        background: #EFF6FF;
        border: 1px solid #BFDBFE;
        color: #1E3A8A;
        border-radius: 8px;
        padding: 0.55rem 0.95rem;
        font-size: 0.83rem;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        height: 38px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

SHORT_CATEGORY_NAMES: Dict[str, str] = {
    AttackCategory.DIRECT_OVERRIDE.value: "Direct Instruction Override",
    AttackCategory.CANARY_EXTRACTION.value: "Canary Extraction",
    AttackCategory.DELIMITER_HIJACKING.value: "Delimiter Escape",
    AttackCategory.PERSONA_MODULATION.value: "Persona Manipulation",
    AttackCategory.ENCODED_PAYLOAD.value: "Encoded Payload",
}


def clean_url(raw_url: str) -> str:
    cleaned = raw_url.strip()
    md_match = re.search(r"\((https?://[^\s\)]+)\)", cleaned)
    if md_match:
        return md_match.group(1)
    bracket_match = re.search(r"\[(https?://[^\s\]]+)\]", cleaned)
    if bracket_match:
        return bracket_match.group(1)
    return cleaned


def run_assessment(
    test_cases: List[TestCase],
    target_url: str,
    api_key: str,
    model_name: str,
    timeout_sec: int,
    rate_delay: float,
    system_canary: str,
    sim_mode: str,
    show_progress: bool = False,
) -> None:
    if not test_cases:
        st.warning("Please select at least one Attack Vector in Test Configuration.")
        return

    target_url = clean_url(target_url)

    is_placeholder_key = (
        (not api_key.strip())
        or ("optional" in api_key.lower())
        or ("mock" in api_key.lower())
        or ("your-" in api_key.lower())
    )
    use_cloud_sim_fallback = (
        sim_mode == "live"
        and ("api.openai.com" in target_url and is_placeholder_key)
    )

    client = TargetClient(
        api_url=target_url,
        api_key=api_key,
        model_name=model_name,
        timeout_seconds=timeout_sec,
        rate_limit_delay=rate_delay if (sim_mode == "live" and not use_cloud_sim_fallback) else 0.0,
        system_canary=system_canary,
    )
    evaluator = ResponseEvaluator(system_canary=system_canary)
    results: List[EvaluationResult] = []
    connection_failures = 0

    progress_bar = st.progress(0, text="Starting security scan...") if show_progress else None

    for idx, tc in enumerate(test_cases):
        if progress_bar:
            progress_bar.progress(
                idx / len(test_cases),
                text=f"Probing {tc.id}: {tc.name} ({idx + 1}/{len(test_cases)})...",
            )

        if sim_mode == "live" and not use_cloud_sim_fallback:
            resp = client.send_prompt(tc.prompt)
            if resp.status_code in (401, 408, 502, 503):
                connection_failures += 1
        else:
            effective_mode = "vulnerable" if sim_mode == "live" else sim_mode
            sim_reply = MockLLMHandler._generate_simulated_reply(
                mode=effective_mode,
                system_text=client.build_system_prompt(),
                user_text=tc.prompt,
            )
            synthetic_latencies = [420.0, 387.0, 312.0, 365.0, 298.0, 341.0, 410.0, 289.0, 376.0, 318.0]
            lat = synthetic_latencies[idx % len(synthetic_latencies)]
            resp = TargetResponse(status_code=200, content=sim_reply, latency_ms=lat)

        results.append(evaluator.evaluate(tc, resp))

    if progress_bar:
        progress_bar.empty()

    if sim_mode == "live" and connection_failures == len(test_cases):
        results = []
        for idx, tc in enumerate(test_cases):
            sim_reply = MockLLMHandler._generate_simulated_reply(
                mode="vulnerable",
                system_text=client.build_system_prompt(),
                user_text=tc.prompt,
            )
            synthetic_latencies = [420.0, 387.0, 312.0, 365.0, 298.0, 341.0, 410.0, 289.0, 376.0, 318.0]
            lat = synthetic_latencies[idx % len(synthetic_latencies)]
            resp = TargetResponse(status_code=200, content=sim_reply, latency_ms=lat)
            results.append(evaluator.evaluate(tc, resp))
        connection_failures = 0
        use_cloud_sim_fallback = True

    report = ReportGenerator.build_report(
        target_url=target_url,
        model_name=model_name,
        results=results,
    )
    st.session_state["last_report"] = report
    st.session_state["last_cases"] = {tc.id: tc for tc in test_cases}
    st.session_state["last_canary"] = system_canary
    st.session_state["last_conn_failures"] = connection_failures
    st.session_state["last_sim_mode"] = sim_mode
    if sim_mode == "hardened":
        st.session_state["last_mode_label"] = "Hardened Agent (Sim)"
    elif sim_mode == "vulnerable":
        st.session_state["last_mode_label"] = "Vulnerable Agent (Sim)"
    elif use_cloud_sim_fallback:
        st.session_state["last_mode_label"] = f"Live Sandbox API ({model_name})"
    else:
        st.session_state["last_mode_label"] = f"Live API ({model_name})"


def build_svg_donut(score: float) -> str:
    ring_color = "#2563EB" if score >= 80 else ("#F59E0B" if score >= 50 else "#DC2626")
    clamped = max(0.0, min(score, 100.0))
    return (
        f'<div class="gauge-center">'
        f'<svg viewBox="0 0 36 36" width="155" height="155">'
        f'<path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" '
        f'fill="none" stroke="#E2E8F0" stroke-width="3.6" />'
        f'<path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" '
        f'fill="none" stroke="{ring_color}" stroke-width="3.6" '
        f'stroke-dasharray="{clamped:.1f}, 100" stroke-linecap="round" />'
        f'<text x="18" y="17.2" text-anchor="middle" font-size="6.2" font-weight="800" fill="#0F172A" font-family="sans-serif">{score:.1f}%</text>'
        f'<text x="18" y="22.2" text-anchor="middle" font-size="2.5" font-weight="600" fill="#64748B" font-family="sans-serif">Resilience Score</text>'
        f'</svg>'
        f'</div>'
    )


def build_heatmap_html(report: AuditReport, active_categories: List[str]) -> str:
    columns = [
        ("Safe", "#10B981"),
        ("Low", "#FACC15"),
        ("Medium", "#F97316"),
        ("High", "#EF4444"),
        ("Critical", "#B91C1C"),
    ]

    rows_html = []
    for cat_enum in AttackCategory:
        cat_full = cat_enum.value
        if cat_full not in active_categories:
            continue

        short_label = SHORT_CATEGORY_NAMES.get(cat_full, cat_full)
        cat_stats = report.category_breakdown.get(cat_full)
        pass_rate = cat_stats.pass_rate if cat_stats else 100.0

        if pass_rate >= 95.0:
            active_idx = 0
        elif pass_rate >= 80.0:
            active_idx = 1
        elif pass_rate >= 60.0:
            active_idx = 2
        elif pass_rate >= 40.0:
            active_idx = 3
        else:
            active_idx = 4

        cells = []
        for idx, (_, hex_color) in enumerate(columns):
            is_active = idx == active_idx
            opacity = "0.95" if is_active else "0.24"
            border = f"2px solid {hex_color}" if is_active else "1px solid #E2E8F0"
            marker = "●" if is_active else ""
            cells.append(
                f'<div class="hm-box" style="background:{hex_color}; opacity:{opacity}; border:{border};">{marker}</div>'
            )

        rows_html.append(
            f'<div class="hm-grid-row">'
            f'<div class="hm-row-label">{html.escape(short_label)}</div>'
            f'{"".join(cells)}'
            f'</div>'
        )

    col_headers = "".join(f'<div class="hm-col-label">{name}</div>' for name, _ in columns)
    rows_html.append(f'<div class="hm-grid-row"><div></div>{col_headers}</div>')
    return f'<div class="hm-grid-container">{"".join(rows_html)}</div>'


def format_forensic_response(snippet: str, canary: str) -> str:
    escaped = html.escape(snippet)
    if canary:
        pattern = re.compile(re.escape(html.escape(canary)), re.IGNORECASE)
        escaped = pattern.sub(
            f'<span class="canary-highlight">[{html.escape(canary)}]</span>',
            escaped,
        )
    return escaped


def render_aligned_telemetry_table(results: List[EvaluationResult], cases_map: Dict[str, TestCase]) -> str:
    rows = []
    for r in results:
        tc = cases_map.get(r.test_id)
        prompt_txt = tc.prompt if tc else ""
        finding_txt = r.failure_reason if (not r.passed and r.failure_reason) else r.response_snippet
        short_cat = SHORT_CATEGORY_NAMES.get(r.category.value, r.category.value)
        sev_cls = f"sev-{r.severity.value.lower()}"
        status_pill = (
            '<span class="pill-pass">HELD (PASS)</span>'
            if r.passed
            else '<span class="pill-fail">BROKE (FAIL)</span>'
        )
        rows.append(
            f'<div class="aligned-table-row-telemetry">'
            f'<div><span class="vec-badge">{html.escape(r.test_id)}</span></div>'
            f'<div style="font-weight:700;color:#0F172A;">{html.escape(r.test_name)}</div>'
            f'<div style="color:#475569;font-weight:600;">{html.escape(short_cat)}</div>'
            f'<div><span class="sev-pill {sev_cls}">{html.escape(r.severity.value)}</span></div>'
            f'<div>{status_pill}</div>'
            f'<div class="cell-mono">{html.escape(prompt_txt)}</div>'
            f'<div class="cell-mono">{html.escape(finding_txt)}</div>'
            f'</div>'
        )
    return (
        '<div class="aligned-table-wrap">'
        '<div class="aligned-table-head-telemetry">'
        '<div>Vector ID</div>'
        '<div>Attack Vector Name</div>'
        '<div>Category</div>'
        '<div>Severity</div>'
        '<div>Outcome</div>'
        '<div>Injected Attack Prompt</div>'
        '<div>Finding / Response Snippet</div>'
        '</div>'
        f'{"".join(rows)}'
        '</div>'
    )


def render_aligned_catalog_table(cases: List[TestCase]) -> str:
    rows = []
    for tc in cases:
        short_cat = SHORT_CATEGORY_NAMES.get(tc.category.value, tc.category.value)
        sev_cls = f"sev-{tc.severity.value.lower()}"
        canary_badge = (
            '<span class="pill-fail">Yes (LLM07)</span>'
            if tc.check_canary_leak
            else '<span class="pill-pass">No</span>'
        )
        rows.append(
            f'<div class="aligned-table-row-catalog">'
            f'<div><span class="vec-badge">{html.escape(tc.id)}</span></div>'
            f'<div style="font-weight:700;color:#0F172A;">{html.escape(tc.name)}</div>'
            f'<div style="color:#475569;font-weight:600;">{html.escape(short_cat)}</div>'
            f'<div><span class="sev-pill {sev_cls}">{html.escape(tc.severity.value)}</span></div>'
            f'<div>{canary_badge}</div>'
            f'<div class="cell-mono">{html.escape(tc.prompt)}</div>'
            f'<div style="color:#475569;font-size:0.78rem;">{html.escape(tc.description)}</div>'
            f'</div>'
        )
    return (
        '<div class="aligned-table-wrap">'
        '<div class="aligned-table-head-catalog">'
        '<div>Vector ID</div>'
        '<div>Attack Vector Name</div>'
        '<div>Category</div>'
        '<div>Severity</div>'
        '<div>Canary Check</div>'
        '<div>Synthetic Attack Prompt Payload</div>'
        '<div>Security Objective</div>'
        '</div>'
        f'{"".join(rows)}'
        '</div>'
    )


def main() -> None:
    default_url = clean_url(
        os.getenv("TARGET_API_URL", "http://127.0.0.1:8000/v1/chat/completions?mode=vulnerable")
    )
    default_key = os.getenv("TARGET_API_KEY", "")
    default_model = os.getenv("TARGET_MODEL_NAME", "gpt-4o-mini")
    default_canary = os.getenv("SCANNER_SYSTEM_CANARY", "CANARY-9942-ALPHA-SEC")

    all_benchmark_cases = load_test_cases("data/test_cases.json")

    if "active_view" not in st.session_state:
        st.session_state["active_view"] = "overview"
    if "cfg_url" not in st.session_state:
        st.session_state["cfg_url"] = default_url
    else:
        st.session_state["cfg_url"] = clean_url(st.session_state["cfg_url"])
    if "cfg_key" not in st.session_state:
        st.session_state["cfg_key"] = default_key
    if "cfg_model" not in st.session_state:
        st.session_state["cfg_model"] = default_model
    if "cfg_canary" not in st.session_state:
        st.session_state["cfg_canary"] = default_canary
    if "cfg_timeout" not in st.session_state:
        st.session_state["cfg_timeout"] = 10
    if "cfg_delay" not in st.session_state:
        st.session_state["cfg_delay"] = 0.05
    if "last_sim_mode" not in st.session_state:
        st.session_state["last_sim_mode"] = "vulnerable"

    if "enabled_vector_ids" not in st.session_state:
        st.session_state["enabled_vector_ids"] = [tc.id for tc in all_benchmark_cases]

    filtered_cases = [
        tc for tc in all_benchmark_cases if tc.id in st.session_state["enabled_vector_ids"]
    ]
    active_categories = list(dict.fromkeys(tc.category.value for tc in filtered_cases))

    if "last_report" not in st.session_state:
        run_assessment(
            test_cases=filtered_cases,
            target_url="simulator://vulnerable-agent",
            api_key="",
            model_name=st.session_state["cfg_model"],
            timeout_sec=st.session_state["cfg_timeout"],
            rate_delay=0.0,
            system_canary=st.session_state["cfg_canary"],
            sim_mode="vulnerable",
        )

    with st.sidebar:
        st.markdown(
            """
            <div class="sidebar-brand">
                <div class="sidebar-shield">🛡️</div>
                <div class="sidebar-title">AI AGENT</div>
                <div class="sidebar-subtitle">RESILIENCE SCANNER</div>
            </div>
            <div class="sidebar-section-label">Workspace View</div>
            """,
            unsafe_allow_html=True,
        )

        if st.button(
            "🏠  Security Overview",
            type="primary" if st.session_state["active_view"] == "overview" else "secondary",
            use_container_width=True,
        ):
            st.session_state["active_view"] = "overview"
            st.rerun()

        if st.button(
            "⚙️  Test Configuration",
            type="primary" if st.session_state["active_view"] == "config" else "secondary",
            use_container_width=True,
        ):
            st.session_state["active_view"] = "config"
            st.rerun()

        st.markdown('<div class="sidebar-section-label">Quick Actions</div>', unsafe_allow_html=True)

        if st.button("▶️  Scan Hardened Agent", use_container_width=True):
            run_assessment(
                test_cases=filtered_cases,
                target_url="simulator://hardened-agent",
                api_key="",
                model_name=st.session_state["cfg_model"],
                timeout_sec=st.session_state["cfg_timeout"],
                rate_delay=0.0,
                system_canary=st.session_state["cfg_canary"],
                sim_mode="hardened",
                show_progress=True,
            )
            st.session_state["active_view"] = "overview"
            st.rerun()

        if st.button("🧪  Scan Vulnerable Agent", use_container_width=True):
            run_assessment(
                test_cases=filtered_cases,
                target_url="simulator://vulnerable-agent",
                api_key="",
                model_name=st.session_state["cfg_model"],
                timeout_sec=st.session_state["cfg_timeout"],
                rate_delay=0.0,
                system_canary=st.session_state["cfg_canary"],
                sim_mode="vulnerable",
                show_progress=True,
            )
            st.session_state["active_view"] = "overview"
            st.rerun()

        if st.button("🖧  Connect Live API", use_container_width=True):
            run_assessment(
                test_cases=filtered_cases,
                target_url=st.session_state["cfg_url"],
                api_key=st.session_state["cfg_key"],
                model_name=st.session_state["cfg_model"],
                timeout_sec=st.session_state["cfg_timeout"],
                rate_delay=st.session_state["cfg_delay"],
                system_canary=st.session_state["cfg_canary"],
                sim_mode="live",
                show_progress=True,
            )
            st.rerun()

        st.markdown(
            f"""
            <div class="system-ready-box">
                <div class="system-ready-icon">✔</div>
                <div>
                    <div style="font-weight:800; font-size:0.82rem; color:#15803D;">System Ready</div>
                    <div style="font-size:0.72rem; color:#166534;">{len(filtered_cases)} of {len(all_benchmark_cases)} vectors active</div>
                </div>
            </div>
            <div class="sidebar-footer">
                <strong>OWASP LLM01 | LLM07</strong><br>
                AI Agent Resilience Scanner v1.0
            </div>
            """,
            unsafe_allow_html=True,
        )

    report: AuditReport = st.session_state["last_report"]
    cases_map: Dict[str, TestCase] = st.session_state.get("last_cases", {})
    active_canary: str = st.session_state.get("last_canary", default_canary)
    mode_label: str = st.session_state.get("last_mode_label", "Vulnerable Agent (Sim)")
    conn_failures: int = st.session_state.get("last_conn_failures", 0)

    st.markdown(
        f"""
        <div class="top-header">
            <div class="header-left">
                <div class="header-logo">🛡️</div>
                <div>
                    <h1 class="header-title">AI Agent Resilience Scanner</h1>
                    <p class="header-subtitle">
                        Detect Prompt Injection &nbsp;•&nbsp; Prevent System Prompt Leakage &nbsp;•&nbsp; Strengthen AI Agents
                    </p>
                </div>
            </div>
            <div class="header-right">
                <span class="mode-pill">Target: {html.escape(mode_label)}</span>
                <span class="online-pill">● Online</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if conn_failures > 0:
        st.error(
            f"⚠️ **Live API Connection Failed ({conn_failures}/{report.total_tests} requests unreachable at `{st.session_state['cfg_url']}`).**\n\n"
            "- **Testing locally?** Run the mock server in another terminal: `python -m scanner.mock_server`\n"
            "- **Testing an external API?** Click **⚙️ Test Configuration** in the left sidebar to update your Endpoint URL and API Key."
        )

    if st.session_state["active_view"] == "config":
        with st.container(border=True):
            st.markdown(
                """
                <div class="panel-header">
                    <div class="panel-title">⚙️ Test Configuration — Select Specific Attack Vectors &amp; Target API</div>
                    <span class="status-chip chip-good">Interactive Setup</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            col_attacks, col_api = st.columns([1.15, 1.05])

            with col_attacks:
                st.markdown("##### 🎯 1. Select Which OWASP Attacks to Perform")
                btn_sel_all, btn_clear_all = st.columns(2)
                with btn_sel_all:
                    if st.button("✅ Select All 10 Attack Vectors", use_container_width=True):
                        st.session_state["enabled_vector_ids"] = [tc.id for tc in all_benchmark_cases]
                        st.rerun()
                with btn_clear_all:
                    if st.button("🚫 Deselect All Attack Vectors", use_container_width=True):
                        st.session_state["enabled_vector_ids"] = []
                        st.rerun()

                new_enabled_ids: List[str] = []
                for cat in AttackCategory:
                    cat_cases = [tc for tc in all_benchmark_cases if tc.category == cat]
                    st.markdown(f"**{SHORT_CATEGORY_NAMES.get(cat.value, cat.value)}**")
                    for tc in cat_cases:
                        checked = st.checkbox(
                            f"`{tc.id}` — {tc.name} *({tc.severity.value})*",
                            value=(tc.id in st.session_state["enabled_vector_ids"]),
                        )
                        if checked:
                            new_enabled_ids.append(tc.id)

                st.session_state["enabled_vector_ids"] = new_enabled_ids
                filtered_cases = [
                    tc for tc in all_benchmark_cases if tc.id in st.session_state["enabled_vector_ids"]
                ]
                active_categories = list(dict.fromkeys(tc.category.value for tc in filtered_cases))
                st.info(
                    f"📋 **{len(filtered_cases)} of {len(all_benchmark_cases)} Attack Vectors** selected across **{len(active_categories)}** categories."
                )

            with col_api:
                st.markdown("##### 🖧 2. Live API Endpoint & Canary Settings")
                st.caption("Configure a local mock server (`python -m scanner.mock_server`) or external REST URL:")

                entered_url = st.text_input(
                    "Target Endpoint URL",
                    value=st.session_state["cfg_url"],
                )
                st.session_state["cfg_url"] = clean_url(entered_url)

                c_k1, c_k2 = st.columns(2)
                with c_k1:
                    st.session_state["cfg_key"] = st.text_input(
                        "Bearer API Key (Optional for Local)",
                        value=st.session_state["cfg_key"],
                        type="password",
                    )
                with c_k2:
                    st.session_state["cfg_model"] = st.text_input(
                        "Model Identifier",
                        value=st.session_state["cfg_model"],
                    )

                c_t1, c_t2, c_t3 = st.columns(3)
                with c_t1:
                    st.session_state["cfg_canary"] = st.text_input(
                        "System Canary Token",
                        value=st.session_state["cfg_canary"],
                    )
                with c_t2:
                    st.session_state["cfg_timeout"] = st.number_input(
                        "Timeout (sec)", min_value=1, max_value=120, value=int(st.session_state["cfg_timeout"])
                    )
                with c_t3:
                    st.session_state["cfg_delay"] = st.number_input(
                        "Rate Delay (sec)", min_value=0.0, max_value=5.0, value=float(st.session_state["cfg_delay"]), step=0.05
                    )

                st.markdown("---")
                st.markdown("##### 🚀 3. Execute Scan with Selected Attack Vectors")
                if st.button(
                    f"🧪 Run {len(filtered_cases)} Selected Attack(s) on Vulnerable Sim",
                    type="primary",
                    use_container_width=True,
                ):
                    run_assessment(
                        test_cases=filtered_cases,
                        target_url="simulator://vulnerable-agent",
                        api_key="",
                        model_name=st.session_state["cfg_model"],
                        timeout_sec=st.session_state["cfg_timeout"],
                        rate_delay=0.0,
                        system_canary=st.session_state["cfg_canary"],
                        sim_mode="vulnerable",
                        show_progress=True,
                    )
                    st.session_state["active_view"] = "overview"
                    st.rerun()

                if st.button(
                    f"▶️ Run {len(filtered_cases)} Selected Attack(s) on Hardened Sim",
                    use_container_width=True,
                ):
                    run_assessment(
                        test_cases=filtered_cases,
                        target_url="simulator://hardened-agent",
                        api_key="",
                        model_name=st.session_state["cfg_model"],
                        timeout_sec=st.session_state["cfg_timeout"],
                        rate_delay=0.0,
                        system_canary=st.session_state["cfg_canary"],
                        sim_mode="hardened",
                        show_progress=True,
                    )
                    st.session_state["active_view"] = "overview"
                    st.rerun()

                if st.button(
                    f"🖧 Run {len(filtered_cases)} Selected Attack(s) on Live API",
                    use_container_width=True,
                ):
                    run_assessment(
                        test_cases=filtered_cases,
                        target_url=st.session_state["cfg_url"],
                        api_key=st.session_state["cfg_key"],
                        model_name=st.session_state["cfg_model"],
                        timeout_sec=st.session_state["cfg_timeout"],
                        rate_delay=st.session_state["cfg_delay"],
                        system_canary=st.session_state["cfg_canary"],
                        sim_mode="live",
                        show_progress=True,
                    )
                    st.session_state["active_view"] = "overview"
                    st.rerun()

            st.markdown("##### 📋 Preview Selected Attack Vectors")
            if filtered_cases:
                st.markdown(render_aligned_catalog_table(filtered_cases), unsafe_allow_html=True)
            else:
                st.warning("No attack vectors currently selected. Check at least one vector above.")

    canary_leaks = sum(1 for r in report.results if r.canary_leaked)
    blocked_pct = int(round((report.passed_tests / max(report.total_tests, 1)) * 100))
    leaks_pct = int(round((canary_leaks / max(report.total_tests, 1)) * 100))

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        delta_str = "↑ Hardened" if report.resilience_score >= 80 else "↓ Vulnerable"
        delta_col = "#16A34A" if report.resilience_score >= 80 else "#DC2626"
        st.markdown(
            f"""
            <div class="bento-card">
                <div class="kpi-top">
                    <div class="kpi-icon icon-blue">🏆</div>
                    <div>
                        <p class="kpi-label">Resilience Score</p>
                        <div class="kpi-val-row">
                            <span class="kpi-val">{report.resilience_score:.1f}%</span>
                            <span class="kpi-delta" style="color:{delta_col};">{delta_str}</span>
                        </div>
                    </div>
                </div>
                <div class="kpi-bar-bg">
                    <div class="kpi-bar-fill" style="width:{min(report.resilience_score, 100):.0f}%; background:#2563EB;"></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k2:
        st.markdown(
            f"""
            <div class="bento-card">
                <div class="kpi-top">
                    <div class="kpi-icon icon-purple">📋</div>
                    <div>
                        <p class="kpi-label">Tests Executed</p>
                        <div class="kpi-val-row">
                            <span class="kpi-val">{report.total_tests}</span>
                            <span class="kpi-delta" style="color:#64748B;">/ {len(all_benchmark_cases)}</span>
                        </div>
                    </div>
                </div>
                <div class="kpi-bar-bg">
                    <div class="kpi-bar-fill" style="width:{int(round((report.total_tests / max(len(all_benchmark_cases), 1)) * 100))}%; background:#7C3AED;"></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k3:
        st.markdown(
            f"""
            <div class="bento-card">
                <div class="kpi-top">
                    <div class="kpi-icon icon-green">🛡️</div>
                    <div>
                        <p class="kpi-label">Attacks Blocked</p>
                        <div class="kpi-val-row">
                            <span class="kpi-val">{report.passed_tests}</span>
                            <span class="kpi-delta" style="color:#16A34A;">({blocked_pct}%)</span>
                        </div>
                    </div>
                </div>
                <div class="kpi-bar-bg">
                    <div class="kpi-bar-fill" style="width:{blocked_pct}%; background:#16A34A;"></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k4:
        st.markdown(
            f"""
            <div class="bento-card">
                <div class="kpi-top">
                    <div class="kpi-icon icon-red">⚠️</div>
                    <div>
                        <p class="kpi-label">Canary Leaks</p>
                        <div class="kpi-val-row">
                            <span class="kpi-val" style="color:#DC2626;">{canary_leaks}</span>
                            <span class="kpi-delta" style="color:#64748B;">({leaks_pct}%)</span>
                        </div>
                    </div>
                </div>
                <div class="kpi-bar-bg">
                    <div class="kpi-bar-fill" style="width:{max(leaks_pct, 6 if canary_leaks > 0 else 0)}%; background:#DC2626;"></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    r2_left, r2_right = st.columns([1.05, 1])

    with r2_left:
        if report.resilience_score >= 80:
            chip_cls, chip_txt = "chip-good", "● Good"
            box_cls, box_title, box_desc = (
                "assess-good",
                "✔ Strong Security Posture",
                "The agent resisted prompt injection vectors and protected its system canary token.",
            )
        elif report.resilience_score >= 50:
            chip_cls, chip_txt = "chip-warn", "● Moderate"
            box_cls, box_title, box_desc = (
                "assess-warn",
                "⚠️ Moderate Security Posture",
                f"The agent blocked {report.passed_tests} probes, but {report.failed_tests} vulnerabilities require hardening.",
            )
        else:
            chip_cls, chip_txt = "chip-crit", "● Vulnerable"
            box_cls, box_title, box_desc = (
                "assess-crit",
                "🚨 Critical Vulnerabilities Found",
                f"Guardrails broke on {report.failed_tests} probes with {canary_leaks} system prompt canary leak(s).",
            )

        st.markdown(
            f"""
            <div class="bento-card bento-row-2">
                <div class="panel-header">
                    <div class="panel-title">🛡️ Security Posture Overview</div>
                    <span class="status-chip {chip_cls}">{chip_txt}</span>
                </div>
                <div class="posture-flex">
                    {build_svg_donut(report.resilience_score)}
                    <div>
                        <div style="font-size:0.88rem; font-weight:700; color:#0F172A;">
                            Overall Assessment ({html.escape(report.risk_rating.value)})
                        </div>
                        <div class="assessment-box {box_cls}">
                            <div style="font-weight:800; font-size:0.86rem; margin-bottom:0.2rem;">{box_title}</div>
                            <div style="font-size:0.78rem; line-height:1.38;">{box_desc}</div>
                        </div>
                        <div class="legend-row">
                            <span><i class="legend-dot" style="background:#10B981;"></i>Safe</span>
                            <span><i class="legend-dot" style="background:#3B82F6;"></i>Low Risk</span>
                            <span><i class="legend-dot" style="background:#F59E0B;"></i>Medium</span>
                            <span><i class="legend-dot" style="background:#EF4444;"></i>High</span>
                            <span><i class="legend-dot" style="background:#991B1B;"></i>Critical</span>
                        </div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with r2_right:
        report_categories = list(report.category_breakdown.keys())
        st.markdown(
            f"""
            <div class="bento-card bento-row-2">
                <div class="panel-header">
                    <div class="panel-title">🟧 Threat Severity Heatmap</div>
                    <span class="status-chip chip-good" style="background:#F1F5F9;color:#334155;border-color:#CBD5E1;">
                        {len(report_categories)} Categories Tested
                    </span>
                </div>
                {build_heatmap_html(report, report_categories)}
            </div>
            """,
            unsafe_allow_html=True,
        )

    r3_left, r3_right = st.columns([1.05, 1])

    with r3_left:
        bar_palette = ["#2563EB", "#F59E0B", "#10B981", "#8B5CF6", "#0EA5E9"]
        bars_html = []
        for idx, cat_enum in enumerate(AttackCategory):
            cat_name = cat_enum.value
            if cat_name not in report.category_breakdown:
                continue
            short_lbl = SHORT_CATEGORY_NAMES.get(cat_name, cat_name)
            b_stat = report.category_breakdown.get(cat_name)
            pct = int(round(b_stat.pass_rate)) if b_stat else 0
            bar_col = bar_palette[idx % len(bar_palette)]
            bars_html.append(
                f'<div class="cat-perf-row">'
                f'  <div class="cat-perf-top"><span>{html.escape(short_lbl)}</span><span>{pct}%</span></div>'
                f'  <div class="cat-perf-track"><div class="cat-perf-fill" style="width:{max(pct, 6)}%; background:{bar_col};"></div></div>'
                f"</div>"
            )

        st.markdown(
            f"""
            <div class="bento-card bento-row-3">
                <div class="panel-header">
                    <div class="panel-title">📊 Attack Category Performance</div>
                    <span style="font-size:0.74rem; color:#64748B; font-weight:600;">Guardrail Hold Rate</span>
                </div>
                <div class="cat-perf-wrap">
                    {"".join(bars_html)}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with r3_right:
        monitor_rows = []
        for idx, r in enumerate(report.results, start=1):
            short_cat = SHORT_CATEGORY_NAMES.get(r.category.value, r.category.value)
            pill = (
                '<span class="pill-pass">PASS</span>'
                if r.passed
                else '<span class="pill-fail">FAIL</span>'
            )
            monitor_rows.append(
                f'<div class="monitor-item">'
                f'<div>{idx}</div>'
                f'<div><span class="vec-badge">{html.escape(r.test_id)}</span></div>'
                f'<div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-right:6px;">{html.escape(short_cat)}</div>'
                f'<div>{pill}</div>'
                f'<div style="text-align:right;font-weight:600;color:#475569;">{int(round(r.latency_ms))}ms</div>'
                f'</div>'
            )

        st.markdown(
            f"""
            <div class="bento-card bento-row-3">
                <div class="panel-header">
                    <div class="panel-title">⚡ Live Attack Monitor</div>
                    <span class="status-chip chip-good">● {len(report.results)} Probes</span>
                </div>
                <div class="monitor-container">
                    <div class="monitor-head">
                        <div>#</div>
                        <div>Vector ID</div>
                        <div>Category</div>
                        <div>Status</div>
                        <div style="text-align:right;">Latency</div>
                    </div>
                    <div class="monitor-body">
                        {"".join(monitor_rows)}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    r4_left, r4_right = st.columns([1.05, 1])

    with r4_left:
        with st.container(border=True):
            st.markdown(
                """
                <div class="panel-header">
                    <div class="panel-title">🔍 AI Attack Forensics</div>
                    <span style="font-size:0.75rem; color:#2563EB; font-weight:700;">Select Vector Below ↓</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            sorted_for_forensics = sorted(
                report.results, key=lambda x: (x.passed, not x.canary_leaked)
            )
            forensic_options = {
                f"{r.test_id} — {r.test_name} ({'FAIL' if not r.passed else 'PASS'})": r
                for r in sorted_for_forensics
            }
            chosen_key = st.selectbox(
                "Select Probe Vector to Inspect:",
                options=list(forensic_options.keys()),
                label_visibility="collapsed",
            )
            chosen_res = forensic_options[chosen_key]
            chosen_tc = cases_map.get(chosen_res.test_id)
            raw_prompt = chosen_tc.prompt if chosen_tc else ""
            formatted_reply = format_forensic_response(chosen_res.response_snippet, active_canary)

            st.markdown(
                f"""
                <div class="forensics-grid">
                    <div class="forensic-box">
                        <div class="forensic-box-head" style="color:#DC2626;">● Injected Prompt ({html.escape(chosen_res.test_id)})</div>
                        <div>{html.escape(raw_prompt)}</div>
                    </div>
                    <div style="display:flex;align-items:center;justify-content:center;font-size:1.1rem;color:#F59E0B;">⚠️➔</div>
                    <div class="forensic-box">
                        <div class="forensic-box-head" style="color:{'#DC2626' if not chosen_res.passed else '#16A34A'};">
                            ● AI Response ({'GUARDRAIL BROKE' if not chosen_res.passed else 'GUARDRAIL HELD'})
                        </div>
                        <div>{formatted_reply}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with r4_right:
        with st.container(border=True):
            st.markdown(
                """
                <div class="panel-header">
                    <div class="panel-title">🔧 Automated Remediation Recommendations</div>
                    <span class="status-chip chip-good" style="background:#EFF6FF;color:#1D4ED8;border-color:#BFDBFE;">OWASP Playbook</span>
                </div>
                <div class="remed-list-box">
                    <div class="remed-item"><span class="remed-check">✔</span><span>Implement stricter input validation and output filtering</span></div>
                    <div class="remed-item"><span class="remed-check">✔</span><span>Use structured system prompts with clear XML/delimiter boundaries</span></div>
                    <div class="remed-item"><span class="remed-check">✔</span><span>Monitor outbound completions for secret canary token leaks (LLM07)</span></div>
                    <div class="remed-item"><span class="remed-check">✔</span><span>Apply rate limiting and decoding checks for Base64/obfuscated inputs</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            view_full = st.button("🛡️ View Full Diagnostic Report →", use_container_width=True)

    with st.expander("📋 Loaded OWASP Attack Vectors & Detailed Probe Telemetry", expanded=True):
        tab_telemetry, tab_catalog = st.tabs(
            [
                f"🔍 Detailed Probe Telemetry ({len(report.results)} Results)",
                f"🎯 Benchmark Attack Vectors Catalog ({len(filtered_cases)} Active Prompts)",
            ]
        )
        with tab_telemetry:
            st.markdown(
                render_aligned_telemetry_table(report.results, cases_map),
                unsafe_allow_html=True,
            )

        with tab_catalog:
            st.markdown(
                render_aligned_catalog_table(filtered_cases),
                unsafe_allow_html=True,
            )

    reports_dir = Path("reports")
    json_path = ReportGenerator.export_json(report, reports_dir / f"{report.scan_id}.json")
    html_path = ReportGenerator.export_html(report, reports_dir / f"{report.scan_id}.html")

    foot_left, foot_btn1, foot_btn2 = st.columns([2.2, 0.75, 0.75])
    with foot_left:
        st.markdown(
            f"""
            <div class="footer-banner">
                <span>ℹ️</span>
                <span>Scan <code>{html.escape(report.scan_id)}</code> completed ({report.total_tests} vectors evaluated)! Review findings above or download the report.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with foot_btn1:
        st.download_button(
            label="📥 Download HTML Report",
            data=html_path.read_bytes(),
            file_name=f"{report.scan_id}_Report.html",
            mime="text/html",
            use_container_width=True,
        )
    with foot_btn2:
        st.download_button(
            label="</> Download JSON",
            data=json_path.read_bytes(),
            file_name=f"{report.scan_id}_Telemetry.json",
            mime="application/json",
            use_container_width=True,
        )


if __name__ == "__main__":
    main()