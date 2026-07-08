"""
app.py — Streamlit frontend for the Agentic-CTI pipeline.

SOC Analyst Triage Grid layout:
  TOP ROW  (full width) : Header + Raw Report Ingestion Terminal.
  BOTTOM ROW (2 : 3)   : Left  → Extracted Intel + Qdrant RAG map.
                          Right → YARA-L 2.0 detection rule (maximum width).

Forced dark terminal theme with Mandiant-style electric blue / cyan accents.
Run with: streamlit run app.py
"""

import io
import json
import logging
import os

import streamlit as st

# ---------------------------------------------------------------------------
# Page config — MUST be first Streamlit call
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Agentic-CTI | SOC Triage Platform",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Module imports (after page config)
# ---------------------------------------------------------------------------
from agent import ThreatIntelReport, run_pipeline

# Mirror of agent.MAX_INPUT_CHARS — max chars sent to the LLM.
# 100k chars ≈ 25k tokens, well within llama-3.3-70b's 128k token window.
# See agent.py for full context math and the map-reduce backlog note.
MAX_INPUT_CHARS = 100_000
import vector_store as vs
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# @st.cache_resource — keeps Qdrant + encoder alive across reruns
# ---------------------------------------------------------------------------

@st.cache_resource(show_spinner="Initialising knowledge base…")
def _bootstrap_vector_store() -> tuple[QdrantClient, SentenceTransformer]:
    qdrant_path = os.getenv("QDRANT_PATH", vs._DEFAULT_QDRANT_PATH)
    client = QdrantClient(":memory:") if qdrant_path == ":memory:" else QdrantClient(path=qdrant_path)
    encoder = SentenceTransformer(vs.EMBEDDING_MODEL)
    vs.set_singletons(client, encoder)
    vs.initialize_collection()
    return client, encoder

_qdrant_client, _st_encoder = _bootstrap_vector_store()
vs.set_singletons(_qdrant_client, _st_encoder)

# ---------------------------------------------------------------------------
# ── FORCED DARK TERMINAL THEME ───────────────────────────────────────────
# Forces #0e1117 background regardless of the user's Streamlit theme setting.
# Mandiant-style electric blue (#00d4ff) + deep navy palette.
# ---------------------------------------------------------------------------
THEME_CSS = """
<style>
/* ── Google Fonts ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ── Force dark background on EVERY Streamlit container ── */
html, body,
[data-testid="stAppViewContainer"],
[data-testid="stApp"],
[data-testid="stMain"],
.main, .block-container,
[data-testid="stSidebar"],
[data-testid="stHeader"],
section[data-testid="stSidebar"] > div,
div[data-testid="stVerticalBlock"] { background-color: #0e1117 !important; }

/* ── Global typography ── */
*, *::before, *::after { box-sizing: border-box; }
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    color: #c9d8e8;
}

/* ── Streamlit default text overrides ── */
.stMarkdown, .stText, p, span, label, div { color: #c9d8e8; }
h1, h2, h3 { color: #e4edf6; }

/* ── Hide Streamlit chrome ── */
#MainMenu, footer, header, [data-testid="stToolbar"] { visibility: hidden; }
.block-container { padding: 1rem 1.5rem 2rem !important; max-width: 100% !important; }

/* ════════════════════════════════════════════════════════
   HEADER BANNER
════════════════════════════════════════════════════════ */
.cti-header {
    background: linear-gradient(135deg, #0a0d14 0%, #0d1520 40%, #0a1628 100%);
    border: 1px solid #1a3a5c;
    border-left: 4px solid #00d4ff;
    border-radius: 6px;
    padding: 18px 28px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: relative;
    overflow: hidden;
}
.cti-header::before {
    content: '';
    position: absolute;
    top: -40px; right: -40px;
    width: 160px; height: 160px;
    background: radial-gradient(circle, rgba(0,212,255,0.08) 0%, transparent 70%);
    pointer-events: none;
}
.cti-header-left h1 {
    font-size: 1.7rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: #00d4ff;
    margin: 0 0 2px 0;
    text-shadow: 0 0 20px rgba(0,212,255,0.4);
}
.cti-header-left p {
    font-size: 0.78rem;
    color: #4a7a9b;
    margin: 0;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.05em;
}
.cti-status-bar {
    display: flex;
    gap: 16px;
    align-items: center;
}
.cti-status-item {
    text-align: center;
}
.cti-status-item .label {
    font-size: 0.65rem;
    color: #3a6a8a;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-family: 'JetBrains Mono', monospace;
}
.cti-status-item .value {
    font-size: 0.85rem;
    font-weight: 600;
    color: #00d4ff;
    font-family: 'JetBrains Mono', monospace;
}
.cti-status-divider {
    width: 1px; height: 36px;
    background: #1a3a5c;
}

/* ════════════════════════════════════════════════════════
   TERMINAL INPUT PANEL
════════════════════════════════════════════════════════ */
.terminal-panel {
    background: #090c12;
    border: 1px solid #1a2a3a;
    border-top: 2px solid #00d4ff;
    border-radius: 6px;
    padding: 0;
    margin-bottom: 16px;
    overflow: hidden;
}
.terminal-titlebar {
    background: #0d1520;
    padding: 8px 14px;
    display: flex;
    align-items: center;
    gap: 10px;
    border-bottom: 1px solid #1a2a3a;
}
.terminal-dot { width: 10px; height: 10px; border-radius: 50%; }
.dot-red    { background: #ff5f57; }
.dot-yellow { background: #febc2e; }
.dot-green  { background: #28c840; }
.terminal-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #3a6a8a;
    margin-left: 6px;
    letter-spacing: 0.06em;
}
.terminal-body { padding: 12px 16px 14px 16px; }

/* Override Streamlit's textarea inside our terminal */
.terminal-body .stTextArea textarea {
    background: #090c12 !important;
    border: 1px solid #1a3a5c !important;
    border-radius: 4px !important;
    color: #00ff88 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.8rem !important;
    caret-color: #00d4ff;
    resize: vertical;
}
.terminal-body .stTextArea textarea::placeholder { color: #2a4a6a !important; }
.terminal-body .stTextArea textarea:focus {
    border-color: #00d4ff !important;
    box-shadow: 0 0 0 2px rgba(0,212,255,0.15) !important;
    outline: none !important;
}

/* ════════════════════════════════════════════════════════
   BUTTONS
════════════════════════════════════════════════════════ */
.stButton > button {
    background: transparent !important;
    border: 1px solid #00d4ff !important;
    color: #00d4ff !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.82rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.05em !important;
    border-radius: 4px !important;
    padding: 8px 20px !important;
    transition: all 0.15s ease !important;
}
.stButton > button:hover {
    background: rgba(0,212,255,0.1) !important;
    box-shadow: 0 0 12px rgba(0,212,255,0.25) !important;
    transform: translateY(-1px) !important;
}
/* Analyze button — filled variant */
.analyze-btn .stButton > button {
    background: linear-gradient(135deg, #005580 0%, #007aaa 100%) !important;
    border-color: #00d4ff !important;
    color: #e0f8ff !important;
    font-size: 0.88rem !important;
    padding: 10px 28px !important;
    width: 100% !important;
    box-shadow: 0 2px 16px rgba(0,212,255,0.2) !important;
}
.analyze-btn .stButton > button:hover {
    background: linear-gradient(135deg, #007aaa 0%, #00a8e8 100%) !important;
    box-shadow: 0 4px 24px rgba(0,212,255,0.35) !important;
}

/* ════════════════════════════════════════════════════════
   SECTION CARDS
════════════════════════════════════════════════════════ */
.soc-card {
    background: #0c111a;
    border: 1px solid #1a2d42;
    border-radius: 6px;
    padding: 16px 18px;
    margin-bottom: 14px;
    height: fit-content;
}
.soc-card-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: #3a7a9a;
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    padding-bottom: 10px;
    border-bottom: 1px solid #12212e;
}
.soc-card-title span { color: #00d4ff; }

/* ════════════════════════════════════════════════════════
   INTEL BADGES (threat actor / malware)
════════════════════════════════════════════════════════ */
.intel-badge-group { margin-bottom: 14px; }
.intel-badge-label {
    font-size: 0.65rem;
    color: #3a6a8a;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 6px;
}
.intel-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    border-radius: 3px;
    font-size: 0.82rem;
    font-weight: 600;
    margin: 3px 4px 3px 0;
    font-family: 'JetBrains Mono', monospace;
}
.badge-actor {
    background: rgba(0,212,255,0.12);
    border: 1px solid rgba(0,212,255,0.35);
    color: #00d4ff;
}
.badge-malware {
    background: rgba(255,100,100,0.1);
    border: 1px solid rgba(255,100,100,0.3);
    color: #ff7070;
}
.badge-ttp {
    background: rgba(180,130,255,0.1);
    border: 1px solid rgba(180,130,255,0.3);
    color: #c090ff;
    font-size: 0.78rem;
}

/* ════════════════════════════════════════════════════════
   IOC CHIP BADGES  (Google Cloud Console style)
════════════════════════════════════════════════════════ */
.ioc-section-label {
    font-size: 0.65rem;
    color: #3a6a8a;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-family: 'JetBrains Mono', monospace;
    margin: 14px 0 8px 0;
    display: flex;
    align-items: center;
    gap: 8px;
}
.ioc-chips-container {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-bottom: 4px;
}
.ioc-chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 10px 4px 8px;
    border-radius: 16px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 500;
    cursor: default;
    transition: filter 0.15s;
    white-space: nowrap;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
}
.ioc-chip:hover { filter: brightness(1.15); }
.ioc-chip-icon {
    font-size: 0.7rem;
    flex-shrink: 0;
}
/* IP Address chips */
.chip-ip {
    background: rgba(0,160,255,0.12);
    border: 1px solid rgba(0,160,255,0.4);
    color: #5bc8ff;
}
/* Domain chips */
.chip-domain {
    background: rgba(255,165,0,0.1);
    border: 1px solid rgba(255,165,0,0.35);
    color: #ffb84d;
}
/* Hash chips */
.chip-hash {
    background: rgba(180,100,255,0.1);
    border: 1px solid rgba(180,100,255,0.3);
    color: #c47fff;
    font-size: 0.67rem;
}

/* ════════════════════════════════════════════════════════
   SIMILARITY SCORE
════════════════════════════════════════════════════════ */
.rag-score-display {
    display: flex;
    align-items: center;
    gap: 16px;
    margin: 10px 0;
}
.rag-score-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
}
.rag-score-label {
    font-size: 0.7rem;
    color: #3a6a8a;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-family: 'JetBrains Mono', monospace;
}
.score-bar-track {
    flex: 1;
    background: #12212e;
    border-radius: 3px;
    height: 6px;
    overflow: hidden;
    min-width: 80px;
}
.score-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.6s ease;
}

/* ════════════════════════════════════════════════════════
   YARA-L CODE BLOCK
════════════════════════════════════════════════════════ */
.yaral-container {
    background: #080b10;
    border: 1px solid #1a3a5c;
    border-top: 2px solid #00d4ff;
    border-radius: 6px;
    padding: 0;
    overflow: hidden;
    margin-bottom: 12px;
}
.yaral-titlebar {
    background: #0d1520;
    padding: 8px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #1a3a5c;
}
.yaral-title-left {
    display: flex;
    align-items: center;
    gap: 10px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #3a6a8a;
    letter-spacing: 0.06em;
}
.yaral-status-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 10px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.05em;
}
.badge-validated {
    background: rgba(0,255,136,0.12);
    border: 1px solid rgba(0,255,136,0.35);
    color: #00ff88;
}
.badge-failed {
    background: rgba(255,68,68,0.12);
    border: 1px solid rgba(255,68,68,0.35);
    color: #ff6666;
}
.badge-pending {
    background: rgba(0,212,255,0.1);
    border: 1px solid rgba(0,212,255,0.3);
    color: #00d4ff;
}

/* Override Streamlit code block */
.yaral-code-inner [data-testid="stCode"],
.yaral-code-inner pre,
.yaral-code-inner code {
    background: #080b10 !important;
    border: none !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.8rem !important;
    color: #a0d8ef !important;
    padding: 16px !important;
    min-height: 300px;
}

/* ════════════════════════════════════════════════════════
   PIPELINE METADATA GRID
════════════════════════════════════════════════════════ */
.meta-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
    margin-top: 10px;
}
.meta-item {
    background: #0a0d14;
    border: 1px solid #1a2a3a;
    border-radius: 4px;
    padding: 10px 12px;
    text-align: center;
}
.meta-item .meta-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    color: #3a6a8a;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 4px;
}
.meta-item .meta-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.1rem;
    font-weight: 700;
    color: #00d4ff;
}
.meta-item .meta-value.ok  { color: #00ff88; }
.meta-item .meta-value.warn{ color: #ffb84d; }

/* ════════════════════════════════════════════════════════
   MATCH CARD (RAG results)
════════════════════════════════════════════════════════ */
.match-card {
    background: #0a0f18;
    border: 1px solid #1a3a5c;
    border-left: 3px solid #00d4ff;
    border-radius: 4px;
    padding: 10px 14px;
    margin-bottom: 8px;
}
.match-card-actor {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    font-weight: 600;
    color: #00d4ff;
    margin-bottom: 4px;
}
.match-card-detail {
    font-size: 0.72rem;
    color: #4a7a9a;
    font-family: 'JetBrains Mono', monospace;
}
.match-score-pill {
    float: right;
    background: rgba(0,255,136,0.12);
    border: 1px solid rgba(0,255,136,0.3);
    color: #00ff88;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 3px;
}

/* ════════════════════════════════════════════════════════
   INFO / WARNING BOXES
════════════════════════════════════════════════════════ */
.cti-info {
    background: rgba(0,160,255,0.07);
    border: 1px solid rgba(0,160,255,0.25);
    border-left: 3px solid #00a0ff;
    border-radius: 4px;
    padding: 10px 14px;
    font-size: 0.78rem;
    color: #6aaad4;
    font-family: 'JetBrains Mono', monospace;
}
.cti-error {
    background: rgba(255,68,68,0.07);
    border: 1px solid rgba(255,68,68,0.25);
    border-left: 3px solid #ff4444;
    border-radius: 4px;
    padding: 10px 14px;
    font-size: 0.78rem;
    color: #ff8888;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 8px;
}

/* ════════════════════════════════════════════════════════
   STREAMLIT MISC OVERRIDES
════════════════════════════════════════════════════════ */
/* Metric widgets */
[data-testid="metric-container"] {
    background: #0a0d14 !important;
    border: 1px solid #1a2a3a !important;
    border-radius: 4px !important;
    padding: 8px 12px !important;
}
[data-testid="metric-container"] label { color: #3a6a8a !important; font-size: 0.7rem !important; }
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    color: #00d4ff !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* Expanders */
[data-testid="stExpander"] {
    background: #0a0d14 !important;
    border: 1px solid #1a2a3a !important;
    border-radius: 4px !important;
}
[data-testid="stExpander"] summary { color: #4a7a9a !important; }

/* Download button */
[data-testid="stDownloadButton"] button {
    background: rgba(0,255,136,0.08) !important;
    border: 1px solid rgba(0,255,136,0.3) !important;
    color: #00ff88 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.78rem !important;
    border-radius: 4px !important;
    width: 100% !important;
}
[data-testid="stDownloadButton"] button:hover {
    background: rgba(0,255,136,0.15) !important;
    box-shadow: 0 0 10px rgba(0,255,136,0.2) !important;
}

/* ── Ingestion toolbar row ── */
.ingestion-toolbar {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
    padding: 6px 0;
}

/* Compact file uploader — inline style */
[data-testid="stFileUploader"] {
    background: #090c12 !important;
    border: 1px solid #1a3a5c !important;
    border-radius: 4px !important;
    padding: 0 !important;
    margin: 0 !important;
}
[data-testid="stFileUploader"] > div {
    padding: 0 !important;
}
/* Hide the big drag-drop section, keep only the Browse button */
[data-testid="stFileUploader"] section[data-testid="stFileUploaderDropzone"] {
    border: none !important;
    background: transparent !important;
    padding: 2px 0 !important;
    min-height: unset !important;
}
[data-testid="stFileUploader"] section[data-testid="stFileUploaderDropzone"] > div:first-child {
    display: none !important;
}
[data-testid="stFileUploader"] section button {
    background: transparent !important;
    border: 1px solid #1a3a5c !important;
    color: #3a6a8a !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.78rem !important;
    letter-spacing: 0.04em !important;
    border-radius: 4px !important;
    padding: 6px 16px !important;
    height: 38px !important;
    white-space: nowrap !important;
    transition: all 0.15s ease !important;
}
[data-testid="stFileUploader"] section button:hover {
    border-color: #00d4ff !important;
    color: #00d4ff !important;
    background: rgba(0,212,255,0.06) !important;
}
[data-testid="stFileUploader"] label { display: none !important; }

/* Status widget */
[data-testid="stStatus"] {
    background: #090c12 !important;
    border: 1px solid #1a3a5c !important;
    border-radius: 4px !important;
    color: #c9d8e8 !important;
}

/* Divider */
hr { border-color: #12212e !important; margin: 12px 0 !important; }

/* Scrollbar */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #090c12; }
::-webkit-scrollbar-thumb { background: #1a3a5c; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #00d4ff; }
</style>
"""

# ---------------------------------------------------------------------------
# Sample report for quick fill
# ---------------------------------------------------------------------------
SAMPLE_REPORT = """Threat Advisory: APT41 Targets South Asian Telecommunications Sector

Initial entry points indicate specialized spear-phishing vectors dropping malicious Microsoft \
Office document attachments. Upon macro execution, the campaign initiates an automated download \
sequence retrieving the KEYPLUG implant infrastructure alongside the DEADEYE downloader tool.

Execution tracking revealed specific PowerShell command script paths (MITRE ATT&CK T1059.001). \
Network telemetry confirmed malware establishes C2 communication to malicious external domains.

Indicators of Compromise:
- C2 IP: 203.0.113.45
- Backup IP: 198.51.100.22
- Domain: backup.evil-apt41.com
- Domain: update.apt41-c2.net
- SHA-256: 3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c
- MD5: aabbccdd11223344aabbccdd11223344

MITRE ATT&CK: T1566.001, T1059.003, T1055, T1071.001, T1027"""

# ---------------------------------------------------------------------------
# Helper: IOC chip HTML
# ---------------------------------------------------------------------------

def _ioc_chips_html(iocs) -> str:
    """Render IOC chips as HTML — handles both IOCBundle model and plain dict."""
    if hasattr(iocs, "ips"):
        ips     = list(iocs.ips or [])
        domains = list(iocs.domains or [])
        hashes  = list(iocs.hashes or [])
    else:
        ips     = iocs.get("ips", [])
        domains = iocs.get("domains", [])
        hashes  = iocs.get("hashes", [])

    html_parts: list[str] = []

    if ips:
        html_parts.append('<div class="ioc-section-label">⬡ IP Addresses</div>'
                          '<div class="ioc-chips-container">')
        for ip in ips:
            html_parts.append(
                f'<span class="ioc-chip chip-ip">'
                f'<span class="ioc-chip-icon">◈</span>{ip}</span>'
            )
        html_parts.append("</div>")

    if domains:
        html_parts.append('<div class="ioc-section-label">⬡ Domains</div>'
                          '<div class="ioc-chips-container">')
        for d in domains:
            html_parts.append(
                f'<span class="ioc-chip chip-domain">'
                f'<span class="ioc-chip-icon">⊕</span>{d}</span>'
            )
        html_parts.append("</div>")

    if hashes:
        html_parts.append('<div class="ioc-section-label">⬡ File Hashes</div>'
                          '<div class="ioc-chips-container">')
        for h in hashes:
            short = h[:8] + "…" + h[-8:] if len(h) > 20 else h
            html_parts.append(
                f'<span class="ioc-chip chip-hash" title="{h}">'
                f'<span class="ioc-chip-icon">#</span>{short}</span>'
            )
        html_parts.append("</div>")

    if not html_parts:
        return '<span style="color:#3a6a8a; font-family:JetBrains Mono; font-size:0.75rem;">No IOCs extracted.</span>'

    return "".join(html_parts)


def _score_color(score: float) -> str:
    if score >= 0.7: return "#00ff88"
    if score >= 0.4: return "#ffb84d"
    return "#4a7a9a"


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------
def main() -> None:
    # Inject forced dark theme CSS
    st.markdown(THEME_CSS, unsafe_allow_html=True)

    # ── TOP ROW: Header ───────────────────────────────────────────────────
    st.markdown("""
    <div class="cti-header">
      <div class="cti-header-left">
        <h1>AGENTIC-CTI</h1>
        <p>DETECTION-AS-CODE PIPELINE // LangGraph + Groq/Llama-3.3 // Qdrant RAG // YARA-L 2.0</p>
      </div>
      <div class="cti-status-bar">
        <div class="cti-status-item">
          <div class="label">Engine</div>
          <div class="value">LLAMA-3.3-70B</div>
        </div>
        <div class="cti-status-divider"></div>
        <div class="cti-status-item">
          <div class="label">Provider</div>
          <div class="value">GROQ</div>
        </div>
        <div class="cti-status-divider"></div>
        <div class="cti-status-item">
          <div class="label">Vector DB</div>
          <div class="value">QDRANT</div>
        </div>
        <div class="cti-status-divider"></div>
        <div class="cti-status-item">
          <div class="label">Rule Format</div>
          <div class="value">YARA-L 2.0</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── TOP ROW: Ingestion terminal ───────────────────────────────────────
    st.markdown("""
    <div class="terminal-panel">
      <div class="terminal-titlebar">
        <span class="terminal-dot dot-red"></span>
        <span class="terminal-dot dot-yellow"></span>
        <span class="terminal-dot dot-green"></span>
        <span class="terminal-label">THREAT-INTEL-INGESTION // stdin</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Backing state key (avoids "cannot modify after instantiation" error)
    if "_cti_report_text" not in st.session_state:
        st.session_state["_cti_report_text"] = ""

    # Toolbar: LOAD SAMPLE  |  UPLOAD PDF/TXT  — single aligned row
    toolbar_left, toolbar_right = st.columns([1, 3])

    with toolbar_left:
        if st.button("[ LOAD SAMPLE ]", key="load_sample"):
            st.session_state["_cti_report_text"] = SAMPLE_REPORT
            st.rerun()

    with toolbar_right:
        uploaded_file = st.file_uploader(
            "Upload PDF or TXT",
            type=["pdf", "txt"],
            key="pdf_uploader",
            label_visibility="collapsed",
            help="Upload a PDF or TXT threat advisory — text is extracted and loaded into the terminal below.",
        )

    # Process upload immediately after widget renders
    if uploaded_file is not None:
        _extracted_text = ""
        if uploaded_file.type == "application/pdf":
            try:
                from pypdf import PdfReader
                _pdf_bytes = io.BytesIO(uploaded_file.read())
                reader = PdfReader(_pdf_bytes)

                # Many vendor/publisher PDFs are AES owner-locked but still "open"
                # (i.e., readable without a user password). Attempt a blank-password
                # decrypt first before failing out.
                if reader.is_encrypted:
                    try:
                        reader.decrypt("")
                    except Exception:
                        # Genuinely password-protected — can't read without the key
                        st.markdown(
                            '<div class="cti-error">'
                            'PDF EXTRACTION FAILED — This PDF is password-protected. '
                            'Please remove the password or copy/paste the text manually.'
                            '</div>',
                            unsafe_allow_html=True,
                        )
                        reader = None  # skip page read

                if reader is not None:
                    _extracted_text = "\n".join(
                        page.extract_text() or "" for page in reader.pages
                    ).strip()

            except Exception as _pdf_err:
                st.markdown(
                    f'<div class="cti-error">PDF EXTRACTION FAILED — {_pdf_err}</div>',
                    unsafe_allow_html=True,
                )
        else:
            _extracted_text = uploaded_file.read().decode("utf-8", errors="replace").strip()

        if _extracted_text and _extracted_text != st.session_state.get("_cti_report_text", ""):
            st.session_state["_cti_report_text"] = _extracted_text
            st.rerun()

    report_text = st.text_area(
        label="Threat Report Input",
        value=st.session_state["_cti_report_text"],
        height=160,
        placeholder="$ paste threat advisory · load sample · or browse to upload a .pdf / .txt file above…",
        label_visibility="collapsed",
    )

    with st.container():
        st.markdown('<div class="analyze-btn">', unsafe_allow_html=True)
        analyze = st.button("EXECUTE PIPELINE  //  ANALYZE + GENERATE DETECTION", key="analyze")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<hr>", unsafe_allow_html=True)

    # ── PIPELINE EXECUTION ────────────────────────────────────────────────
    if analyze:
        if not report_text.strip():
            st.markdown('<div class="cti-error">⚠ Input is empty — paste a threat report above.</div>',
                        unsafe_allow_html=True)
            return

        with st.status("Running Agentic-CTI pipeline…", expanded=True) as status:
            # Warn analyst if input will be auto-truncated (large PDF ingestion)
            if len(report_text) > MAX_INPUT_CHARS:
                st.warning(
                    f"Input is {len(report_text):,} chars — pipeline will analyse the "
                    f"first {MAX_INPUT_CHARS:,} chars to fit the LLM context window. "
                    "IOCs in the latter portion of the document will be skipped.",
                    icon="⚠",
                )
            st.write("▸ Node 0 — Prompt injection scan…")
            st.write("▸ Node 1 — Extracting structured intelligence via Llama-3.3…")
            try:
                result = run_pipeline(report_text)

                # Show accurate per-node status based on actual results
                if result.get("extracted_report"):
                    st.write("▸ Node 1 — Extraction complete.")
                    st.write("▸ Node 2 — RAG similarity search complete.")
                    if result.get("final_yaral_rule"):
                        st.write("▸ Node 3/4 — YARA-L generated and validated.")
                        status.update(label="✓ Pipeline complete — detection rule ready.", state="complete", expanded=False)
                    else:
                        st.write("▸ Node 3/4 — YARA-L generation exhausted retries.")
                        status.update(label="✗ YARA-L generation failed after retries.", state="error", expanded=False)
                else:
                    err = result.get("extraction_error") or "LLM did not return valid JSON"
                    st.error(f"Node 1 — Extraction failed: {err}")
                    status.update(label="✗ Extraction failed — see error below.", state="error", expanded=False)

            except Exception as exc:
                status.update(label=f"✗ Fatal error: {exc}", state="error")
                st.markdown(f'<div class="cti-error">Fatal: {exc}</div>', unsafe_allow_html=True)
                return

        # Pipeline error banner
        if result.get("pipeline_error") and not result.get("final_yaral_rule"):
            st.markdown(
                f'<div class="cti-error">✗ PIPELINE ERROR — {result["pipeline_error"]}</div>',
                unsafe_allow_html=True,
            )

        # ── BOTTOM ROW: 2 : 3 split ───────────────────────────────────────
        left_col, right_col = st.columns([2, 3], gap="medium")

        extracted: ThreatIntelReport | None = result.get("extracted_report")
        rag: dict = result.get("rag_context") or {}
        final_rule: str | None = result.get("final_yaral_rule")
        validation_err: str | None = result.get("yaral_validation_error")
        retry_count: int = result.get("retry_count", 0)

        # ================================================================
        # LEFT COLUMN — Intel Tags + RAG Map
        # ================================================================
        with left_col:

            # ── Extracted Intelligence Card ───────────────────────────
            st.markdown('<div class="soc-card">', unsafe_allow_html=True)
            st.markdown(
                '<div class="soc-card-title"><span>▸</span> EXTRACTED THREAT INTELLIGENCE</div>',
                unsafe_allow_html=True,
            )

            if extracted:
                # Threat actor
                st.markdown(
                    f'<div class="intel-badge-group">'
                    f'<div class="intel-badge-label">THREAT ACTOR</div>'
                    f'<span class="intel-badge badge-actor">⬡ {extracted.threat_actor or "Unknown"}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

                # Malware families
                if extracted.malware_families:
                    badges = " ".join(
                        f'<span class="intel-badge badge-malware">⬡ {m}</span>'
                        for m in extracted.malware_families
                    )
                    st.markdown(
                        f'<div class="intel-badge-group">'
                        f'<div class="intel-badge-label">MALWARE FAMILIES</div>'
                        f'{badges}</div>',
                        unsafe_allow_html=True,
                    )

                # MITRE ATT&CK TTPs
                if extracted.mitre_ttps:
                    ttp_pills = " ".join(
                        f'<span class="intel-badge badge-ttp">{t}</span>'
                        for t in extracted.mitre_ttps
                    )
                    st.markdown(
                        f'<div class="intel-badge-group">'
                        f'<div class="intel-badge-label">MITRE ATT&CK TTPs</div>'
                        f'{ttp_pills}</div>',
                        unsafe_allow_html=True,
                    )

                # IOC Chips
                ioc_dict = extracted.iocs if isinstance(extracted.iocs, dict) else extracted.iocs
                ioc_total = (
                    len(list(ioc_dict.ips or []) if hasattr(ioc_dict, "ips") else ioc_dict.get("ips", []))
                    + len(list(ioc_dict.domains or []) if hasattr(ioc_dict, "domains") else ioc_dict.get("domains", []))
                    + len(list(ioc_dict.hashes or []) if hasattr(ioc_dict, "hashes") else ioc_dict.get("hashes", []))
                )
                st.markdown(
                    f'<div class="intel-badge-label" style="margin-top:14px;">INDICATORS OF COMPROMISE '
                    f'<span style="color:#00d4ff;">({ioc_total})</span></div>',
                    unsafe_allow_html=True,
                )
                st.markdown(_ioc_chips_html(ioc_dict), unsafe_allow_html=True)

                # Raw JSON expander
                st.markdown("<br>", unsafe_allow_html=True)
                with st.expander("{ } Raw Extracted JSON"):
                    st.json(json.loads(extracted.model_dump_json()))

            else:
                err_txt = result.get("extraction_error") or "LLM did not return valid JSON."
                st.markdown(
                    f'<div class="cti-error">EXTRACTION FAILED — {err_txt}</div>',
                    unsafe_allow_html=True,
                )
                raw_llm = result.get("llm_raw_response")
                if raw_llm:
                    with st.expander("View Raw LLM Response (debug)"):
                        st.code(raw_llm[:2000], language="text")
                else:
                    st.markdown(
                        '<div class="cti-info">No LLM response captured — '
                        'the API call may have failed before returning.</div>',
                        unsafe_allow_html=True,
                    )

            st.markdown("</div>", unsafe_allow_html=True)

            # ── RAG Similarity Card ───────────────────────────────────
            top_score: float = rag.get("top_similarity_score", 0.0)
            col_size: int = rag.get("collection_size", 0)
            matches: list = rag.get("matches", [])
            sc_color = _score_color(top_score)
            pct = int(top_score * 100)

            st.markdown('<div class="soc-card">', unsafe_allow_html=True)
            st.markdown(
                '<div class="soc-card-title"><span>▸</span> QDRANT RAG SIMILARITY MAP</div>',
                unsafe_allow_html=True,
            )

            st.markdown(
                f"""
                <div class="rag-score-display">
                  <div>
                    <div class="rag-score-value" style="color:{sc_color};">{top_score:.4f}</div>
                    <div class="rag-score-label">Cosine Similarity</div>
                  </div>
                  <div class="score-bar-track">
                    <div class="score-bar-fill"
                         style="width:{pct}%; background:linear-gradient(90deg,{sc_color}88,{sc_color});"></div>
                  </div>
                  <div style="text-align:right;">
                    <div class="rag-score-value" style="font-size:1.3rem; color:#00d4ff;">{col_size + 1}</div>
                    <div class="rag-score-label">KB Records</div>
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if matches:
                for i, m in enumerate(matches, 1):
                    sc = m["score"]
                    st.markdown(
                        f"""
                        <div class="match-card">
                          <span class="match-score-pill">{sc:.4f}</span>
                          <div class="match-card-actor">#{i} {m['threat_actor']}</div>
                          <div class="match-card-detail">
                            TTPs: {', '.join(m['mitre_ttps']) or 'N/A'}<br>
                            Malware: {', '.join(m['malware_families']) or 'N/A'}
                          </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown(
                    '<div class="cti-info">ℹ No prior matches found — '
                    'current report ingested into knowledge base. '
                    'Future analyses will produce similarity scores.</div>',
                    unsafe_allow_html=True,
                )

            st.markdown("</div>", unsafe_allow_html=True)

        # ================================================================
        # RIGHT COLUMN — YARA-L Detection Rule (maximum width)
        # ================================================================
        with right_col:

            # Rule status badge HTML
            if final_rule:
                status_badge = '<span class="yaral-status-badge badge-validated">✓ VALIDATED</span>'
            else:
                status_badge = '<span class="yaral-status-badge badge-failed">✗ FAILED</span>'

            retry_info = ""
            if retry_count > 0:
                retry_info = (
                    f'<span style="font-size:0.65rem; color:#ffb84d; margin-left:10px;">'
                    f'{"corrected after" if final_rule else "exhausted"} {retry_count} retr{"y" if retry_count==1 else "ies"}'
                    f'</span>'
                )

            st.markdown(
                f"""
                <div class="yaral-container">
                  <div class="yaral-titlebar">
                    <div class="yaral-title-left">
                      YARA-L 2.0 // Google SecOps Detection Rule{retry_info}
                    </div>
                    {status_badge}
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if final_rule:
                st.markdown('<div class="yaral-code-inner">', unsafe_allow_html=True)
                st.code(final_rule, language="text")
                st.markdown("</div>", unsafe_allow_html=True)

                rule_name = (
                    extracted.threat_actor.lower().replace(" ", "_").replace("(", "").replace(")", "")
                    if extracted else "rule"
                )
                st.download_button(
                    label="⬇  EXPORT  //  Download .yaral rule file",
                    data=final_rule,
                    file_name=f"agentic_cti_{rule_name}.yaral",
                    mime="text/plain",
                    key="dl_rule",
                )
            else:
                st.markdown(
                    '<div class="cti-error">✗ Could not produce a valid YARA-L rule after maximum retries.</div>',
                    unsafe_allow_html=True,
                )
                if validation_err:
                    with st.expander("View Last Validation Error"):
                        st.code(validation_err, language="text")
                if result.get("yaral_draft"):
                    with st.expander("View Last Draft (unvalidated)"):
                        st.code(result["yaral_draft"], language="text")

            # ── Pipeline Metadata Grid ────────────────────────────────
            st.markdown('<div class="soc-card" style="margin-top:12px;">', unsafe_allow_html=True)
            st.markdown(
                '<div class="soc-card-title"><span>▸</span> PIPELINE METADATA</div>',
                unsafe_allow_html=True,
            )

            retry_class = "warn" if retry_count > 0 else "ok"
            score_class = "ok" if top_score >= 0.7 else ("warn" if top_score >= 0.4 else "")
            ioc_c = ioc_total if extracted else 0
            ttp_c = len(extracted.mitre_ttps) if extracted else 0

            st.markdown(
                f"""
                <div class="meta-grid">
                  <div class="meta-item">
                    <div class="meta-label">LLM Model</div>
                    <div class="meta-value" style="font-size:0.85rem;">Llama-3.3-70B</div>
                  </div>
                  <div class="meta-item">
                    <div class="meta-label">Provider</div>
                    <div class="meta-value" style="font-size:0.85rem;">Groq API</div>
                  </div>
                  <div class="meta-item">
                    <div class="meta-label">Retries Used</div>
                    <div class="meta-value {retry_class}">{retry_count}/3</div>
                  </div>
                  <div class="meta-item">
                    <div class="meta-label">IOCs Extracted</div>
                    <div class="meta-value">{ioc_c}</div>
                  </div>
                  <div class="meta-item">
                    <div class="meta-label">TTPs Identified</div>
                    <div class="meta-value">{ttp_c}</div>
                  </div>
                  <div class="meta-item">
                    <div class="meta-label">RAG Score</div>
                    <div class="meta-value {score_class}">{top_score:.4f}</div>
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown("</div>", unsafe_allow_html=True)

    # ── Landing state ─────────────────────────────────────────────────────
    else:
        st.markdown(
            """
            <div style="
                border: 1px dashed #1a3a5c;
                border-radius: 6px;
                padding: 60px 20px;
                text-align: center;
                background: rgba(0,212,255,0.02);
            ">
              <div style="font-size:2.5rem; margin-bottom:14px; opacity:0.5;"></div>
              <div style="
                  font-family: 'JetBrains Mono', monospace;
                  font-size:0.9rem;
                  color:#2a5a7a;
                  margin-bottom:8px;
                  letter-spacing:0.06em;
              ">AWAITING INPUT // PASTE THREAT REPORT AND EXECUTE PIPELINE</div>
              <div style="font-size:0.75rem; color:#1a3a52; font-family:'JetBrains Mono',monospace;">
                Extract IOCs · Query Knowledge Base · Generate YARA-L 2.0 Detection Rule
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


if __name__ == "__main__":
    main()
