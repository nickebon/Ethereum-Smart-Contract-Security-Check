"""
Smart Contract Security Dashboard
"""

import streamlit as st
import json

st.set_page_config(
    page_title="SC Audit Dashboard",
    page_icon="🔒",
    layout="wide"
)

st.markdown("""
<style>
  /* Hard-reset every Streamlit surface */
  html, body,
  [data-testid="stAppViewContainer"],
  [data-testid="stAppViewBlockContainer"],
  [data-testid="stMain"],
  [data-testid="stHeader"],
  [data-testid="stToolbar"],
  [data-testid="stBottom"],
  [data-testid="stSidebar"],
  section[data-testid="stSidebar"],
  .main, .block-container,
  [class*="css"] {
    background-color: #f7f6f2 !important;
    color: #1a1a18 !important;
    color-scheme: light !important;
  }

  /* All text elements */
  p, span, div, label, li, td, th, small,
  [class*="stMarkdown"], [class*="stText"] {
    color: #1a1a18 !important;
  }

  /* Inputs */
  input, textarea, select,
  [data-baseweb="input"], [data-baseweb="select"], [data-baseweb="textarea"] {
    background-color: #ffffff !important;
    color: #1a1a18 !important;
    border-color: #e5e4e0 !important;
  }

  /* Expanders */
  [data-testid="stExpander"],
  [data-testid="stExpander"] > div,
  details, details > summary {
    background-color: #ffffff !important;
    color: #1a1a18 !important;
    border-color: #e5e4e0 !important;
  }

  /* Metrics */
  [data-testid="metric-container"] {
    background-color: #ffffff !important;
    border: 1px solid #e5e4e0 !important;
  }
  [data-testid="stMetricValue"],
  [data-testid="stMetricLabel"],
  [data-testid="stMetricDelta"] { color: #1a1a18 !important; }

  /* Code blocks */
  code, pre,
  [data-testid="stCode"], [data-testid="stCodeBlock"], [class*="stCode"] {
    background-color: #f0efeb !important;
    color: #1a1a18 !important;
    border-color: #e5e4e0 !important;
  }

  /* Tabs */
  [data-baseweb="tab-list"],
  [data-baseweb="tab"],
  [data-baseweb="tab-panel"] {
    background-color: #f7f6f2 !important;
    color: #1a1a18 !important;
  }

  /* File uploader */
  [data-testid="stFileUploader"],
  [data-testid="stFileUploaderDropzone"] {
    background-color: #ffffff !important;
    border-color: #ccc !important;
    color: #1a1a18 !important;
  }

  /* Alerts */
  [data-testid="stAlert"], .stAlert,
  [data-testid="stAlertContentInfo"],
  [data-testid="stAlertContentSuccess"],
  [data-testid="stAlertContentWarning"],
  [data-testid="stAlertContentError"] {
    background-color: #f0efeb !important;
    color: #1a1a18 !important;
  }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: #f7f6f2 !important; }
  ::-webkit-scrollbar-thumb { background: #ccc !important; }

  /* st.json viewer and syntax highlighter — these have their own shadow styling */
  [data-testid="stJson"],
  [data-testid="stJson"] > div,
  .stJson, .stCodeBlock,
  pre[class*="language-"],
  code[class*="language-"],
  .highlight, .highlight pre,
  div[data-testid="stCode"] > div,
  div[data-testid="stCode"] pre {
    background-color: #f0efeb !important;
    color: #1a1a18 !important;
    border: 1px solid #e5e4e0 !important;
  }
</style>
""", unsafe_allow_html=True)

# ── P-CATEGORY REFERENCE (from p_mapping.yaml) ───────────────────────────────
P_CATEGORIES = {
    "P1":  {"name": "Reentrancy",                  "swc": ["SWC-107"],                           "slither": ["reentrancy", "reentrancy-eth", "reentrancy-no-eth"]},
    "P2":  {"name": "Access Control",              "swc": ["SWC-105", "SWC-106", "SWC-118", "SWC-124"], "slither": ["missing-ownable", "tx-origin", "suicidal", "unprotected-upgrade"]},
    "P3":  {"name": "Arithmetic / Overflow",       "swc": ["SWC-101"],                           "slither": ["arbitrary-send-erc20", "unchecked-transfer", "divide-before-multiply"]},
    "P4":  {"name": "TOD / Front-running",         "swc": ["SWC-114", "SWC-116"],                "slither": ["timestamp", "blockhash-usage", "weak-randomness"]},
    "P5":  {"name": "Denial of Service",           "swc": ["SWC-113"],                           "slither": ["dos-with-revert", "dos-unbounded-operations"]},
    "P6":  {"name": "Uninitialized / Defaults",    "swc": ["SWC-109", "SWC-110"],                "slither": ["uninitialized-state", "uninitialized-storage", "uninitialized-local"]},
    "P7":  {"name": "Delegatecall / Callcode",     "swc": ["SWC-112"],                           "slither": ["controlled-delegatecall", "dangerous-delegatecall"]},
    "P8":  {"name": "Insecure Ether Handling",     "swc": ["SWC-105"],                           "slither": ["arbitrary-send", "unchecked-send", "dangerous-low-level-call"]},
    "P9":  {"name": "Access Modifier / Visibility","swc": ["SWC-100", "SWC-108"],                "slither": ["missing-zero-check", "unused-return"]},
    "P10": {"name": "Cross-Function Reentrancy",   "swc": ["SWC-107"],                           "slither": ["reentrancy-unlimited-gas"]},
    "P11": {"name": "Short Address / Encoding",    "swc": ["SWC-123"],                           "slither": ["abi-encode-packed", "incorrect-shift"]},
    "P12": {"name": "Unsafe Cast / Type",          "swc": ["SWC-123", "SWC-128"],                "slither": ["tautological-compare", "incorrect-cast"]},
    "P13": {"name": "Oracle / Price Manipulation", "swc": [],                                    "slither": ["weak-prng", "manipulable-oracle"]},
    "P14": {"name": "Upgradeability / Proxy Risks","swc": ["SWC-115"],                           "slither": ["transparent-upgradeable-proxy", "initializer-usage"]},
    "P15": {"name": "Misc / Others",               "swc": [],                                    "slither": []},
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "unknown": 5}

def p_sort_key(p_str):
    """Sort P-categories numerically; unmapped/None goes to end."""
    if not p_str or p_str.strip() == "" or p_str.upper() == "N/A":
        return (999, 0)
    try:
        num = int(p_str.upper().replace("P", "").split("-")[0])
        return (0, num)
    except Exception:
        return (999, 0)

def severity_badge(severity):
    sev = severity.lower() if severity else "unknown"
    colors = {
        "critical":      ("#7f1d1d", "#ffffff"),
        "high":          ("#9a3412", "#ffffff"),
        "medium":        ("#78350f", "#ffffff"),
        "low":           ("#166534", "#ffffff"),
        "informational": ("#1e40af", "#ffffff"),
        "unknown":       ("#374151", "#ffffff"),
    }
    bg, fg = colors.get(sev, colors["unknown"])
    return f'<span style="background:{bg};color:{fg} !important;padding:2px 8px;border-radius:2px;font-size:0.68rem;letter-spacing:0.1em;text-transform:uppercase;font-weight:600;">{sev}</span>'

def p_badge(p_str):
    if not p_str or p_str.strip() == "" or p_str.upper() == "N/A":
        return '<span style="background:#e5e4e0 !important;color:#9a9a96 !important;padding:2px 8px;border-radius:2px;font-size:0.68rem;letter-spacing:0.1em;font-weight:600;">UNMAPPED</span>'
    p_info = P_CATEGORIES.get(p_str.upper(), None)
    if p_info:
        label = f"{p_str.upper()} · {p_info['name']}"
        return f'<span style="background:#1a1a18 !important;color:#f7f6f2 !important;padding:2px 8px;border-radius:2px;font-size:0.68rem;letter-spacing:0.1em;font-weight:600;">{label}</span>'
    else:
        # P-value exists but not in our yaml (e.g. P0) — show it but flag as unrecognised
        return f'<span style="background:#e5e4e0 !important;color:#4a4a46 !important;border:1px dashed #9a9a96;padding:2px 8px;border-radius:2px;font-size:0.68rem;letter-spacing:0.1em;font-weight:600;">{p_str.upper()} · Unrecognised</span>'

def swc_badge(swc_str):
    if not swc_str or swc_str.upper() == "N/A":
        return '<span style="border:1px solid #4b5563;color:#6b7280;padding:2px 8px;border-radius:2px;font-size:0.68rem;letter-spacing:0.08em;">SWC: —</span>'
    return f'<span style="border:1px solid #4a4a46;color:#4a4a46;padding:2px 8px;border-radius:2px;font-size:0.68rem;letter-spacing:0.08em;">{swc_str}</span>'

# ── GLOBAL CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&display=swap');

  /* Base */
  html, body, [class*="css"] {
    font-family: -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Helvetica, Arial, sans-serif;
    background-color: #f7f6f2;
    color: #1a1a18;
  }

  .main > div { padding-top: 1.5rem; }
  .block-container { padding: 2rem 3rem; max-width: 1100px; }

  /* Typography overrides */
  h1 { font-weight: 900; font-size: 2.2rem; letter-spacing: -0.03em; color: #1a1a18; }
  h2 { font-weight: 700; font-size: 0.78rem; letter-spacing: 0.1em; text-transform: uppercase; color: #4a4a46; margin-top: 2.5rem; }
  h3 { font-weight: 600; font-size: 0.9rem; color: #1a1a18; }

  /* Remove default streamlit blue tint */
  .stAlert { background: #f0efeb; border-left: 3px solid #1a1a18; border-radius: 0; color: #4a4a46; }

  /* Metrics */
  [data-testid="metric-container"] {
    background: white;
    border: 1px solid #e5e4e0;
    padding: 1.2rem 1.5rem;
    border-radius: 0;
  }
  [data-testid="stMetricLabel"] { font-size: 0.68rem !important; letter-spacing: 0.12em; text-transform: uppercase; color: #9a9a96; font-weight: 500; }
  [data-testid="stMetricValue"] { font-size: 2.4rem !important; font-weight: 900; letter-spacing: -0.03em; color: #1a1a18; }
  [data-testid="stMetricDelta"] { font-size: 0.8rem; }

  /* Tabs */
  .stTabs [data-baseweb="tab-list"] {
    gap: 0;
    border-bottom: 1px solid #1a1a18;
    background: transparent;
  }
  .stTabs [data-baseweb="tab"] {
    font-size: 0.72rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    font-weight: 500;
    color: #9a9a96;
    padding: 0.75rem 1.5rem;
    border-radius: 0;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
  }
  .stTabs [aria-selected="true"] {
    color: #1a1a18;
    border-bottom: 2px solid #1a1a18;
    background: transparent;
  }

  /* Expanders */
  .stExpander {
    border: 1px solid #e5e4e0;
    border-radius: 0;
    background: white;
    margin-bottom: 0.5rem;
  }
  .stExpander summary { font-size: 0.88rem; font-weight: 500; }

  /* File uploader */
  [data-testid="stFileUploader"] {
    background: white;
    border: 1px dashed #ccc;
    border-radius: 0;
    padding: 0.5rem;
  }

  /* Fix file uploader button contrast */
  [data-testid="stFileUploaderDropzoneInput"] + button,
  [data-testid="stBaseButton-secondary"] {
    background-color: #ffffff !important;
    color: #1a1a18 !important;
    border: 1px solid #1a1a18 !important;
  }

  /* Dividers */
  hr { border: none; border-top: 1px solid rgba(26,26,24,0.12); margin: 2rem 0; }

  /* Code blocks */
  code { 
    font-family: 'IBM Plex Mono', monospace; 
    font-size: 0.8rem; 
    background: #f0efeb; 
    padding: 1px 5px; 
    border-radius: 2px;
    color: #1a1a18;
  }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: #f7f6f2; }
  ::-webkit-scrollbar-thumb { background: #ccc; }

  /* Unmapped warning row */
  .unmapped-section-label {
    font-size: 0.65rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: #9a9a96;
    margin: 1.5rem 0 0.5rem;
    padding-top: 1rem;
    border-top: 1px dashed #d1d0cb;
  }

  /* Prevent Streamlit from overriding span colors */
  .stMarkdown span {
    color: inherit !important;
  }
</style>
""", unsafe_allow_html=True)

# ── HEADER ────────────────────────────────────────────────────────────────────
st.markdown('<p style="font-size:0.65rem;letter-spacing:0.2em;text-transform:uppercase;color:#9a9a96;margin-bottom:0.2rem;">UTS Capstone 2026</p>', unsafe_allow_html=True)
st.title("Smart Contract Audit Dashboard")
st.markdown('<hr>', unsafe_allow_html=True)

# ── SIDEBAR ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("#### Upload deduplicated result")
    uploaded = st.file_uploader(
        "JSON output from llm_deduplicator.py",
        type=["json"],
        label_visibility="collapsed"
    )

# ── TABS ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["Analysis", "P-Category & SWC Reference", "Settings & Configuration"])

# ═════════════════════════════════════════════════════════════════════════════
with tab1:
    if not uploaded:
        st.markdown("""
        <div style="background:white;border:1px dashed #d1d0cb;padding:3rem 2rem;text-align:center;margin-top:1.5rem;">
            <p style="color:#9a9a96;font-size:0.85rem;margin:0;">Upload a <code>*_deduplicated.json</code> file in the sidebar to view findings.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        try:
            data = json.load(uploaded)
        except json.JSONDecodeError:
            st.error("Invalid JSON. Upload a valid deduplicated output file.")
            st.stop()

        contract_name = uploaded.name.replace("_deduplicated.json", "").replace("_", " ").title()
        summary = data.get("summary", {})
        input_count  = summary.get("total_input", data.get("input_count", 0))
        unique_count = summary.get("unique_count", 0)
        removed      = summary.get("duplicates_removed", input_count - unique_count)
        reduction    = (removed / input_count * 100) if input_count > 0 else 0

        st.markdown(f'<p style="font-size:0.65rem;letter-spacing:0.18em;text-transform:uppercase;color:#9a9a96;margin-bottom:0.1rem;">Contract</p>', unsafe_allow_html=True)
        st.markdown(f'<h2 style="font-size:1.6rem;font-weight:900;letter-spacing:-0.02em;color:#1a1a18;margin-top:0;text-transform:none;">{contract_name}</h2>', unsafe_allow_html=True)

        # Metrics
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Raw Alerts", input_count, help="Total findings from Slither + Mythril before deduplication")
        with c2:
            st.metric("Unique Vulnerabilities", unique_count, help="Semantically distinct vulnerabilities after LLM grouping")
        with c3:
            st.metric("Alerts Removed", removed, delta=f"−{reduction:.0f}%", delta_color="inverse", help="Duplicate / overlapping alerts collapsed")

        st.markdown('<hr>', unsafe_allow_html=True)

        # ── VULNERABILITY LIST ─────────────────────────────────────────────
        st.markdown("## Findings")

        vulnerabilities = data.get("unique_vulnerabilities", [])
        if not vulnerabilities:
            st.success("No vulnerabilities found in this contract.")
        else:
            # Partition: mapped vs unmapped P-category
            def is_unmapped(v):
                p = v.get("ethtrust_rule", v.get("p_category", ""))
                return not p or p.strip() == "" or p.upper() == "N/A"

            mapped   = [v for v in vulnerabilities if not is_unmapped(v)]
            unmapped = [v for v in vulnerabilities if is_unmapped(v)]

            # Sort mapped: P-category number, then severity
            mapped_sorted = sorted(
                mapped,
                key=lambda v: (
                    p_sort_key(v.get("ethtrust_rule", v.get("p_category", ""))),
                    SEVERITY_ORDER.get(v.get("severity", "unknown").lower(), 5)
                )
            )
            unmapped_sorted = sorted(
                unmapped,
                key=lambda v: SEVERITY_ORDER.get(v.get("severity", "unknown").lower(), 5)
            )

            all_sorted = mapped_sorted + unmapped_sorted
            unmapped_start_idx = len(mapped_sorted)

            for idx, vuln in enumerate(all_sorted):
                # Section label before unmapped group
                if idx == unmapped_start_idx and unmapped_sorted:
                    st.markdown('<div class="unmapped-section-label">Unmapped — P-category not resolved</div>', unsafe_allow_html=True)

                severity = vuln.get("severity", "unknown")
                p_cat    = vuln.get("ethtrust_rule", vuln.get("p_category", ""))
                swc_id   = vuln.get("swc_id", "")
                name     = vuln.get("name", "Unknown Vulnerability")
                location = vuln.get("location", "Not specified")
                reasoning= vuln.get("reasoning", "No analysis provided.")
                finding_ids = vuln.get("finding_ids", [])
                unmapped_flag = is_unmapped(vuln)

                # Expander label
                sev_upper = severity.upper() if severity else "UNKNOWN"
                p_label   = p_cat.upper() if p_cat and p_cat.upper() != "N/A" else "—"
                exp_label = f"{p_label}  ·  {name}  ·  {sev_upper}"

                auto_expand = severity.lower() in ["critical", "high"]

                with st.expander(exp_label, expanded=auto_expand):
                    # Classification row
                    badge_html = f"""
                    <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;margin-bottom:1.2rem;">
                      {severity_badge(severity)}
                      {p_badge(p_cat if p_cat else "")}
                      {swc_badge(swc_id if swc_id else "")}
                    </div>
                    """
                    if unmapped_flag:
                        badge_html += '<p style="font-size:0.75rem;color:#9a9a96;background:#f7f6f2;border:1px dashed #d1d0cb;padding:0.5rem 0.75rem;margin-bottom:1rem;">This finding could not be mapped to an EthTrust P-category or SWC ID. Manual review recommended.</p>'
                    st.markdown(badge_html, unsafe_allow_html=True)

                    left, right = st.columns([3, 1.2])

                    with left:
                        st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin-bottom:0.2rem;">Location</p>', unsafe_allow_html=True)
                        st.code(location, language=None)

                        st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin:0.8rem 0 0.2rem;">LLM Reasoning</p>', unsafe_allow_html=True)
                        st.markdown(f'<p style="font-size:0.85rem;color:#1a1a18;line-height:1.6;">{reasoning}</p>', unsafe_allow_html=True)

                    with right:
                        st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin-bottom:0.4rem;">Source Alerts</p>', unsafe_allow_html=True)
                        st.markdown(f'<p style="font-size:1.6rem;font-weight:900;letter-spacing:-0.03em;color:#1a1a18;margin:0;">{len(finding_ids)}</p>', unsafe_allow_html=True)
                        st.markdown(f'<p style="font-size:0.72rem;color:#9a9a96;">IDs: {", ".join(map(str, finding_ids))}</p>', unsafe_allow_html=True)

        st.markdown('<hr>', unsafe_allow_html=True)
        st.markdown("## Analysis Metadata")

        m1, m2, m3 = st.columns(3)
        with m1:
            st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin-bottom:0.2rem;">LLM Model</p>', unsafe_allow_html=True)
            st.code(data.get("llm_model", "GPT-4o"))
        with m2:
            st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin-bottom:0.2rem;">Temperature</p>', unsafe_allow_html=True)
            st.code("0 (deterministic)")
        with m3:
            st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin-bottom:0.2rem;">Deduplication Rate</p>', unsafe_allow_html=True)
            st.code(f"{reduction:.1f}%")

        with st.expander("Raw summary JSON"):
            st.code(json.dumps(summary, indent=2), language="json")

# ═════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("## P-Category & SWC Reference")
    st.markdown('<p style="color:#4a4a46;font-size:0.85rem;max-width:60ch;">EthTrust-SL P-categories (P1–P15) used to classify findings in this pipeline. Each maps to one or more SWC IDs (Mythril) and Slither detector names.</p>', unsafe_allow_html=True)
    st.markdown('<hr>', unsafe_allow_html=True)

    for p_id, info in P_CATEGORIES.items():
        swc_list     = ", ".join(info["swc"])     if info["swc"]     else "—"
        slither_list = ", ".join(info["slither"]) if info["slither"] else "—"
        with st.expander(f"{p_id} — {info['name']}"):
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin-bottom:0.3rem;">Mythril SWC IDs</p>', unsafe_allow_html=True)
                st.markdown(f'<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.82rem;color:#1a1a18;">{swc_list}</p>', unsafe_allow_html=True)
            with col_b:
                st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin-bottom:0.3rem;">Slither Detectors</p>', unsafe_allow_html=True)
                st.markdown(f'<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.82rem;color:#1a1a18;">{slither_list}</p>', unsafe_allow_html=True)

# ═════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown('<hr>', unsafe_allow_html=True)

    st.markdown("#### Analysis Configuration")
    st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin-bottom:0.2rem;">LLM Model</p>', unsafe_allow_html=True)
    st.code("Azure OpenAI GPT-4o")
    st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin:0.8rem 0 0.2rem;">Temperature</p>', unsafe_allow_html=True)
    st.code("0 — deterministic output")
    st.markdown('<p style="font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:#9a9a96;margin:0.8rem 0 0.2rem;">Deduplication Method</p>', unsafe_allow_html=True)
    st.code("Semantic similarity via LLM prompt")

    st.markdown('<hr>', unsafe_allow_html=True)

    st.markdown('<p style="font-size:0.65rem;letter-spacing:0.14em;text-transform:uppercase;color:#9a9a96;">AI Disclosure — All findings should be verified by a qualified reviewer. Automated analysis can produce false positives and may omit context.</p>', unsafe_allow_html=True)