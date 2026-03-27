"""
Smart Contract Security Dashboard
LLM-Powered Vulnerability Deduplication
"""

import streamlit as st
import json
from pathlib import Path

st.set_page_config(
    page_title="Smart Contract Audit Dashboard",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS for professional styling
st.markdown("""
<style>
    /* Main container styling */
    .main > div {
        padding-top: 2rem;
    }
    
    /* Info banner styling */
    .stAlert {
        background-color: #e8f4fd;
        border-left: 4px solid #2196F3;
        padding: 1rem;
        margin-bottom: 1.5rem;
    }
    
    /* Metric cards */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: 600;
    }
    
    /* Section headers */
    h1 {
        color: #1e293b;
        font-weight: 700;
        margin-bottom: 0.5rem;
    }
    
    h2 {
        color: #334155;
        font-weight: 600;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    
    h3 {
        color: #475569;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }
    
    /* Upload section */
    .upload-section {
        background-color: #f8fafc;
        border: 2px dashed #cbd5e1;
        border-radius: 8px;
        padding: 2rem;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    /* Vulnerability cards */
    .stExpander {
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        margin-bottom: 0.75rem;
        background-color: white;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
        border-bottom: 2px solid #e2e8f0;
    }
    
    .stTabs [data-baseweb="tab"] {
        padding: 0.75rem 0;
        font-weight: 500;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.title("🔒 Smart Contract Security Audit Dashboard")
st.caption("AI-Powered Vulnerability Deduplication • LLM Synthesis Layer")

# Info banner
st.info("""
**ℹ️ Licensee Responsibility & AI Disclosure**  
The Licensee is solely responsible for selecting and customising the audit items that align with their internal risk appetite. 
While our AI uses deterministic logic to find evidence, it can make errors or omit context. All automated findings should be 
treated as a tool for efficiency and verified by a qualified compliance officer where appropriate.
""")

# Tabs
tab1, tab2, tab3 = st.tabs(["📋 Analysis Dashboard", "📖 Usage Guide", "⚙️ Settings"])

with tab1:
    # Upload section
    st.markdown("### Upload Analysis Results")
    
    uploaded = st.file_uploader(
        "Choose a deduplicated JSON file",
        type=['json'],
        help="Upload the output file from llm_deduplicator.py (e.g., ContractName_deduplicated.json)",
        label_visibility="collapsed"
    )
    
    if uploaded:
        # Load data
        try:
            data = json.load(uploaded)
        except json.JSONDecodeError:
            st.error("❌ Invalid JSON file. Please upload a valid deduplicated JSON file.")
            st.stop()
        
        # Extract contract name
        contract_name = uploaded.name.replace('_deduplicated.json', '').replace('_', ' ').title()
        
        st.divider()
        
        # Contract header
        st.markdown(f"## Analysis Results: **{contract_name}**")
        
        # Summary metrics row
        summary = data.get('summary', {})
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            input_count = summary.get('total_input', 0)
            st.metric(
                label="📥 Input Findings",
                value=input_count,
                help="Total security alerts from Slither and Mythril"
            )
        
        with col2:
            unique_count = summary.get('unique_count', 0)
            st.metric(
                label="✅ Unique Vulnerabilities",
                value=unique_count,
                help="Deduplicated vulnerabilities after LLM semantic grouping"
            )
        
        with col3:
            removed = summary.get('duplicates_removed', 0)
            if input_count > 0:
                reduction_pct = (removed / input_count) * 100
            else:
                reduction_pct = 0
            st.metric(
                label="🗑️ Cascading Alerts Removed",
                value=removed,
                delta=f"-{reduction_pct:.0f}%",
                delta_color="inverse",
                help="Duplicate alerts collapsed through semantic understanding"
            )
        
        st.divider()
        
        # Vulnerabilities section
        st.markdown("## 1. Vulnerability Findings & Risk Assessment")
        
        vulnerabilities = data.get('unique_vulnerabilities', [])
        
        if not vulnerabilities:
            st.success("✅ No vulnerabilities detected in this contract.")
        else:
            # Sort by severity
            severity_order = {
                'critical': 0, 
                'high': 1, 
                'medium': 2, 
                'low': 3, 
                'informational': 4, 
                'unknown': 5
            }
            
            vulnerabilities_sorted = sorted(
                vulnerabilities,
                key=lambda x: severity_order.get(x.get('severity', 'unknown').lower(), 5)
            )
            
            # Display each vulnerability
            for idx, vuln in enumerate(vulnerabilities_sorted, 1):
                severity = vuln.get('severity', 'unknown').lower()
                
                # Severity badge and color
                severity_config = {
                    'critical': {'icon': '🔴', 'color': '#dc2626'},
                    'high': {'icon': '🔴', 'color': '#dc2626'},
                    'medium': {'icon': '🟡', 'color': '#f59e0b'},
                    'low': {'icon': '🟢', 'color': '#10b981'},
                    'informational': {'icon': '🔵', 'color': '#3b82f6'},
                    'unknown': {'icon': '⚪', 'color': '#6b7280'}
                }
                
                config = severity_config.get(severity, severity_config['unknown'])
                
                # Expandable vulnerability card
                with st.expander(
                    f"{config['icon']} **{idx}. {vuln.get('name', 'Unknown Vulnerability')}** — {severity.upper()}",
                    expanded=(severity in ['critical', 'high'])
                ):
                    # Two-column layout
                    left_col, right_col = st.columns([2.5, 1.5])
                    
                    with left_col:
                        st.markdown("#### 📍 Location")
                        location = vuln.get('location', 'Not specified')
                        st.code(location, language=None)
                        
                        st.markdown("#### 📝 Analysis")
                        reasoning = vuln.get('reasoning', 'No analysis provided.')
                        st.write(reasoning)
                    
                    with right_col:
                        st.markdown("#### 🏷️ Classification")
                        swc_id = vuln.get('swc_id', 'N/A')
                        if swc_id and swc_id != 'N/A':
                            st.markdown(f"**SWC Category:** `{swc_id}`")
                        else:
                            st.markdown("**SWC Category:** Not mapped")
                        
                        st.markdown(f"**Severity Level:** `{severity.upper()}`")
                        
                        st.markdown("#### 🔗 Source Alerts")
                        finding_ids = vuln.get('finding_ids', [])
                        st.markdown(f"**Grouped Findings:** {len(finding_ids)}")
                        st.caption(f"Alert IDs: {', '.join(map(str, finding_ids))}")
        
        st.divider()
        
        # Metadata section
        st.markdown("## 2. Analysis Metadata & Configuration")
        
        meta_col1, meta_col2, meta_col3 = st.columns(3)
        
        with meta_col1:
            st.markdown("**LLM Model**")
            st.code(data.get('llm_model', 'Unknown'))
        
        with meta_col2:
            st.markdown("**Total Input Alerts**")
            st.code(str(data.get('input_count', 0)))
        
        with meta_col3:
            st.markdown("**Deduplication Rate**")
            if input_count > 0:
                dedup_rate = (removed / input_count) * 100
                st.code(f"{dedup_rate:.1f}%")
            else:
                st.code("N/A")
        
        # Expandable raw data
        with st.expander("📊 View Raw Summary Data"):
            st.json(summary)
    
    else:
        # Empty state
        st.markdown("""
        <div style="text-align: center; padding: 3rem 1rem; background-color: #f8fafc; border-radius: 8px; border: 2px dashed #cbd5e1;">
            <h3 style="color: #64748b; margin-bottom: 1rem;">📤 No Analysis File Uploaded</h3>
            <p style="color: #94a3b8;">Upload a <code>*_deduplicated.json</code> file above to view vulnerability analysis results.</p>
        </div>
        """, unsafe_allow_html=True)

with tab2:
    st.markdown("## 📖 How to Use This Dashboard")
    
    st.markdown("""
    ### Workflow Overview
    
    This dashboard displays the results of AI-powered smart contract security analysis. Follow these steps:
    """)
    
    # Step 1
    with st.container():
        st.markdown("#### 1. Run Security Analysis")
        st.code("""# Step 1: Run Slither static analysis
slither contract.sol --json output_slither.json

# Step 2: Combine with Mythril results (if available)
python parser.py --slither output_slither.json --mythril mythril.log --out combined.json

# Step 3: Run LLM deduplication
python llm_deduplicator.py combined.json""", language='bash')
    
    # Step 2
    with st.container():
        st.markdown("#### 2. Upload Results")
        st.markdown("Upload the generated `*_deduplicated.json` file using the file uploader in the Analysis Dashboard tab.")
    
    # Step 3
    with st.container():
        st.markdown("#### 3. Review Findings")
        st.markdown("""
        The dashboard displays:
        - **Input Findings:** Total alerts from security tools
        - **Unique Vulnerabilities:** Deduplicated using AI semantic analysis
        - **Cascading Alerts Removed:** How many duplicate alerts were consolidated
        """)
    
    st.divider()
    
    st.markdown("### Understanding the Results")
    
    st.markdown("""
    **Severity Levels:**
    - 🔴 **Critical/High:** Immediate security risks requiring urgent remediation
    - 🟡 **Medium:** Potential vulnerabilities that should be addressed
    - 🟢 **Low:** Minor issues or best practice violations
    - 🔵 **Informational:** Code quality or compliance notices
    
    **SWC Categories:**  
    Vulnerabilities are mapped to the [Smart Contract Weakness Classification (SWC) Registry](https://swcregistry.io/), 
    the industry-standard taxonomy for Ethereum security issues.
    """)

with tab3:
    st.markdown("## ⚙️ Settings & Configuration")
    
    st.markdown("### Analysis Configuration")
    st.markdown("**LLM Model:** Azure OpenAI GPT-5.3")
    st.markdown("**Temperature:** 0 (deterministic output)")
    st.markdown("**Deduplication Method:** Semantic similarity analysis")
    
    st.divider()
    
    st.markdown("### About This Tool")
    st.markdown("""
    This dashboard is part of a UTS Engineering Capstone project exploring LLM-based synthesis 
    of smart contract security tool outputs. The system addresses the "cascading alert problem" 
    where multiple security tools report the same vulnerability in different ways.
    
    **Technology Stack:**
    - Slither (static analysis)
    - Mythril (symbolic execution)
    - Azure OpenAI GPT-5.3 (semantic deduplication)
    - Python + Streamlit (dashboard)
    """)

# Footer
st.divider()
st.caption("🔒 Smart Contract Audit Dashboard • Built with Streamlit • UTS Engineering Capstone 2026")