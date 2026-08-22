import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from pipeline import run_pipeline


import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import tempfile
import urllib.parse

class UploadHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(length)
            fd, path = tempfile.mkstemp(suffix='.csv')
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
            
            # Write to upload_state.py to trigger Streamlit's native auto-reload!
            state_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'upload_state.py')
            with open(state_file, 'w', encoding='utf-8') as f:
                f.write(f'UPLOADED_FILE = {repr(path)}\n')
                
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'OK')
        except Exception as e:
            print("Upload error:", e)
            self.send_response(500)
            self.end_headers()

@st.cache_resource
def start_upload_server():
    try:
        server = HTTPServer(('127.0.0.1', 8503), UploadHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    except OSError:
        pass # Port likely already in use by previous run
    return True

start_upload_server()


st.set_page_config(
    page_title="Network Bouncer X | SOC Intelligence Platform",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# ═══════════════════════════════════════════════════════════════════════════════
# PROCESS UPLOAD
# ═══════════════════════════════════════════════════════════════════════════════
if 'results' not in st.session_state: st.session_state.results = None
if 'processed_file' not in st.session_state: st.session_state.processed_file = None

# Hide sidebar and collapsed control globally
st.markdown("<style>[data-testid='stSidebar'] { display: none !important; } [data-testid='collapsedControl'] { display: none !important; }</style>", unsafe_allow_html=True)

try:
    import dashboard.upload_state as upload_state
    import importlib
    importlib.reload(upload_state)
    uploaded_file_path = upload_state.UPLOADED_FILE
except Exception as e:
    uploaded_file_path = None

if uploaded_file_path and not os.path.exists(uploaded_file_path):
    uploaded_file_path = None

if uploaded_file_path and uploaded_file_path != st.session_state.processed_file:
    st.session_state.processed_file = uploaded_file_path
    
    with st.spinner("⚡ Analyzing network traffic — building baselines, running ensemble detectors..."):
        try:
            # Default parameters since sidebar is removed
            st.session_state.results = run_pipeline(
                uploaded_file_path, 
                window_size=500,
                baseline_ratio=0.4, 
                enable_ml=True
            )
            st.success("Analysis complete! Rendering dashboard...")
        except Exception as e:
            st.error(f"Pipeline error: {e}")
            import traceback; st.code(traceback.format_exc())
        finally:
            try:
                os.unlink(uploaded_file_path)
            except:
                pass

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL THEME & CSS INJECTION
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
/* ── Google Font ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

/* ── Root Variables ── */
:root {
    --bg-primary:    #0B1020;
    --bg-secondary:  #0F172A;
    --bg-card:       #131C35;
    --bg-card-hover: #1A2445;
    --border:        rgba(99,179,237,0.15);
    --border-accent: rgba(99,179,237,0.35);
    --text-primary:  #E2E8F0;
    --text-secondary:#94A3B8;
    --text-muted:    #64748B;
    --cyan:          #22D3EE;
    --blue:          #3B82F6;
    --green:         #10B981;
    --yellow:        #F59E0B;
    --orange:        #F97316;
    --red:           #EF4444;
    --purple:        #8B5CF6;
    --shadow:        0 4px 24px rgba(0,0,0,0.5);
    --shadow-glow:   0 0 20px rgba(34,211,238,0.08);
}

/* ── Global App Background ── */
.stApp, .main, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-primary) !important;
    font-family: 'Inter', sans-serif !important;
    color: var(--text-primary) !important;
}
[data-testid="stHeader"] { background: var(--bg-primary) !important; }
section[data-testid="stSidebar"] {
    background: var(--bg-secondary) !important;
    border-right: 1px solid var(--border) !important;
}

/* ── Sidebar text ── */
section[data-testid="stSidebar"] * { color: var(--text-primary) !important; }
section[data-testid="stSidebar"] .stMarkdown p { color: var(--text-secondary) !important; }

/* ── Block containers ── */
[data-testid="stVerticalBlock"] > div { gap: 0.75rem; }

/* ── Tabs ── */
[data-testid="stTabs"] [data-baseweb="tab-list"] {
    background: var(--bg-secondary) !important;
    border-bottom: 1px solid var(--border) !important;
    gap: 0 !important;
    padding: 0 8px !important;
    border-radius: 10px 10px 0 0 !important;
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    background: transparent !important;
    color: var(--text-muted) !important;
    font-size: 0.78rem !important;
    font-weight: 500 !important;
    padding: 10px 14px !important;
    border-radius: 8px 8px 0 0 !important;
    border: none !important;
    transition: all 0.2s ease !important;
}
[data-testid="stTabs"] [data-baseweb="tab"]:hover {
    color: var(--cyan) !important;
    background: rgba(34,211,238,0.05) !important;
}
[data-testid="stTabs"] [aria-selected="true"] {
    color: var(--cyan) !important;
    background: rgba(34,211,238,0.08) !important;
    border-bottom: 2px solid var(--cyan) !important;
}
[data-testid="stTabs"] [data-baseweb="tab-panel"] {
    background: var(--bg-secondary) !important;
    border: 1px solid var(--border) !important;
    border-radius: 0 0 10px 10px !important;
    padding: 1.5rem !important;
}

/* ── Metric cards ── */
[data-testid="metric-container"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    padding: 1rem 1.25rem !important;
    box-shadow: var(--shadow) !important;
    transition: all 0.2s ease !important;
}
[data-testid="metric-container"]:hover {
    border-color: var(--border-accent) !important;
    box-shadow: var(--shadow-glow) !important;
}
[data-testid="metric-container"] [data-testid="stMetricLabel"] {
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
    color: var(--text-muted) !important;
}
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    font-size: 2rem !important;
    font-weight: 800 !important;
    color: var(--text-primary) !important;
    line-height: 1.1 !important;
}

/* ── DataFrames ── */
[data-testid="stDataFrame"], .stDataFrame {
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
    overflow: hidden !important;
}
[data-testid="stDataFrame"] thead th {
    background: var(--bg-card) !important;
    color: var(--cyan) !important;
    font-size: 0.72rem !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.06em !important;
    border-bottom: 1px solid var(--border) !important;
}
[data-testid="stDataFrame"] tbody tr {
    background: var(--bg-secondary) !important;
    border-bottom: 1px solid var(--border) !important;
    color: var(--text-primary) !important;
    font-size: 0.82rem !important;
}
[data-testid="stDataFrame"] tbody tr:hover {
    background: var(--bg-card-hover) !important;
}

/* ── Expanders ── */
[data-testid="stExpander"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
    margin-bottom: 0.5rem !important;
}
[data-testid="stExpander"] summary {
    color: var(--text-primary) !important;
    font-weight: 500 !important;
}
[data-testid="stExpander"] summary:hover { color: var(--cyan) !important; }

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #1D4ED8, #0E7490) !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
    padding: 0.5rem 1.25rem !important;
    transition: all 0.2s ease !important;
    box-shadow: 0 2px 12px rgba(29,78,216,0.35) !important;
}
.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 20px rgba(29,78,216,0.5) !important;
}

/* ── Info / Warning / Error boxes ── */
[data-testid="stAlert"] {
    border-radius: 10px !important;
    border-left-width: 3px !important;
    font-size: 0.83rem !important;
}

/* ── Sliders ── */
[data-testid="stSlider"] [data-baseweb="slider"] [role="slider"] {
    background: var(--cyan) !important;
}

/* ── Divider ── */
hr { border-color: var(--border) !important; margin: 1rem 0 !important; }

/* ── Plotly charts bg ── */
.js-plotly-plot .plotly { background: transparent !important; }

/* ── Custom card class ── */
.nbx-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
    box-shadow: var(--shadow);
}
.nbx-card-title {
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
}
.nbx-card-accent { border-left: 3px solid var(--cyan); }

/* ── KPI icon row ── */
.kpi-icon { font-size: 1.4rem; margin-bottom: 0.25rem; display: block; }

/* ── Severity badges ── */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}
.badge-critical { background: rgba(239,68,68,0.2); color: #FCA5A5; border: 1px solid rgba(239,68,68,0.4); }
.badge-high     { background: rgba(249,115,22,0.2); color: #FDBA74; border: 1px solid rgba(249,115,22,0.4); }
.badge-medium   { background: rgba(245,158,11,0.2); color: #FDE68A; border: 1px solid rgba(245,158,11,0.4); }
.badge-low      { background: rgba(16,185,129,0.2); color: #6EE7B7; border: 1px solid rgba(16,185,129,0.4); }
.badge-normal   { background: rgba(100,116,139,0.2); color: #CBD5E1; border: 1px solid rgba(100,116,139,0.4); }

/* ── Section headers ── */
.section-header {
    font-size: 1.15rem;
    font-weight: 700;
    color: var(--text-primary);
    border-left: 3px solid var(--cyan);
    padding-left: 0.75rem;
    margin-bottom: 1rem;
}
.section-subheader {
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
}

/* ── Progress bars ── */
.risk-bar-container {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 4px 0;
}
.risk-bar-label {
    font-size: 0.75rem;
    color: var(--text-secondary);
    width: 150px;
    flex-shrink: 0;
}
.risk-bar-track {
    flex: 1;
    height: 6px;
    background: rgba(255,255,255,0.08);
    border-radius: 3px;
    overflow: hidden;
}
.risk-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.5s ease;
}
.risk-bar-value {
    font-size: 0.72rem;
    color: var(--text-muted);
    width: 40px;
    text-align: right;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--border-accent); border-radius: 3px; }

/* ── File uploader — dark themed ── */
[data-testid="stFileUploader"] {
    background: transparent !important;
}
[data-testid="stFileUploader"] > div {
    background: #141b2d !important;
    border: 1.5px dashed rgba(34,211,238,0.45) !important;
    border-radius: 10px !important;
    padding: 0.75rem !important;
    transition: border-color 0.2s ease, background 0.2s ease !important;
}
[data-testid="stFileUploader"] > div:hover {
    border-color: rgba(34,211,238,0.8) !important;
    background: rgba(34,211,238,0.04) !important;
}
[data-testid="stFileUploader"] label {
    color: #94A3B8 !important;
    font-size: 0.78rem !important;
}
[data-testid="stFileUploader"] small,
[data-testid="stFileUploader"] p,
[data-testid="stFileUploader"] span {
    color: #64748B !important;
    font-size: 0.72rem !important;
}
[data-testid="stFileUploader"] [data-testid="stFileUploaderDropzone"] {
    background: #141b2d !important;
    border: 1.5px dashed rgba(34,211,238,0.4) !important;
    border-radius: 8px !important;
}
[data-testid="stFileUploaderDropzone"] svg {
    fill: #22D3EE !important;
    color: #22D3EE !important;
    stroke: #22D3EE !important;
}
[data-testid="stFileUploaderDropzone"] button {
    background: rgba(34,211,238,0.1) !important;
    color: #22D3EE !important;
    border: 1px solid rgba(34,211,238,0.35) !important;
    border-radius: 6px !important;
    font-size: 0.75rem !important;
    font-weight: 600 !important;
}

/* ── Landing animations ── */
@keyframes radar-pulse {
    0%   { transform: scale(1);   opacity: 0.25; }
    50%  { transform: scale(1.12); opacity: 0.08; }
    100% { transform: scale(1);   opacity: 0.25; }
}
@keyframes radar-pulse-2 {
    0%   { transform: scale(1);   opacity: 0.18; }
    50%  { transform: scale(1.08); opacity: 0.06; }
    100% { transform: scale(1);   opacity: 0.18; }
}
@keyframes radar-pulse-3 {
    0%   { transform: scale(1);   opacity: 0.12; }
    50%  { transform: scale(1.05); opacity: 0.04; }
    100% { transform: scale(1);   opacity: 0.12; }
}
@keyframes shield-float {
    0%, 100% { transform: translateY(0px); }
    50%       { transform: translateY(-6px); }
}
@keyframes gradient-slide {
    0%   { background-position: 0% 50%; }
    50%  { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}
@keyframes fade-in-up {
    from { opacity: 0; transform: translateY(16px); }
    to   { opacity: 1; transform: translateY(0); }
}
.nbx-shield-float { animation: shield-float 4s ease-in-out infinite; }
.nbx-fade-in { animation: fade-in-up 0.6s ease forwards; }
.nbx-fade-in-2 { animation: fade-in-up 0.6s ease 0.15s forwards; opacity: 0; }
.nbx-fade-in-3 { animation: fade-in-up 0.6s ease 0.3s forwards; opacity: 0; }
.nbx-fade-in-4 { animation: fade-in-up 0.6s ease 0.45s forwards; opacity: 0; }

/* ── Landing accent bar ── */
.nbx-accent-bar {
    height: 2px;
    width: 120px;
    margin: 0 auto 1.5rem auto;
    background: linear-gradient(90deg, transparent, #22D3EE, #3B82F6, #22D3EE, transparent);
    background-size: 200% 100%;
    animation: gradient-slide 3s ease infinite;
    border-radius: 2px;
}

/* ── Ghost/skeleton cards ── */
.ghost-card {
    background: rgba(19,28,53,0.55);
    border: 1px solid rgba(99,179,237,0.1);
    border-radius: 12px;
    padding: 1rem 0.9rem;
    text-align: center;
    opacity: 0.55;
    transition: opacity 0.2s ease, border-color 0.2s ease;
    position: relative;
    overflow: hidden;
}
.ghost-card::after {
    content: '';
    position: absolute;
    inset: 0;
    background: repeating-linear-gradient(
        -45deg,
        transparent,
        transparent 4px,
        rgba(99,179,237,0.025) 4px,
        rgba(99,179,237,0.025) 8px
    );
    border-radius: 12px;
}
.ghost-card:hover { opacity: 0.75; border-color: rgba(34,211,238,0.25); }
.ghost-bar {
    height: 5px;
    border-radius: 3px;
    background: rgba(99,179,237,0.15);
    margin: 6px auto;
}
.ghost-circle {
    width: 36px; height: 36px;
    border-radius: 50%;
    background: rgba(34,211,238,0.08);
    border: 1px solid rgba(34,211,238,0.15);
    margin: 0 auto 8px auto;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.1rem;
}
</style>
""", unsafe_allow_html=True)

# ── Plotly dark template ─────────────────────────────────────────────────────
PLOTLY_TEMPLATE = dict(
    layout=dict(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(19,28,53,0.6)',
        font=dict(family='Inter', color='#94A3B8', size=12),
        title_font=dict(family='Inter', color='#E2E8F0', size=14),
        xaxis=dict(gridcolor='rgba(99,179,237,0.08)', linecolor='rgba(99,179,237,0.2)',
                   tickfont=dict(color='#94A3B8', size=11)),
        yaxis=dict(gridcolor='rgba(99,179,237,0.08)', linecolor='rgba(99,179,237,0.2)',
                   tickfont=dict(color='#94A3B8', size=11)),
        legend=dict(bgcolor='rgba(0,0,0,0)', font=dict(color='#94A3B8')),
        colorway=['#22D3EE','#3B82F6','#8B5CF6','#10B981','#F59E0B','#EF4444','#F97316'],
    )
)
COLOR_SEV = {'Critical': '#EF4444', 'High': '#F97316', 'Medium': '#F59E0B', 'Low': '#10B981'}
COLOR_DNA = {'Horizontal': '#3B82F6', 'Vertical': '#F97316', 'Hybrid': '#EF4444', 'Normal': '#10B981'}

def apply_theme(fig, height=380):
    fig.update_layout(**PLOTLY_TEMPLATE['layout'], height=height,
                      margin=dict(l=12, r=12, t=40, b=12))
    return fig




results = st.session_state.results

if results is None:
    import streamlit.components.v1 as components
    _landing_path = os.path.join(os.path.dirname(__file__), "landing.html")
    with open(_landing_path, "r", encoding="utf-8") as _f:
        _landing_html = _f.read()
    
    # Make iframe full-bleed by removing Streamlit padding
    st.markdown("""
        <style>
        .block-container {
            padding: 0 !important;
            max-width: 100vw !important;
        }
        .stApp {
            overflow: hidden !important;
        }
        iframe {
            display: block;
            height: 100vh !important;
            width: 100vw !important;
            border: none;
        }
        </style>
    """, unsafe_allow_html=True)
    
    components.html(_landing_html, height=800, scrolling=True)
    st.stop()





# ═══════════════════════════════════════════════════════════════════════════════
# UNPACK RESULTS
# ═══════════════════════════════════════════════════════════════════════════════
records      = results['records']
stories      = results['stories']
summary      = results['summary']
bands        = results['bands']
weights      = results['weights']
thresh       = results['thresholds']
attack_graph = results['attack_graph']
drift        = results['drift']
peer_groups  = results['peer_groups']

df_rec   = pd.DataFrame(records)
alert_df = df_rec[df_rec['is_alert'] == True].copy()
stage_map = {1: 'Normal', 2: 'Exploration', 3: 'Scanning', 4: 'Probable Compromise'}
stage_icon = {'Normal': '🟢', 'Exploration': '🟡', 'Scanning': '🟠', 'Probable Compromise': '🔴'}


# ═══════════════════════════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════════════════════════
tabs = st.tabs([
    "📊 Executive Summary",
    "🎯 Threat Radar",
    "🧬 Scan DNA Explorer",
    "📈 Threat Evolution",
    "🗳️ Ensemble Engine",
    "🔗 Attack Graph",
    "📉 Behavioral Drift",
    "🔎 Explainability Center",
    "🧠 Cognitive Twin Analysis",
    "⚙️ System Config",
    "✅ Validation Dashboard",
])


# ─────────────────────────────────────────────────────────────────────────────
# TAB 1 — Executive Summary  (Command Center)
# ─────────────────────────────────────────────────────────────────────────────
with tabs[0]:
    st.markdown('<div class="section-header">🛡️ Command Center</div>', unsafe_allow_html=True)

    # KPI row with icons
    kpi_data = [
        ("🖥️", "Total Hosts",      summary['total_hosts'],      "#22D3EE"),
        ("⚠️", "Suspicious Hosts", summary['suspicious_hosts'], "#F59E0B"),
        ("🔴", "Critical Hosts",   summary['critical_hosts'],   "#EF4444"),
        ("📉", "Drifting Hosts",   summary['drift_hosts'],      "#8B5CF6"),
        ("🔔", "Total Alerts",     summary['total_alerts'],     "#F97316"),
        ("📊", "Windows Analyzed", summary['total_windows'],    "#3B82F6"),
    ]
    cols = st.columns(6)
    for col, (icon, label, val, color) in zip(cols, kpi_data):
        with col:
            st.markdown(f"""
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;
                        padding:1rem 1.1rem;box-shadow:var(--shadow);text-align:center;
                        border-top:2px solid {color};">
              <div style="font-size:1.6rem;">{icon}</div>
              <div style="font-size:1.9rem;font-weight:800;color:{color};line-height:1.1;margin:4px 0;">{val}</div>
              <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;
                          color:var(--text-muted);">{label}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Attack graph summary banner
    gi = summary['graph_info']
    st.markdown(f"""
    <div class="nbx-card nbx-card-accent" style="display:flex;gap:2rem;align-items:center;flex-wrap:wrap;">
      <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:var(--cyan);">
        Attack Graph Intel
      </div>
      <div style="color:var(--text-secondary);font-size:0.82rem;">
        🔴 <strong style="color:var(--text-primary);">{gi['flagged_node_count']}</strong> flagged nodes &nbsp;|&nbsp;
        🔗 <strong style="color:var(--text-primary);">{gi['edge_count']}</strong> communication edges &nbsp;|&nbsp;
        🔄 <strong style="color:var(--text-primary);">{gi['chain_count']}</strong> recon chains &nbsp;|&nbsp;
        📏 Longest chain: <strong style="color:#EF4444;">{gi['longest_chain']} hops</strong>
      </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        if not alert_df.empty:
            sev_counts = alert_df.groupby('severity')['srcip'].nunique().reset_index()
            sev_counts.columns = ['Severity', 'Hosts']
            fig = px.pie(sev_counts, names='Severity', values='Hosts',
                         color='Severity', color_discrete_map=COLOR_SEV,
                         title="Alert Severity Distribution",
                         hole=0.45)
            fig.update_traces(textfont_color='white', textfont_size=12)
            fig = apply_theme(fig)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.success("✅ No alerts — all hosts within normal behavioral bounds.")
    with col2:
        fig2 = px.histogram(df_rec, x='scan_score', nbins=30,
                            color_discrete_sequence=['#3B82F6'],
                            title="Risk Score Distribution")
        for val, color, label in [
            (bands['low'],    '#10B981', 'Low'),
            (bands['medium'], '#F59E0B', 'Medium'),
            (bands['high'],   '#EF4444', 'Critical'),
        ]:
            fig2.add_vline(x=val, line_dash='dot', line_color=color,
                           annotation_text=label,
                           annotation_font_color=color,
                           annotation_font_size=11)
        fig2 = apply_theme(fig2)
        st.plotly_chart(fig2, use_container_width=True)

    # Learned params card
    st.markdown(f"""
    <div class="nbx-card" style="display:flex;gap:3rem;flex-wrap:wrap;align-items:center;">
      <div>
        <div class="section-subheader">Dataset-Learned Thresholds</div>
        <div style="font-size:0.82rem;color:var(--text-secondary);">
          Exploration: <strong style="color:#F59E0B;">{thresh['exploration']:.2f}x</strong> &nbsp;
          Scanning: <strong style="color:#F97316;">{thresh['scanning']:.2f}x</strong>
        </div>
      </div>
      <div>
        <div class="section-subheader">Severity Bands</div>
        <div style="font-size:0.82rem;color:var(--text-secondary);">
          Low ≥ <strong style="color:#10B981;">{bands['low']:.1f}</strong> &nbsp;
          Med ≥ <strong style="color:#F59E0B;">{bands['medium']:.1f}</strong> &nbsp;
          Crit ≥ <strong style="color:#EF4444;">{bands['high']:.1f}</strong>
        </div>
      </div>
      <div>
        <div class="section-subheader">Score Weights (learned)</div>
        <div style="font-size:0.82rem;color:var(--text-secondary);">
          Dest: <strong style="color:#22D3EE;">{weights['dest']:.2f}</strong> &nbsp;
          Port: <strong style="color:#22D3EE;">{weights['port']:.2f}</strong> &nbsp;
          Burst: <strong style="color:#22D3EE;">{weights['burst']:.2f}</strong> &nbsp;
          Peer: <strong style="color:#22D3EE;">{weights['peer']:.2f}</strong>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 2 — Threat Radar  (renamed from Top Risk Hosts)
# ─────────────────────────────────────────────────────────────────────────────
with tabs[1]:
    st.markdown('<div class="section-header">🎯 Threat Radar — Situational Awareness</div>', unsafe_allow_html=True)

    if alert_df.empty:
        st.success("✅ No alerts — all hosts within normal behavioral bounds.")
    else:
        # Build top hosts table
        top = (alert_df.groupby('srcip')
               .agg(max_score=('scan_score', 'max'),
                    max_confidence=('confidence', 'max'),
                    max_level=('threat_level', 'max'),
                    severity=('severity', lambda x: x.mode()[0]),
                    scan_dna=('scan_dna', lambda x: x.mode()[0]),
                    similar_pattern=('similar_pattern', lambda x: x.mode()[0]),
                    similarity_pct=('similarity_pct', 'max'),
                    max_votes=('detector_votes', 'max'),
                    ensemble_conf=('ensemble_confidence', lambda x: x.mode()[0]),
                    stability=('stability_label', lambda x: x.mode()[0]),
                    drift=('drift_detected', 'max'),
                    alert_windows=('window', 'count'))
               .sort_values('max_score', ascending=False).reset_index())
        top['threat_stage'] = top['max_level'].map(stage_map)
        top['drift'] = top['drift'].map({True: '⚠️ Yes', False: 'No', 1: '⚠️ Yes', 0: 'No'})

        # ── Signature Radial Scatter (Threat Radar) ──────────────────────────
        st.markdown('<div class="section-subheader">Situational Awareness — Radial Risk Map</div>',
                    unsafe_allow_html=True)
        st.markdown("""
        <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:0.75rem;">
            Hosts closer to the centre have higher risk scores. Color = severity. Size = detector votes.
        </div>
        """, unsafe_allow_html=True)

        n = len(top)
        # Assign angular positions evenly, sorted by score desc
        angles = np.linspace(0, 360, n, endpoint=False)
        # Radial distance: invert score so highest score = smallest radius (centre)
        max_s = top['max_score'].max() if top['max_score'].max() > 0 else 1
        radii  = 1 - (top['max_score'].values / max_s)   # 0=centre, 1=edge
        radii  = radii * 80 + 10                         # scale to [10, 90]
        theta_rad = np.deg2rad(angles)
        x_pos = radii * np.cos(theta_rad)
        y_pos = radii * np.sin(theta_rad)

        sev_color_map = {'Critical': '#EF4444', 'High': '#F97316', 'Medium': '#F59E0B', 'Low': '#10B981'}
        node_colors = top['severity'].map(sev_color_map).fillna('#64748B').tolist()
        node_sizes  = (top['max_votes'] * 6 + 12).tolist()

        hover_text = [
            f"<b>{row.srcip}</b><br>"
            f"Risk Score: {row.max_score:.0f}<br>"
            f"Severity: {row.severity}<br>"
            f"DNA: {row.scan_dna}<br>"
            f"Stage: {row.threat_stage}<br>"
            f"Votes: {row.max_votes}/5"
            for _, row in top.iterrows()
        ]

        radar_fig = go.Figure()
        # Concentric guide circles
        for r_circle in [25, 50, 75]:
            theta_c = np.linspace(0, 2 * np.pi, 100)
            radar_fig.add_trace(go.Scatter(
                x=r_circle * np.cos(theta_c),
                y=r_circle * np.sin(theta_c),
                mode='lines',
                line=dict(color='rgba(99,179,237,0.08)', width=1, dash='dot'),
                hoverinfo='none', showlegend=False
            ))
        # Cross-hairs
        for dx, dy in [((-90, 90), (0, 0)), ((0, 0), (-90, 90))]:
            radar_fig.add_trace(go.Scatter(
                x=list(dx), y=list(dy), mode='lines',
                line=dict(color='rgba(99,179,237,0.06)', width=1),
                hoverinfo='none', showlegend=False
            ))
        # Zone labels
        for r_label, label in [(20, 'CRITICAL ZONE'), (50, 'HIGH RISK'), (80, 'WATCH LIST')]:
            radar_fig.add_annotation(
                x=r_label, y=0, text=label,
                font=dict(color='rgba(148,163,184,0.4)', size=9, family='Inter'),
                showarrow=False
            )
        # Host nodes
        radar_fig.add_trace(go.Scatter(
            x=x_pos, y=y_pos, mode='markers+text',
            marker=dict(size=node_sizes, color=node_colors,
                        line=dict(color='rgba(255,255,255,0.2)', width=1),
                        opacity=0.9),
            text=top['srcip'].tolist(),
            textposition='top center',
            textfont=dict(color='#94A3B8', size=9, family='Inter'),
            hovertext=hover_text, hoverinfo='text',
            name='Hosts'
        ))
        # Centre marker
        radar_fig.add_trace(go.Scatter(
            x=[0], y=[0], mode='markers',
            marker=dict(size=12, color='#EF4444',
                        symbol='x', line=dict(color='white', width=2)),
            hovertext='Threat Centre', hoverinfo='text', showlegend=False
        ))
        radar_layout = PLOTLY_TEMPLATE['layout'].copy()
        radar_layout.update(
            height=480,
            xaxis=dict(range=[-100, 100], showgrid=False, zeroline=False,
                       showticklabels=False, showline=False),
            yaxis=dict(range=[-100, 100], showgrid=False, zeroline=False,
                       showticklabels=False, showline=False,
                       scaleanchor='x', scaleratio=1),
            title=dict(text='Threat Radar — Risk Proximity Map', x=0.5,
                       font=dict(size=14, color='#E2E8F0')),
            margin=dict(l=20, r=20, t=50, b=20)
        )
        radar_fig.update_layout(**radar_layout)
        st.plotly_chart(radar_fig, use_container_width=True)

        st.markdown("---")
        st.markdown('<div class="section-subheader">Host Risk Rankings</div>', unsafe_allow_html=True)

        st.dataframe(top[['srcip', 'max_score', 'max_confidence', 'severity',
                           'threat_stage', 'scan_dna', 'max_votes', 'ensemble_conf',
                           'stability', 'drift', 'similar_pattern', 'similarity_pct']],
                     use_container_width=True,
                     column_config={
                         'max_score':      st.column_config.ProgressColumn("Risk Score", max_value=100),
                         'max_confidence': st.column_config.ProgressColumn("Confidence %", max_value=100),
                         'similarity_pct': st.column_config.ProgressColumn("Pattern Match %", max_value=100),
                         'max_votes':      st.column_config.NumberColumn("Detector Votes (of 5)"),
                     })

        fig_bar = px.bar(top.head(20), x='srcip', y='max_score', color='severity',
                         color_discrete_map=COLOR_SEV, title="Top 20 Hosts by Risk Score",
                         labels={'max_score': 'Risk Score', 'srcip': 'Source IP'})
        fig_bar = apply_theme(fig_bar, height=340)
        st.plotly_chart(fig_bar, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 3 — Scan DNA Explorer
# ─────────────────────────────────────────────────────────────────────────────
with tabs[2]:
    st.markdown('<div class="section-header">🧬 Scan DNA Explorer</div>', unsafe_allow_html=True)

    dna_counts = df_rec.groupby('scan_dna')['srcip'].nunique().reset_index()
    dna_counts.columns = ['Scan Type', 'Hosts']
    col1, col2 = st.columns(2)
    with col1:
        fig = px.pie(dna_counts, names='Scan Type', values='Hosts',
                     color='Scan Type', color_discrete_map=COLOR_DNA,
                     title="Scan DNA Breakdown", hole=0.45)
        fig.update_traces(textfont_color='white', textfont_size=12)
        fig = apply_theme(fig)
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.markdown("""
        <div class="nbx-card" style="margin-top:0.5rem;">
          <div class="section-subheader">Scan Type Definitions</div>
          <div style="display:flex;flex-direction:column;gap:0.75rem;margin-top:0.5rem;">
            <div style="display:flex;align-items:flex-start;gap:10px;">
              <span style="color:#3B82F6;font-size:1.1rem;">⬤</span>
              <div>
                <strong style="color:#E2E8F0;font-size:0.82rem;">Horizontal</strong>
                <div style="color:#94A3B8;font-size:0.75rem;">Few ports swept across many hosts — service sweep</div>
              </div>
            </div>
            <div style="display:flex;align-items:flex-start;gap:10px;">
              <span style="color:#F97316;font-size:1.1rem;">⬤</span>
              <div>
                <strong style="color:#E2E8F0;font-size:0.82rem;">Vertical</strong>
                <div style="color:#94A3B8;font-size:0.75rem;">Many ports on one host — service enumeration</div>
              </div>
            </div>
            <div style="display:flex;align-items:flex-start;gap:10px;">
              <span style="color:#EF4444;font-size:1.1rem;">⬤</span>
              <div>
                <strong style="color:#E2E8F0;font-size:0.82rem;">Hybrid</strong>
                <div style="color:#94A3B8;font-size:0.75rem;">Many ports across many hosts — full recon 🚨</div>
              </div>
            </div>
            <div style="display:flex;align-items:flex-start;gap:10px;">
              <span style="color:#10B981;font-size:1.1rem;">⬤</span>
              <div>
                <strong style="color:#E2E8F0;font-size:0.82rem;">Normal</strong>
                <div style="color:#94A3B8;font-size:0.75rem;">Within learned behavioral baseline</div>
              </div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    if not alert_df.empty:
        dna_score = alert_df.groupby(['scan_dna', 'srcip'])['scan_score'].max().reset_index()
        fig2 = px.box(dna_score, x='scan_dna', y='scan_score', color='scan_dna',
                      color_discrete_map=COLOR_DNA,
                      title="Score Distribution by Scan DNA Type",
                      labels={'scan_score': 'Risk Score', 'scan_dna': 'Scan Type'})
        fig2 = apply_theme(fig2)
        st.plotly_chart(fig2, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 4 — Threat Evolution
# ─────────────────────────────────────────────────────────────────────────────
with tabs[3]:
    st.markdown('<div class="section-header">📈 Threat Evolution Meter</div>', unsafe_allow_html=True)

    stage_counts = df_rec['threat_stage_label'].value_counts().reset_index()
    stage_counts.columns = ['Stage', 'Windows']
    col1, col2 = st.columns(2)
    with col1:
        fig = px.funnel(stage_counts, x='Windows', y='Stage', title="Threat Stage Funnel",
                        color='Stage',
                        color_discrete_map={
                            'Normal': '#10B981', 'Exploration': '#F59E0B',
                            'Scanning': '#F97316', 'Probable Compromise': '#EF4444'
                        })
        fig = apply_theme(fig)
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.markdown(f"""
        <div class="nbx-card">
          <div class="section-subheader">Stage Transition Rules (Self-Tuned)</div>
          <table style="width:100%;font-size:0.78rem;border-collapse:collapse;margin-top:0.5rem;">
            <tr style="border-bottom:1px solid var(--border);">
              <td style="padding:6px 8px;color:#10B981;">🟢 Normal</td>
              <td style="padding:6px 8px;color:#94A3B8;">All deviations ≤ {thresh['exploration']:.1f}x</td>
            </tr>
            <tr style="border-bottom:1px solid var(--border);">
              <td style="padding:6px 8px;color:#F59E0B;">🟡 Exploration</td>
              <td style="padding:6px 8px;color:#94A3B8;">1 indicator &gt; {thresh['exploration']:.1f}x</td>
            </tr>
            <tr style="border-bottom:1px solid var(--border);">
              <td style="padding:6px 8px;color:#F97316;">🟠 Scanning</td>
              <td style="padding:6px 8px;color:#94A3B8;">2+ indicators &gt; {thresh['scanning']:.1f}x</td>
            </tr>
            <tr>
              <td style="padding:6px 8px;color:#EF4444;">🔴 Compromise</td>
              <td style="padding:6px 8px;color:#94A3B8;">Scanning + high score / persistence / Hybrid</td>
            </tr>
          </table>
        </div>
        """, unsafe_allow_html=True)

    if not alert_df.empty:
        top10 = (alert_df.groupby('srcip')['scan_score'].max().nlargest(10).index.tolist())
        prog_df = df_rec[df_rec['srcip'].isin(top10)]
        fig3 = px.line(prog_df, x='window', y='threat_level', color='srcip',
                       title="Threat Level Progression — Top 10 Hosts",
                       labels={'threat_level': 'Threat Level', 'window': 'Window Index'})
        fig3.update_yaxes(tickvals=[1, 2, 3, 4],
                          ticktext=['Normal', 'Exploration', 'Scanning', 'Compromise'])
        fig3 = apply_theme(fig3, height=360)
        st.plotly_chart(fig3, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 5 — Ensemble Engine
# ─────────────────────────────────────────────────────────────────────────────
with tabs[4]:
    st.markdown('<div class="section-header">🗳️ Ensemble Rule Engine — 5 Independent Detectors</div>',
                unsafe_allow_html=True)

    st.markdown("""
    <div class="nbx-card">
      <div class="section-subheader">How the Ensemble Works</div>
      <div style="font-size:0.8rem;color:#94A3B8;line-height:1.7;">
        Each window is evaluated by <strong style="color:#22D3EE;">5 independent detectors</strong>.
        An alert requires agreement from <strong style="color:#F59E0B;">2+ detectors</strong>,
        reducing false positives from single-indicator spikes.
      </div>
      <div style="display:flex;gap:1rem;flex-wrap:wrap;margin-top:1rem;">
    """, unsafe_allow_html=True)

    detector_info = [
        ("Destination", "Dest spread vs combined baseline", "#22D3EE"),
        ("Port",        "Port diversity vs combined baseline", "#3B82F6"),
        ("Burst",       "Connection rate vs combined baseline", "#8B5CF6"),
        ("Protocol",    "Protocol changed from host's learned norm", "#F59E0B"),
        ("Peer",        "New peer ratio > 30% threshold", "#F97316"),
    ]
    det_cols = st.columns(5)
    for col, (name, desc, color) in zip(det_cols, detector_info):
        with col:
            st.markdown(f"""
            <div style="background:var(--bg-card);border:1px solid {color}30;border-top:2px solid {color};
                        border-radius:10px;padding:0.75rem;text-align:center;">
              <div style="font-size:0.75rem;font-weight:700;color:{color};margin-bottom:4px;">{name}</div>
              <div style="font-size:0.65rem;color:#64748B;line-height:1.4;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    vote_counts = df_rec['detector_votes'].value_counts().sort_index().reset_index()
    vote_counts.columns = ['Votes', 'Windows']
    fig = px.bar(vote_counts, x='Votes', y='Windows',
                 color='Votes', color_continuous_scale=['#10B981', '#F59E0B', '#F97316', '#EF4444'],
                 title="Detector Vote Distribution Across All Windows",
                 labels={'Votes': 'Detector Votes', 'Windows': 'Window Count'})
    fig.update_xaxes(tickvals=[0, 1, 2, 3, 4, 5],
                     ticktext=['0 (Clean)', '1 (Marginal)', '2 (Low)',
                               '3 (Medium)', '4 (High)', '5 (Very High)'])
    fig = apply_theme(fig)
    st.plotly_chart(fig, use_container_width=True)

    if not alert_df.empty:
        st.markdown('<div class="section-subheader">Ensemble Details — Alert Windows</div>',
                    unsafe_allow_html=True)
        ens_df = alert_df[['srcip', 'window', 'detector_votes', 'ensemble_confidence',
                            'scan_score', 'severity']].copy()
        ens_df = ens_df.sort_values('detector_votes', ascending=False)
        st.dataframe(ens_df, use_container_width=True)

        top_host = alert_df.groupby('srcip')['scan_score'].max().idxmax()
        top_rec  = alert_df[alert_df['srcip'] == top_host].sort_values(
                       'scan_score', ascending=False).iloc[0]
        st.markdown(f"""
        <div class="nbx-card nbx-card-accent">
          <div class="section-subheader">Detector Reasons — {top_host}</div>
        """, unsafe_allow_html=True)
        for r in top_rec.get('detector_reasons', []):
            st.markdown(f"- {r}")
        st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 6 — Attack Graph
# ─────────────────────────────────────────────────────────────────────────────
with tabs[5]:
    st.markdown('<div class="section-header">🔗 Attack Graph — Reconnaissance Propagation</div>',
                unsafe_allow_html=True)

    gi = summary['graph_info']
    c1, c2, c3, c4 = st.columns(4)
    for col, label, val, color in [
        (c1, "Flagged Nodes",  gi['flagged_node_count'], "#EF4444"),
        (c2, "Comm. Edges",   gi['edge_count'],          "#F97316"),
        (c3, "Recon Chains",  gi['chain_count'],         "#8B5CF6"),
        (c4, "Longest Chain", f"{gi['longest_chain']} hops", "#22D3EE"),
    ]:
        with col:
            st.markdown(f"""
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:10px;
                        padding:0.85rem 1rem;text-align:center;border-top:2px solid {color};">
              <div style="font-size:1.6rem;font-weight:800;color:{color};">{val}</div>
              <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;
                          color:var(--text-muted);margin-top:2px;">{label}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    nodes = attack_graph['nodes']
    edges = attack_graph['edges']

    if edges:
        import networkx as nx
        G = nx.DiGraph()
        for src, dst, w in edges:
            G.add_edge(src, dst, weight=w)
        pos = nx.spring_layout(G, seed=42)
        edge_x, edge_y = [], []
        for s, d in G.edges():
            x0, y0 = pos[s]; x1, y1 = pos[d]
            edge_x += [x0, x1, None]; edge_y += [y0, y1, None]
        node_x     = [pos[n][0] for n in G.nodes()]
        node_y     = [pos[n][1] for n in G.nodes()]
        node_text  = [f"{n}<br>Score: {nodes.get(n,{}).get('score',0):.0f}<br>"
                      f"Stage: {nodes.get(n,{}).get('stage','')}"
                      for n in G.nodes()]
        node_color = [nodes.get(n, {}).get('score', 0) for n in G.nodes()]

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode='lines',
                                  line=dict(width=1, color='rgba(99,179,237,0.3)'),
                                  hoverinfo='none'))
        fig.add_trace(go.Scatter(x=node_x, y=node_y, mode='markers+text',
                                  marker=dict(size=22, color=node_color,
                                              colorscale='RdYlGn_r', showscale=True,
                                              colorbar=dict(title='Risk Score',
                                                            tickfont=dict(color='#94A3B8')),
                                              line=dict(color='rgba(255,255,255,0.2)', width=1)),
                                  text=list(G.nodes()), textposition='top center',
                                  textfont=dict(color='#94A3B8', size=9),
                                  hovertext=node_text, hoverinfo='text'))
        graph_layout = PLOTLY_TEMPLATE['layout'].copy()
        graph_layout.update(
            title="Host Communication Graph (Flagged Hosts)",
            showlegend=False, height=500,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
        fig.update_layout(**graph_layout)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No inter-host communication edges detected between flagged hosts.")

    if gi['chain_strings']:
        st.markdown("""
        <div class="nbx-card">
          <div class="section-subheader">Detected Reconnaissance Chains (Lateral Movement Paths)</div>
        """, unsafe_allow_html=True)
        for i, chain in enumerate(gi['chain_strings'], 1):
            st.markdown(f"`{i}.` {chain}")
        st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 7 — Behavioral Drift
# ─────────────────────────────────────────────────────────────────────────────
with tabs[6]:
    st.markdown('<div class="section-header">📉 Behavioral Drift — Slow Reconnaissance Detection</div>',
                unsafe_allow_html=True)

    st.markdown("""
    <div class="nbx-card">
      <div style="font-size:0.82rem;color:#94A3B8;line-height:1.7;">
        Detects hosts whose behavior is <strong style="color:#22D3EE;">monotonically increasing</strong>
        across windows without ever producing a single spike. This catches slow scanners that evade
        single-window detection.<br>
        <strong style="color:#E2E8F0;">Method:</strong> Linear trend fit (slope + R²) across all windows per host.
        Drift confirmed if slope &gt; 0.05, R² &gt; 0.6, and end value &gt; 1.5× start value.
      </div>
    </div>
    """, unsafe_allow_html=True)

    drifting = {s: d for s, d in drift.items() if d['drift_detected']}
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"""
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:10px;
                    padding:0.85rem 1rem;text-align:center;border-top:2px solid #8B5CF6;">
          <div style="font-size:2rem;font-weight:800;color:#8B5CF6;">{len(drifting)}</div>
          <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;
                      color:var(--text-muted);">Drifting Hosts</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:10px;
                    padding:0.85rem 1rem;text-align:center;border-top:2px solid #3B82F6;">
          <div style="font-size:2rem;font-weight:800;color:#3B82F6;">{len(drift)}</div>
          <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;
                      color:var(--text-muted);">Total Hosts Monitored</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    if drifting:
        drift_rows = [{'Host': src, 'Metric': d.get('metric', ''),
                       'Slope': d.get('slope', 0), 'R²': d.get('r2', 0),
                       'Start': d.get('start_val', 0), 'End': d.get('end_val', 0),
                       'Growth': f"{d.get('end_val',0)/max(d.get('start_val',1),0.01):.1f}x"}
                      for src, d in drifting.items()]
        st.dataframe(pd.DataFrame(drift_rows), use_container_width=True)

        for src, d in list(drifting.items())[:5]:
            vals = d.get('window_values', [])
            if vals:
                metric_label = d.get('metric', 'deviation').replace('_', ' ').title()
                fig = px.line(x=list(range(len(vals))), y=vals,
                              title=f"Drift Trend — {src} ({metric_label})",
                              labels={'x': 'Window', 'y': f'{metric_label} (deviation ratio)'})
                fig.add_hline(y=1.0, line_dash='dot', line_color='#10B981',
                              annotation_text='Normal baseline',
                              annotation_font_color='#10B981')
                fig = apply_theme(fig, height=300)
                st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("✅ No behavioral drift detected across any monitored hosts.")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 8 — Explainability Center  (renamed from Attack Stories)
# ─────────────────────────────────────────────────────────────────────────────
with tabs[7]:
    st.markdown('<div class="section-header">🔎 Explainability Center</div>', unsafe_allow_html=True)

    if not alert_df.empty:
        host_options = (alert_df.groupby('srcip')['scan_score'].max()
                        .sort_values(ascending=False).index.tolist())
        sel_host = st.selectbox("Select host to investigate", host_options, key='expl_host')

        # ── Risk Contributors Panel ───────────────────────────────────────────
        host_recs = alert_df[alert_df['srcip'] == sel_host]
        worst_rec = host_recs.loc[host_recs['scan_score'].idxmax()]

        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown("""
            <div class="nbx-card nbx-card-accent">
              <div class="section-subheader">Risk Contributors</div>
            """, unsafe_allow_html=True)

            contrib_data = [
                ("Dest Spread",    worst_rec.get('dest_dev', 1),  10.0, "#22D3EE"),
                ("Port Diversity", worst_rec.get('port_dev', 1),  10.0, "#3B82F6"),
                ("Burst Activity", worst_rec.get('burst_dev', 1), 10.0, "#8B5CF6"),
                ("New Peer Ratio", worst_rec.get('new_peer_ratio', 0) * 10, 10.0, "#F59E0B"),
                ("Threat Stage",   (worst_rec.get('threat_level', 1) - 1) * 33.3, 100.0, "#EF4444"),
            ]
            bar_html = ""
            for label, raw_val, max_val, color in contrib_data:
                pct = min(raw_val / max_val * 100, 100)
                bar_html += f"""
                <div class="risk-bar-container">
                  <div class="risk-bar-label">{label}</div>
                  <div class="risk-bar-track">
                    <div class="risk-bar-fill" style="width:{pct:.1f}%;background:{color};"></div>
                  </div>
                  <div class="risk-bar-value">{pct:.0f}%</div>
                </div>"""
            st.markdown(bar_html + "</div>", unsafe_allow_html=True)

        with col2:
            severity = worst_rec.get('severity', 'Low')
            sev_color = COLOR_SEV.get(severity, '#10B981')
            st.markdown(f"""
            <div class="nbx-card" style="border-top:2px solid {sev_color};">
              <div class="section-subheader">Threat Summary</div>
              <div style="display:flex;gap:1rem;flex-wrap:wrap;margin-top:0.5rem;">
                <div>
                  <div style="font-size:0.65rem;color:#64748B;text-transform:uppercase;">Risk Score</div>
                  <div style="font-size:1.8rem;font-weight:800;color:{sev_color};">{worst_rec.get('scan_score',0):.0f}</div>
                </div>
                <div>
                  <div style="font-size:0.65rem;color:#64748B;text-transform:uppercase;">Severity</div>
                  <div style="font-size:1.1rem;font-weight:700;color:{sev_color};margin-top:6px;">{severity}</div>
                </div>
                <div>
                  <div style="font-size:0.65rem;color:#64748B;text-transform:uppercase;">Scan DNA</div>
                  <div style="font-size:1.1rem;font-weight:700;color:#22D3EE;margin-top:6px;">{worst_rec.get('scan_dna','Normal')}</div>
                </div>
                <div>
                  <div style="font-size:0.65rem;color:#64748B;text-transform:uppercase;">Pattern Match</div>
                  <div style="font-size:1.1rem;font-weight:700;color:#8B5CF6;margin-top:6px;">{worst_rec.get('similar_pattern','—')} ({worst_rec.get('similarity_pct',0):.0f}%)</div>
                </div>
              </div>
              <div style="margin-top:0.75rem;">
                <div class="section-subheader">Why Flagged</div>
                {"".join(f'<div style="font-size:0.78rem;color:#94A3B8;padding:3px 0;border-bottom:1px solid rgba(99,179,237,0.06);">⚡ {r}</div>' for r in worst_rec.get("reasons", ["No strong indicator"]))}
              </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown('<div class="section-subheader">Attack Timeline</div>', unsafe_allow_html=True)

        story = stories.get(sel_host, [])
        for block in story:
            w     = block['window']
            score = block.get('scan_score', 0)
            dna   = block.get('scan_dna', 'Normal')
            level = block.get('threat_level', 1)
            stage = stage_map.get(level, 'Normal')
            icon  = stage_icon.get(stage, '⚪')
            sev_c = COLOR_SEV.get(classify := ('Critical' if score >= bands['high'] else
                                               'High' if score >= bands['medium'] else
                                               'Medium' if score >= bands['low'] else 'Low'), '#64748B')
            with st.expander(f"{icon} Window {w} — Score: {score:.0f} | {stage} | {dna}"):
                for ev in block['events']:
                    st.markdown(f"- {ev}")
    else:
        st.success("✅ No suspicious hosts detected.")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 9 — Cognitive Twin Analysis  (renamed from Host Detail)
# ─────────────────────────────────────────────────────────────────────────────
with tabs[8]:
    st.markdown('<div class="section-header">🧠 Cognitive Twin Analysis</div>', unsafe_allow_html=True)

    all_hosts = sorted(df_rec['srcip'].unique())
    sel = st.selectbox("Select a host", all_hosts, key='detail_host')
    host_df = df_rec[df_rec['srcip'] == sel].sort_values('window')

    if not host_df.empty:
        latest = host_df.iloc[-1]
        sev_val = latest.get('severity', '—')
        sev_color = COLOR_SEV.get(sev_val, '#64748B')

        # ── KPI strip ────────────────────────────────────────────────────────
        kpi_cols = st.columns(5)
        kpi_items = [
            ("Risk Score",     f"{latest['scan_score']:.0f}", sev_color),
            ("Severity",       sev_val,                       sev_color),
            ("Confidence",     f"{latest.get('confidence',0):.1f}%", "#22D3EE"),
            ("Threat Stage",   latest.get('threat_stage_label', '—'), "#F59E0B"),
            ("Detector Votes", f"{latest.get('detector_votes',0)}/5", "#8B5CF6"),
        ]
        for col, (label, val, color) in zip(kpi_cols, kpi_items):
            with col:
                st.markdown(f"""
                <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:10px;
                            padding:0.85rem 1rem;text-align:center;border-top:2px solid {color};">
                  <div style="font-size:1.5rem;font-weight:800;color:{color};">{val}</div>
                  <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;
                              color:var(--text-muted);margin-top:2px;">{label}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Hero: Behavioral Deviation Radar ─────────────────────────────────
        st.markdown('<div class="section-subheader">Behavioral Deviation Radar</div>', unsafe_allow_html=True)

        cats = ['Dest Spread', 'Port Diversity', 'Burst Activity', 'New Peer Ratio']
        vals_cur = [min(latest.get('dest_dev', 1), 10),
                    min(latest.get('port_dev', 1), 10),
                    min(latest.get('burst_dev', 1), 10),
                    latest.get('new_peer_ratio', 0) * 10]

        radar_fig = go.Figure()
        radar_fig.add_trace(go.Scatterpolar(
            r=[1, 1, 1, 1, 1], theta=cats + [cats[0]],
            fill='toself', name='Baseline',
            line=dict(color='#10B981', width=2),
            fillcolor='rgba(16,185,129,0.1)'
        ))
        radar_fig.add_trace(go.Scatterpolar(
            r=vals_cur + [vals_cur[0]], theta=cats + [cats[0]],
            fill='toself', name='Current',
            line=dict(color='#EF4444', width=2),
            fillcolor='rgba(239,68,68,0.15)'
        ))
        drift_radar_layout = PLOTLY_TEMPLATE['layout'].copy()
        drift_radar_layout.update(
            polar=dict(
                radialaxis=dict(range=[0, 10], tickfont=dict(color='#64748B', size=9),
                                gridcolor='rgba(99,179,237,0.1)'),
                angularaxis=dict(tickfont=dict(color='#94A3B8', size=11),
                                 gridcolor='rgba(99,179,237,0.1)'),
                bgcolor='rgba(0,0,0,0)'
            ),
            legend=dict(font=dict(color='#94A3B8'), bgcolor='rgba(0,0,0,0)'),
            height=420, margin=dict(l=40, r=40, t=30, b=40),
            title=dict(text=f"Host {sel} — Baseline vs Current Behavior", x=0.5,
                       font=dict(size=13, color='#E2E8F0'))
        )
        radar_fig.update_layout(**drift_radar_layout)
        st.plotly_chart(radar_fig, use_container_width=True)

        # ── Risk score timeline ───────────────────────────────────────────────
        fig2 = px.line(host_df, x='window', y='scan_score',
                       title=f"Risk Score Over Windows — {sel}", markers=True,
                       labels={'scan_score': 'Risk Score', 'window': 'Window Index'})
        fig2.add_hline(y=bands['high'],   line_dash='dot', line_color='#EF4444',
                       annotation_text='Critical', annotation_font_color='#EF4444')
        fig2.add_hline(y=bands['medium'], line_dash='dot', line_color='#F59E0B',
                       annotation_text='Medium', annotation_font_color='#F59E0B')
        fig2 = apply_theme(fig2, height=300)
        st.plotly_chart(fig2, use_container_width=True)

        st.markdown("---")

        # ── Detail panels ─────────────────────────────────────────────────────
        col3, col4 = st.columns(2)
        with col3:
            st.markdown("""<div class="nbx-card nbx-card-accent">
              <div class="section-subheader">Why Flagged</div>""", unsafe_allow_html=True)
            for r in latest.get('reasons', []):
                st.markdown(f"- {r}")
            st.markdown("</div>", unsafe_allow_html=True)

            # ── Multi-Baseline Investigation (structured panel) ───────────────
            st.markdown("""<div class="nbx-card">
              <div class="section-subheader">Multi-Baseline Investigation</div>
              <div style="font-size:0.72rem;color:#64748B;margin-bottom:0.75rem;">
                Host behavior vs all 3 baseline layers
              </div>""", unsafe_allow_html=True)

            mb_lines = latest.get('multi_baseline_view', [])
            # Build a comparison mini-table from the multi_baseline_view text
            mb_html = ""
            mb_html += """<table style="width:100%;border-collapse:collapse;font-size:0.75rem;">
              <tr style="border-bottom:1px solid rgba(99,179,237,0.15);">
                <th style="color:#64748B;text-align:left;padding:4px 6px;">Metric</th>
                <th style="color:#22D3EE;text-align:right;padding:4px 6px;">vs Host</th>
                <th style="color:#8B5CF6;text-align:right;padding:4px 6px;">vs Peer</th>
                <th style="color:#3B82F6;text-align:right;padding:4px 6px;">vs Global</th>
              </tr>"""
            for line in mb_lines:
                # Parse: "Destination: vs Host=X | vs Peer Group=Y | vs Global=Z"
                try:
                    metric_part = line.split(':')[0].strip()
                    h_val = p_val = g_val = "—"
                    if 'vs Host=' in line:
                        h_val = line.split('vs Host=')[1].split('|')[0].strip().replace('x','') + 'x'
                    if 'vs Peer Group=' in line:
                        p_val = line.split('vs Peer Group=')[1].split('|')[0].strip().replace('x','') + 'x'
                    if 'vs Global=' in line:
                        g_val = line.split('vs Global=')[1].split('(')[0].strip().replace('x','') + 'x'
                    # Color code high deviations
                    def _color_dev(v):
                        try:
                            n = float(v.replace('x',''))
                            if n >= 5: return f'<span style="color:#EF4444;font-weight:700;">{v}</span>'
                            if n >= 2.5: return f'<span style="color:#F59E0B;font-weight:600;">{v}</span>'
                            return f'<span style="color:#94A3B8;">{v}</span>'
                        except: return f'<span style="color:#94A3B8;">{v}</span>'
                    mb_html += f"""<tr style="border-bottom:1px solid rgba(99,179,237,0.06);">
                      <td style="color:#E2E8F0;padding:5px 6px;">{metric_part}</td>
                      <td style="text-align:right;padding:5px 6px;">{_color_dev(h_val)}</td>
                      <td style="text-align:right;padding:5px 6px;">{_color_dev(p_val)}</td>
                      <td style="text-align:right;padding:5px 6px;">{_color_dev(g_val)}</td>
                    </tr>"""
                except Exception:
                    mb_html += f'<tr><td colspan="4" style="color:#64748B;font-size:0.72rem;padding:4px 6px;">{line}</td></tr>'
            mb_html += "</table></div>"
            st.markdown(mb_html, unsafe_allow_html=True)

        with col4:
            st.markdown("""<div class="nbx-card">
              <div class="section-subheader">Analyst Recommendations</div>""", unsafe_allow_html=True)
            for rec_txt in latest.get('recommendations', []):
                st.markdown(f"- {rec_txt}")
            st.markdown("</div>", unsafe_allow_html=True)

            st.markdown("""<div class="nbx-card">
              <div class="section-subheader">Counterfactual Analysis</div>
              <div style="font-size:0.72rem;color:#64748B;margin-bottom:0.5rem;">
                What would make this host appear normal?
              </div>""", unsafe_allow_html=True)
            for cf in latest.get('counterfactual', []):
                st.markdown(f"- {cf}")

            st.markdown(f"""
              <div style="margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border);">
                <span style="font-size:0.7rem;color:#64748B;">Risk Stability:</span>
                <strong style="color:#E2E8F0;font-size:0.82rem;"> {latest.get('stability_label','—')}</strong>
                <span style="color:#64748B;font-size:0.72rem;"> ({latest.get('risk_stability_pct',0):.0f}% of windows elevated)</span>
              </div>
            """, unsafe_allow_html=True)

            if latest.get('drift_detected'):
                st.warning(f"⚠️ Behavioral drift detected on **{latest.get('drift_metric','unknown')}** "
                           f"metric (slope={latest.get('drift_slope',0):.3f})")

            if latest.get('ml_anomaly_score') is not None:
                ml_score = latest.get('ml_anomaly_score', 0)
                ml_flag  = latest.get('ml_is_anomaly', False)
                ml_color = '#EF4444' if ml_flag else '#10B981'
                st.markdown(f"""
                <div style="margin-top:0.75rem;padding:0.6rem 0.75rem;
                            background:rgba(0,0,0,0.2);border-radius:8px;
                            border-left:3px solid {ml_color};">
                  <span style="font-size:0.7rem;color:#64748B;">ML (Isolation Forest):</span>
                  <strong style="color:{ml_color};"> Score={ml_score:.1f} | {'🚨 Anomaly' if ml_flag else '✅ Normal'}</strong>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("---")
        display_cols = ['window', 'unique_dsts', 'unique_ports', 'conn_count',
                        'dest_dev', 'port_dev', 'burst_dev', 'new_peer_ratio',
                        'scan_dna', 'threat_stage_label', 'scan_score', 'severity',
                        'detector_votes', 'ensemble_confidence',
                        'stability_label', 'is_alert', 'persistence']
        st.dataframe(host_df[[c for c in display_cols if c in host_df.columns]],
                     use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 10 — System Config
# ─────────────────────────────────────────────────────────────────────────────
with tabs[9]:
    st.markdown('<div class="section-header">⚙️ System Configuration</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="nbx-card nbx-card-accent">
      <div style="font-size:0.8rem;color:#94A3B8;">
        ✅ <strong style="color:#22D3EE;">No values are hardcoded.</strong>
        Every parameter below is derived from your uploaded dataset.
      </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown('<div class="section-subheader">Deviation Thresholds</div>', unsafe_allow_html=True)
        st.json(thresh)
        st.markdown('<div class="section-subheader">Score Weights</div>', unsafe_allow_html=True)
        st.json(weights)
    with col2:
        st.markdown('<div class="section-subheader">Severity Bands</div>', unsafe_allow_html=True)
        st.json(bands)
        st.markdown('<div class="section-subheader">Scan DNA Thresholds</div>', unsafe_allow_html=True)
        st.json(summary.get('scan_thresholds', {}))
    with col3:
        st.markdown('<div class="section-subheader">Peer Groups</div>', unsafe_allow_html=True)
        pg_df = pd.DataFrame(list(summary['peer_groups'].items()),
                             columns=['Group', 'Host Count'])
        st.dataframe(pg_df, use_container_width=True)
        st.markdown('<div class="section-subheader">Pipeline Settings</div>', unsafe_allow_html=True)
        st.json({'window_size': 500,
                 'baseline_ratio': 0.4,
                 'ml_enabled': True})


# ─────────────────────────────────────────────────────────────────────────────
# TAB 11 — Validation Dashboard  (NEW)
# ─────────────────────────────────────────────────────────────────────────────
with tabs[10]:
    st.markdown('<div class="section-header">✅ Validation Dashboard — Ground Truth Comparison</div>',
                unsafe_allow_html=True)

    st.markdown("""
    <div class="nbx-card">
      <div style="font-size:0.82rem;color:#94A3B8;line-height:1.7;">
        Comparing our detection predictions (<code>is_alert</code>) against the UNSW-NB15 ground truth
        labels (<code>attack_present</code>) at the window level.
        Ground truth = any attack row in that window. Predictions = FP-filtered alerts.
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Compute metrics ───────────────────────────────────────────────────────
    if 'attack_present' in df_rec.columns and 'is_alert' in df_rec.columns:
        from sklearn.metrics import (precision_score, recall_score, f1_score,
                                     confusion_matrix)

        y_true = df_rec['attack_present'].fillna(0).astype(int).values
        y_pred = df_rec['is_alert'].fillna(False).astype(int).values

        # Handle edge cases
        unique_true = set(y_true)
        n_pos_true  = int(y_true.sum())
        n_pos_pred  = int(y_pred.sum())
        n_total     = len(y_true)

        if len(unique_true) < 2:
            st.warning("Ground truth labels are all the same class — metrics not computable. "
                       "Upload a dataset with both normal and attack traffic.")
        else:
            precision = precision_score(y_true, y_pred, zero_division=0)
            recall    = recall_score(y_true, y_pred, zero_division=0)
            f1        = f1_score(y_true, y_pred, zero_division=0)
            cm        = confusion_matrix(y_true, y_pred, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, n_pos_pred)
            fpr = fp / max(fp + tn, 1)

            # ── KPI row ───────────────────────────────────────────────────────
            val_kpis = [
                ("🎯", "Precision",     f"{precision*100:.1f}%", "#10B981",
                 "Of our alerts, % that are real attacks"),
                ("📡", "Recall",        f"{recall*100:.1f}%",    "#22D3EE",
                 "Of real attacks, % we caught"),
                ("⚖️", "F1 Score",      f"{f1*100:.1f}%",        "#3B82F6",
                 "Harmonic mean of Precision & Recall"),
                ("🚫", "False Pos Rate",f"{fpr*100:.1f}%",       "#F59E0B",
                 "Normal windows incorrectly flagged"),
                ("✅", "True Positives", str(tp),                "#8B5CF6",
                 "Real attacks correctly detected"),
            ]
            kpi_cols = st.columns(5)
            for col, (icon, label, val, color, desc) in zip(kpi_cols, val_kpis):
                with col:
                    st.markdown(f"""
                    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;
                                padding:1rem 1.1rem;text-align:center;border-top:2px solid {color};
                                box-shadow:var(--shadow);">
                      <div style="font-size:1.6rem;">{icon}</div>
                      <div style="font-size:1.9rem;font-weight:800;color:{color};line-height:1.1;margin:4px 0;">{val}</div>
                      <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;
                                  color:var(--text-muted);">{label}</div>
                      <div style="font-size:0.6rem;color:#334155;margin-top:4px;line-height:1.3;">{desc}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # ── Confusion Matrix Heatmap ──────────────────────────────────────
            col1, col2 = st.columns([1, 1])
            with col1:
                st.markdown('<div class="section-subheader">Confusion Matrix</div>',
                            unsafe_allow_html=True)
                cm_data = [[tn, fp], [fn, tp]]
                cm_labels = [['True Negative', 'False Positive'],
                             ['False Negative', 'True Positive']]
                hover_txt = [[f"TN: {tn}<br>Normal windows correctly ignored",
                              f"FP: {fp}<br>Normal windows incorrectly flagged"],
                             [f"FN: {fn}<br>Attacks missed by detector",
                              f"TP: {tp}<br>Attacks correctly detected"]]
                cm_fig = go.Figure(go.Heatmap(
                    z=cm_data,
                    x=['Predicted: Normal', 'Predicted: Alert'],
                    y=['Actual: Normal', 'Actual: Attack'],
                    text=[[str(tn), str(fp)], [str(fn), str(tp)]],
                    texttemplate='<b>%{text}</b>',
                    textfont=dict(size=22, color='white'),
                    hovertext=hover_txt, hoverinfo='text',
                    colorscale=[
                        [0,   'rgba(16,185,129,0.3)'],
                        [0.33,'rgba(245,158,11,0.3)'],
                        [0.66,'rgba(249,115,22,0.4)'],
                        [1,   'rgba(239,68,68,0.8)'],
                    ],
                    showscale=False
                ))
                cm_layout = PLOTLY_TEMPLATE['layout'].copy()
                cm_layout.update(
                    height=320,
                    xaxis=dict(side='bottom', tickfont=dict(color='#94A3B8', size=11)),
                    yaxis=dict(tickfont=dict(color='#94A3B8', size=11)),
                    margin=dict(l=12, r=12, t=20, b=12)
                )
                cm_fig.update_layout(**cm_layout)
                st.plotly_chart(cm_fig, use_container_width=True)

            with col2:
                st.markdown("""
                <div class="nbx-card" style="height:310px;overflow:auto;">
                  <div class="section-subheader">Metric Interpretation</div>
                  <table style="width:100%;border-collapse:collapse;font-size:0.78rem;">
                """, unsafe_allow_html=True)

                interp_rows = [
                    ("Precision",      f"{precision*100:.1f}%",
                     "High = few false alarms", "#10B981"),
                    ("Recall",         f"{recall*100:.1f}%",
                     "High = few missed attacks", "#22D3EE"),
                    ("F1 Score",       f"{f1*100:.1f}%",
                     "Balance of precision & recall", "#3B82F6"),
                    ("False Pos Rate", f"{fpr*100:.1f}%",
                     "Low = analyst fatigue reduction", "#F59E0B"),
                    ("True Positives", str(tp),
                     "Real attacks caught", "#8B5CF6"),
                    ("False Positives",str(fp),
                     "Normal windows flagged incorrectly", "#F97316"),
                    ("False Negatives",str(fn),
                     "Attacks missed", "#EF4444"),
                    ("True Negatives", str(tn),
                     "Normal windows correctly cleared", "#10B981"),
                ]
                rows_html = ""
                for m, v, desc, color in interp_rows:
                    rows_html += f"""
                    <tr style="border-bottom:1px solid rgba(99,179,237,0.08);">
                      <td style="padding:6px 8px;color:#E2E8F0;font-weight:600;">{m}</td>
                      <td style="padding:6px 8px;color:{color};font-weight:800;text-align:right;">{v}</td>
                      <td style="padding:6px 8px;color:#64748B;font-size:0.7rem;">{desc}</td>
                    </tr>"""
                st.markdown(rows_html + "</table></div>", unsafe_allow_html=True)

            # ── Score distribution by ground truth ────────────────────────────
            st.markdown("---")
            st.markdown('<div class="section-subheader">Risk Score Distribution by Ground Truth Label</div>',
                        unsafe_allow_html=True)
            df_val = df_rec[['scan_score', 'attack_present', 'is_alert']].copy()
            df_val['Ground Truth'] = df_val['attack_present'].map({1: 'Attack', 0: 'Normal'})
            fig_dist = px.histogram(df_val, x='scan_score', color='Ground Truth', nbins=30,
                                    barmode='overlay', opacity=0.7,
                                    color_discrete_map={'Attack': '#EF4444', 'Normal': '#10B981'},
                                    title="Risk Score by Ground Truth — Should See Separation",
                                    labels={'scan_score': 'Risk Score'})
            for val, color, label in [(bands['low'], '#10B981', 'Low'),
                                       (bands['medium'], '#F59E0B', 'Medium'),
                                       (bands['high'], '#EF4444', 'Critical')]:
                fig_dist.add_vline(x=val, line_dash='dot', line_color=color,
                                   annotation_text=label, annotation_font_color=color)
            fig_dist = apply_theme(fig_dist, height=320)
            st.plotly_chart(fig_dist, use_container_width=True)

    else:
        st.warning("⚠️ `attack_present` column not found in results. "
                   "Ensure you are running pipeline.py v2+ which passes through "
                   "this field from time_window.py.")
