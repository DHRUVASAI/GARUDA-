import re
import os

path = r'c:\Users\dhruv\Downloads\DELL HACATHON\DELL HACATHON\network_bouncer_x\dashboard\app.py'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add server logic at the top (after imports)
server_logic = """
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
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(path.encode('utf-8'))
        except Exception as e:
            print("Upload error:", e)
            self.send_response(500)
            self.end_headers()

@st.cache_resource
def start_upload_server():
    try:
        server = HTTPServer(('127.0.0.1', 8502), UploadHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    except OSError:
        pass # Port likely already in use by previous run
    return True

start_upload_server()
"""
if 'class UploadHandler' not in content:
    content = content.replace("st.set_page_config(", server_logic + "\n\nst.set_page_config(")


# 2. Hide Sidebar completely
hide_sidebar_css = """
/* ── Sidebar and Top Bar Hiding ── */
[data-testid="stSidebar"] { display: none !important; }
[data-testid="collapsedControl"] { display: none !important; }
"""
if 'stSidebar' not in content: # wait, stSidebar is in there...
    content = content.replace("/* ── Sidebar text ── */", hide_sidebar_css + "\n/* ── Sidebar text ── */")


# 3. Replace the sidebar block and session state with our new logic
# We'll use regex to replace from "with st.sidebar:" up to "os.unlink(tmp_path)"
sidebar_regex = re.compile(r'# ═══════════════════════════════════════════════════════════════════════════════\n# SIDEBAR.*os\.unlink\(tmp_path\)', re.DOTALL)

new_logic = """# ═══════════════════════════════════════════════════════════════════════════════
# PROCESS UPLOAD
# ═══════════════════════════════════════════════════════════════════════════════
if 'results' not in st.session_state: st.session_state.results = None

# Hide sidebar and collapsed control globally
st.markdown("<style>[data-testid='stSidebar'] { display: none !important; } [data-testid='collapsedControl'] { display: none !important; }</style>", unsafe_allow_html=True)

uploaded_file_path = st.query_params.get("uploaded_file")
if uploaded_file_path and st.session_state.results is None:
    st.query_params.clear()
    with st.spinner("⚡ Analyzing network traffic — building baselines, running ensemble detectors..."):
        try:
            # Default parameters since sidebar is removed
            st.session_state.results = run_pipeline(
                uploaded_file_path, 
                window_size=500,
                baseline_ratio=0.4, 
                enable_ml=True
            )
        except Exception as e:
            st.error(f"Pipeline error: {e}")
            import traceback; st.code(traceback.format_exc())
        finally:
            try:
                os.unlink(uploaded_file_path)
            except:
                pass"""

content = sidebar_regex.sub(new_logic, content)

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Updated app.py successfully")
