import os

path = r'c:\Users\dhruv\Downloads\DELL HACATHON\DELL HACATHON\network_bouncer_x\dashboard\app.py'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Remove the broken block
broken_block = """# ═══════════════════════════════════════════════════════════════════════════════
# PROCESS UPLOAD
# ═══════════════════════════════════════════════════════════════════════════════
if 'results' not in st.session_state: st.session_state.results = None

# Hide sidebar and collapsed control globally
st.markdown("<style>[data-testid='stSidebar'] { display: none !important; } [data-testid='collapsedControl'] { display: none !important; }</style>", unsafe_allow_html=True)

try:
    import upload_state
    import importlib
    importlib.reload(upload_state)
    uploaded_file_path = upload_state.UPLOADED_FILE
except Exception as e:
    uploaded_file_path = None

if uploaded_file_path and st.session_state.results is None:
    # Clear the trigger so it doesn't run again if the user refreshes
    state_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'upload_state.py')
    with open(state_file, 'w', encoding='utf-8') as f:
        f.write("UPLOADED_FILE = None\\n")
        
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
                pass

"""
content = content.replace(broken_block, "")

# We also had the old block further down which we should remove:
old_process_block = """# ═══════════════════════════════════════════════════════════════════════════════
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

content = content.replace(old_process_block, "")

# Now insert the clean block AFTER set_page_config
correct_block = """
# ═══════════════════════════════════════════════════════════════════════════════
# PROCESS UPLOAD
# ═══════════════════════════════════════════════════════════════════════════════
if 'results' not in st.session_state: st.session_state.results = None

# Hide sidebar and collapsed control globally
st.markdown("<style>[data-testid='stSidebar'] { display: none !important; } [data-testid='collapsedControl'] { display: none !important; }</style>", unsafe_allow_html=True)

try:
    import dashboard.upload_state as upload_state
    import importlib
    importlib.reload(upload_state)
    uploaded_file_path = upload_state.UPLOADED_FILE
except Exception as e:
    uploaded_file_path = None

if uploaded_file_path and st.session_state.results is None:
    # Clear the trigger so it doesn't run again if the user refreshes
    state_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'upload_state.py')
    with open(state_file, 'w', encoding='utf-8') as f:
        f.write("UPLOADED_FILE = None\\n")
        
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
                pass
"""

content = content.replace('page_icon="🛡️", layout="wide"\n)', 'page_icon="🛡️", layout="wide"\n)\n' + correct_block)

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Fixed app.py layout")
