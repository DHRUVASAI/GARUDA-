import os

path = r'c:\Users\dhruv\Downloads\DELL HACATHON\DELL HACATHON\network_bouncer_x\dashboard\app.py'

with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find boundaries
BLOCK_START = None
BLOCK_END   = None
in_block = False
for i, line in enumerate(lines):
    if 'if results is None:' in line:
        BLOCK_START = i
        in_block = True
    if in_block and 'st.stop()' in line:
        BLOCK_END = i + 1  # exclusive — line after st.stop()
        break

assert BLOCK_START is not None and BLOCK_END is not None, f"Markers not found: start={BLOCK_START} end={BLOCK_END}"
print(f"Replacing lines {BLOCK_START+1}–{BLOCK_END} (0-indexed {BLOCK_START}–{BLOCK_END-1})")

new_block = (
    'if results is None:\n'
    '    import streamlit.components.v1 as components\n'
    '    _landing_path = os.path.join(os.path.dirname(__file__), "landing.html")\n'
    '    with open(_landing_path, "r", encoding="utf-8") as _f:\n'
    '        _landing_html = _f.read()\n'
    '    components.html(_landing_html, height=2800, scrolling=True)\n'
    '    st.stop()\n'
)

new_lines = lines[:BLOCK_START] + [new_block] + lines[BLOCK_END:]

with open(path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f"Done. New total lines: {len(new_lines)}")

# Verify seam
for i, l in enumerate(new_lines[BLOCK_START-1:BLOCK_START+10], start=BLOCK_START):
    print(f"L{i+1}: {l[:90].rstrip()}")
