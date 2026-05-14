import os
import re

SHARED_UTILS = """// shared utils
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function escAttr(s) {
  return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function showToast(msg, type='info', duration=3500) {
  let c = document.getElementById('garuda-toasts');
  if (!c) {
    c = document.createElement('div');
    c.id = 'garuda-toasts';
    c.style.cssText = 'position:fixed;bottom:24px;right:24px;display:flex;flex-direction:column;gap:10px;z-index:99999;pointer-events:none;align-items:flex-end;';
    document.body.appendChild(c);
  }
  const t = document.createElement('div');
  const s = getComputedStyle(document.documentElement);
  const accent = s.getPropertyValue('--accent').trim() || '#3b82f6';
  const success = s.getPropertyValue('--success').trim() || '#10b981';
  const warn = s.getPropertyValue('--warn').trim() || '#f59e0b';
  const danger = s.getPropertyValue('--danger').trim() || '#ef4444';
  const bg = type === 'error' ? danger : type === 'warn' ? warn : type === 'success' ? success : accent;
  t.style.cssText = `background:rgba(15,20,28,0.95);color:#fff;border-left:4px solid ${bg};padding:12px 16px;border-radius:6px;font-family:system-ui,sans-serif;font-size:13px;box-shadow:0 4px 12px rgba(0,0,0,0.3);opacity:0;transform:translateY(20px);transition:opacity 0.3s ease, transform 0.3s ease;pointer-events:auto;max-width:300px;word-wrap:break-word;`;
  t.innerHTML = escHtml(msg);
  c.appendChild(t);
  requestAnimationFrame(() => { t.style.opacity = '1'; t.style.transform = 'translateY(0)'; });
  setTimeout(() => {
    t.style.opacity = '0'; t.style.transform = 'translateY(20px)';
    setTimeout(() => t.remove(), 300);
  }, duration);
}
"""

FILES = [
    "history.html",
    "index.html",
    "garuda-realtime.html",
    "garuda.html",
    "garuda-landing.html",
    "diagnostic.html"
]

def remove_existing_utils(content):
    # Remove old escHtml, escAttr, showApiToast if any
    content = re.sub(r'function escHtml\([^)]*\)\s*\{[^}]*\}', '', content)
    content = re.sub(r'function escAttr\([^)]*\)\s*\{[^}]*\}', '', content)
    content = re.sub(r'let apiToastTimer = null;\s*function showApiToast\([^)]*\)\s*\{[\s\S]*?\}\s*(?=}?\n)', '', content)
    content = re.sub(r'let _toastT = null;\s*function showApiToast\([^)]*\)\s*\{[\s\S]*?\}\s*(?=}?\n)', '', content)
    content = re.sub(r'function esc\([^)]*\)\s*\{[^}]*\}', '', content)
    return content

for filename in FILES:
    if not os.path.exists(filename):
        print(f"Skipping {filename}, not found")
        continue
    
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    
    content = remove_existing_utils(content)
    
    # Inject at the first <script> block that doesn't have src
    # Find <script> not <script src=
    parts = re.split(r'(<script(?![^>]*src=)[^>]*>)', content)
    
    if len(parts) >= 3:
        # parts[0] is everything before <script>
        # parts[1] is the <script> tag itself
        # parts[2:] is everything after
        
        # Check if already has shared utils
        if "// shared utils" not in parts[2]:
            new_content = parts[0] + parts[1] + "\n" + SHARED_UTILS + parts[2]
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Injected shared utils into {filename}")
        else:
            print(f"{filename} already has shared utils")
    else:
        print(f"Could not find inline <script> block in {filename}")
