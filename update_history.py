import os
import re

def update_history():
    with open('history.html', 'r', encoding='utf-8') as f:
        content = f.read()

    # Add :root variables
    root_vars = """
:root {
  --bg: #0d1117;
  --bg-card: #161b22;
  --bg-secondary: #1c2128;
  --text-primary: #eef0f7;
  --text-secondary: #8b93a6;
  --text-muted: #3d4658;
  --accent: #3b82f6;
  --danger: #ef4444;
  --warn: #f59e0b;
  --success: #10b981;
  --purple: #a855f7;
  --critical: #ef4444;
  --b0: rgba(255,255,255,0.05);
  --b1: rgba(255,255,255,0.1);
}
"""
    # Inject root_vars after <style>
    content = content.replace("<style>", f"<style>\n{root_vars}")

    # Replace hex with var()
    hex_map = {
        r'#0d1117': 'var(--bg)',
        r'#161b22': 'var(--bg-card)',
        r'#1c2128': 'var(--bg-secondary)',
        r'#eef0f7': 'var(--text-primary)',
        r'#8b93a6': 'var(--text-secondary)',
        r'#3d4658': 'var(--text-muted)',
        r'#3b82f6': 'var(--accent)',
        r'#ef4444': 'var(--danger)',
        r'#f59e0b': 'var(--warn)',
        r'#10b981': 'var(--success)',
        r'#a855f7': 'var(--purple)',
        r'#f97316': 'var(--warn)' # map orange to warn
    }
    
    # Simple replace in style block
    style_match = re.search(r'<style>(.*?)</style>', content, flags=re.DOTALL)
    if style_match:
        style_content = style_match.group(1)
        for hex_val, var_name in hex_map.items():
            # ignore case in replace
            pattern = re.compile(hex_val, re.IGNORECASE)
            style_content = pattern.sub(var_name, style_content)
        content = content[:style_match.start(1)] + style_content + content[style_match.end(1):]

    # Chart.js defaults
    chart_defaults_old = """Chart.defaults.color = '#8b93a6';
Chart.defaults.borderColor = 'rgba(255,255,255,0.05)';"""

    chart_defaults_new = """const docStyle = getComputedStyle(document.documentElement);
const accentColor = docStyle.getPropertyValue('--accent').trim();
const successColor = docStyle.getPropertyValue('--success').trim();
const dangerColor = docStyle.getPropertyValue('--danger').trim();
const warnColor = docStyle.getPropertyValue('--warn').trim();
const textColor = docStyle.getPropertyValue('--text-secondary').trim();
const mutedColor = docStyle.getPropertyValue('--text-muted').trim();

Chart.defaults.color = textColor;
Chart.defaults.borderColor = 'rgba(255,255,255,0.05)';"""

    content = content.replace(chart_defaults_old, chart_defaults_new)

    # In JS: replace hex colors with vars
    content = content.replace("'#1f6feb'", "accentColor")
    content = content.replace("'#ef4444'", "dangerColor")
    content = content.replace("'#f97316'", "warnColor")
    content = content.replace("'#f59e0b'", "warnColor")
    content = content.replace("'#10b981'", "successColor")
    content = content.replace("'#3b82f6'", "accentColor")
    
    # riskColor
    risk_color_old = """function riskColor(label) {
  if (!label) return '#8b93a6';
  const l = label.toLowerCase();
  if (l === 'critical') return '#ef4444';
  if (l === 'high') return '#f97316';
  if (l === 'medium') return '#f59e0b';
  return '#10b981';
}"""
    risk_color_new = """function riskColor(label) {
  if (!label) return textColor;
  const l = label.toLowerCase();
  if (l === 'critical') return dangerColor;
  if (l === 'high') return warnColor; // Fallback or separate
  if (l === 'medium') return warnColor;
  return successColor;
}"""
    content = content.replace(risk_color_old, risk_color_new)

    # Remove console.log and console.error
    content = re.sub(r'console\.log\([^)]*\);?', '', content)
    content = re.sub(r'console\.error\([^)]*\);?', '', content)

    # Rewrite apiFetch unwrapping
    # Actually, history.html already uses apiFetch, let's fix its apiFetch implementation
    api_fetch_old = """async function apiFetch(path) {
  const res = await fetch(API + path);
  let body = {};
  try { body = await res.json(); } catch (_) {}
  if (body && typeof body.success === 'boolean') {
    if (!body.success) throw new Error(body.error || ('HTTP ' + res.status));
    return body.data;
  }
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return body;
}"""
    api_fetch_new = """async function apiFetch(path) {
  const res = await fetch(API + path);
  let json = {};
  try { json = await res.json(); } catch (_) {}
  if (json && typeof json.success === 'boolean') {
    if (!json.success) { showToast(json.error || 'Request failed', 'error'); throw new Error(json.error || 'Request failed'); }
    return json.data;
  }
  if (!res.ok) { showToast('HTTP ' + res.status, 'error'); throw new Error('HTTP ' + res.status); }
  return json;
}"""
    content = content.replace(api_fetch_old, api_fetch_new)

    # escAttr usage in HTML templating strings in history.html
    # Look for places where title, id, data-* are set
    # E.g. data-rid="${rid}" is already safe but let's do ${escAttr(rid)}
    content = content.replace('data-rid="${rid}"', 'data-rid="${escAttr(rid)}"')
    content = content.replace('id="${rid}"', 'id="${escAttr(rid)}"')
    # Also in generatePDFReport, though that is a new window doc

    # write back
    with open('history.html', 'w', encoding='utf-8') as f:
        f.write(content)

update_history()
