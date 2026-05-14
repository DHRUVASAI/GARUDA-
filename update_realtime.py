import re

def update_realtime():
    with open('garuda-realtime.html', 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. CSS for SSE badge
    css_insert = """
.sse-badge {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 12px;
  margin-left: 10px;
  font-family: var(--mono);
  letter-spacing: 0.05em;
  transition: all 0.3s ease;
}
.sse-live {
  background: rgba(52, 211, 153, 0.15);
  color: var(--success);
  border: 1px solid rgba(52, 211, 153, 0.3);
  box-shadow: 0 0 8px rgba(52, 211, 153, 0.4);
  animation: ssePulse 2s infinite;
}
.sse-recon {
  background: rgba(251, 191, 36, 0.15);
  color: var(--warn);
  border: 1px solid rgba(251, 191, 36, 0.3);
}
@keyframes ssePulse {
  0% { opacity: 1; }
  50% { opacity: 0.5; }
  100% { opacity: 1; }
}
"""
    if ".sse-badge" not in content:
        content = content.replace("</style>", f"{css_insert}</style>")

    # 2. Add badge to HTML
    if "sseBadge" not in content:
        content = content.replace("<h2>Alerts</h2>", '<h2 style="display:flex;align-items:center;">Alerts <span id="sseBadge" class="sse-badge sse-recon">CONNECTING</span></h2>')

    # 3. Update startSse JS
    old_sse = """  function startSse() {
    if (typeof EventSource === 'undefined') return;
    try { if (es) { es.close(); es = null; } } catch (e) {}
    const url = apiBase() + '/api/stream/alerts';
    es = new EventSource(url);
    es.onmessage = function (ev) {
      try {
        const msg = JSON.parse(ev.data);
        if (msg && msg.type === 'alert') mergeAlertFront(msg);
      } catch (e) { /* ignore malformed */ }
    };
    es.onerror = function () {
      /* browser auto-reconnects EventSource */
    };
  }"""
    
    new_sse = """  function startSse() {
    if (typeof EventSource === 'undefined') return;
    try { if (es) { es.close(); es = null; } } catch (e) {}
    const url = apiBase() + '/api/stream/alerts';
    es = new EventSource(url);
    const badge = document.getElementById('sseBadge');
    
    es.onopen = function() {
      if(badge) {
        badge.className = 'sse-badge sse-live';
        badge.textContent = 'LIVE';
      }
    };
    
    es.onmessage = function (ev) {
      try {
        const msg = JSON.parse(ev.data);
        if (msg && msg.type === 'alert') mergeAlertFront(msg);
      } catch (e) { /* ignore malformed */ }
    };
    
    es.onerror = function () {
      if(badge) {
        badge.className = 'sse-badge sse-recon';
        badge.textContent = 'RECONNECTING';
      }
    };
  }"""
    content = content.replace(old_sse, new_sse)

    # 4. Update apiFetch to use showToast
    content = content.replace("if (!j.success) throw new Error(j.error || ('API error: ' + path));",
"""if (!j.success) { showToast(j.error || 'API error: ' + path, 'error'); throw new Error(j.error || ('API error: ' + path)); }""")

    with open('garuda-realtime.html', 'w', encoding='utf-8') as f:
        f.write(content)

update_realtime()
