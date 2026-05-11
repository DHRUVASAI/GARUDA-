import re

with open('garuda.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix 1: loadPageData
old_loadPageData = """function loadPageData(page) {
  switch(page) {
    case 'dashboard':     loadDashboard(); break;
    case 'scan-history':  loadScans(); break;
    case 'alerts':        loadAlerts(); break;
    case 'known-devices': loadDevices(); break;
    case 'live-traffic':  
      renderCharts(); 
      fetch(`${API}/api/traffic/live`).then(r=>r.json()).then(t=>updateTrafficLive(t)).catch(()=>{});
      break;
    case 'history-traffic': loadTrafficHistory(24); break;
  }
}"""
new_loadPageData = """function loadPageData(page) {
  switch(page) {
    case 'overview':      loadDashboard(); break;
    case 'scan-history':  loadScans(); break;
    case 'alerts':        loadAlerts(); break;
  }
}"""
content = content.replace(old_loadPageData, new_loadPageData)

# Fix 2: loadDashboard Interval check
content = content.replace(
    "dashInterval=setInterval(async()=>{if(currentPage!=='dashboard')",
    "dashInterval=setInterval(async()=>{if(currentPage!=='overview')"
)

# Fix 3: renderScans empty state
old_renderScans_start = """function renderScans(el){
  if(!el) el=document.getElementById('scans-content');
  const tp=Math.max(1,Math.ceil(allScans.length/SCAN_PAGE_SIZE));"""
new_renderScans_start = """function renderScans(el){
  if(!el) el=document.getElementById('scans-content');
  if(allScans.length===0){
    el.innerHTML=`<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg><p>No scan history found. Run a network scan to get started.</p></div>`;
    return;
  }
  const tp=Math.max(1,Math.ceil(allScans.length/SCAN_PAGE_SIZE));"""
content = content.replace(old_renderScans_start, new_renderScans_start)

with open('garuda.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixes applied.")
