import re

with open('garuda.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Remove dead function calls from updateAll()
content = re.sub(r'^\s*updatePortScanner\(portData\);\s*\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*updateTrafficLive\(data\.network_traffic\|\|\{\}\);\s*\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*buildTopology\(data\);\s*\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*startTrafficPolling\(\);\s*\n', '', content, flags=re.MULTILINE)

# 2. Rewrite loadScans and renderScans for deduplication
new_load_scans = """async function loadScans(){
  const el=document.getElementById('scans-content');el.innerHTML=loadingHTML();
  try{
    const data=await apiFetch('/api/history/scans?limit=500');
    let rawScans=Array.isArray(data)?data:(data.scans||[]);
    let grouped = {};
    rawScans.forEach(s => {
      let key = s.ssid || 'Unknown Network';
      if (!grouped[key]) {
        grouped[key] = { ...s, scan_count: 1 };
      } else {
        grouped[key].scan_count++;
        if (new Date(s.timestamp) > new Date(grouped[key].timestamp)) {
          let count = grouped[key].scan_count;
          grouped[key] = { ...s, scan_count: count };
        }
      }
    });
    allScans = Object.values(grouped).sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));
    scanPage=1;
    renderScans(el);
  }
  catch(e){el.innerHTML=errorHTML(e.message,loadScans);}
}
function renderScans(el){
  if(!el) el=document.getElementById('scans-content');
  const tp=Math.max(1,Math.ceil(allScans.length/SCAN_PAGE_SIZE));
  if(scanPage>tp) scanPage=tp;
  const start=(scanPage-1)*SCAN_PAGE_SIZE;
  const page=allScans.slice(start,start+SCAN_PAGE_SIZE);
  let html=`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><div class="count">Showing ${start+1}–${Math.min(start+SCAN_PAGE_SIZE,allScans.length)} of ${allScans.length} unique networks</div></div>`;
  html+=`<div class="table-wrap"><table><thead><tr><th>#</th><th>Last Scan</th><th>Network</th><th>Times Scanned</th><th>Encryption</th><th>Devices</th><th>Risk Score</th><th>Threat Level</th></tr></thead><tbody>`;
  page.forEach((s,i)=>{
    const rid='scan_'+(s.id||i);const gi=start+i+1;
    html+=`<tr class="scan-row" data-rid="${rid}" style="cursor:pointer;font-family:var(--font-display)">
      <td>${gi}</td><td class="mono">${fmtDate(s.timestamp)}</td><td>${s.ssid||'—'}</td><td>${s.scan_count}</td><td>${s.encryption||'—'}</td><td>${s.device_count??'—'}</td>
      <td style="font-family:var(--font-display);font-weight:700;color:${riskColor(s.risk_label)}">${s.risk_score??'—'}</td>
      <td><span class="badge ${riskClass(s.threat_level)}">${s.threat_level||'—'}</span></td>
    </tr>
    <tr class="expand-row" id="${rid}" style="display:none"><td colspan="8"><div class="expand-content">
      <div>Duration: <span>${s.duration||'—'}</span></div><div>Gateway: <span>${s.gateway_ip||'—'}</span></div><div>Local IP: <span>${s.local_ip||'—'}</span></div><div>Active: <span>${s.active_count??'—'}</span></div>
    </div></td></tr>`;
  });
  html+='</tbody></table></div>';
  html+=buildPagination(allScans.length,scanPage,tp).replace(/goDevicePage/g,'goScanPage');
  el.innerHTML=html;
  el.querySelectorAll('.scan-row').forEach(row=>{row.addEventListener('click',()=>{const rid=row.dataset.rid;const expRow=document.getElementById(rid);if(expandedScanRow&&expandedScanRow!==expRow)expandedScanRow.style.display='none';expRow.style.display=expRow.style.display==='none'?'table-row':'none';expandedScanRow=expRow.style.display==='table-row'?expRow:null;});});
}"""

content = re.sub(
    r'async function loadScans\(\)\{.*?(?=function goScanPage)', 
    new_load_scans + '\n', 
    content, 
    flags=re.DOTALL
)

with open('garuda.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("JS modifications applied successfully.")
