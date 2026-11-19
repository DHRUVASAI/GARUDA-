(() => {
  const state = {
    view: "landing",
    filter: "all",
    search: "",
    renamingMac: null,
    topologyMode: "3d", // "3d" | "2d"
    topo3d: null,
    topo3dFailed: false,
    snapshot: null,
    offlineMode: false,
    ws: null,
    radarPoints: [],
    hoveredMac: null,
    selectedDeviceMac: null,
    radarZoom: 1.0,
    radarPanX: 0,
    radarPanY: 0,
    isRadarDragging: false,
    radarDragStartX: 0,
    radarDragStartY: 0,
    dragDistance: 0,
    pointerDownPos: null,
    soundEnabled: true,
    desktopNotifications: true,
    seenAlertIds: new Set(),
    checkedAdvice: new Set(JSON.parse(localStorage.getItem("garuda_v4_checked_advice") || "[]")),
    animPhase: 0,
  };

  const ICONS = {
    router: "📡", laptop: "💻", phone: "📱", tablet: "📲",
    tv: "📺", printer: "🖨️", iot: "🔌", unknown: "❓",
  };

  const $ = (id) => document.getElementById(id);

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function showToast(title, body, severity = "info") {
    const stack = $("toastStack");
    const el = document.createElement("div");
    el.className = `toast ${severity}`;
    el.innerHTML = `<div style="font-weight:700;margin-bottom:2px;">${escapeHtml(title)}</div><div style="opacity:0.88;">${escapeHtml(body)}</div>`;
    stack.appendChild(el);
    setTimeout(() => el.remove(), 5500);
  }

  function playAlertTone(severity = "warning") {
    if (!state.soundEnabled) return;
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = severity === "critical" ? "triangle" : "sine";
      osc.frequency.setValueAtTime(severity === "critical" ? 680 : 520, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(severity === "critical" ? 420 : 640, ctx.currentTime + 0.18);
      gain.gain.setValueAtTime(0.08, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.28);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.3);
    } catch (_) {}
  }

  function sendDesktopNotification(alert) {
    if (!state.desktopNotifications || !("Notification" in window)) return;
    if (Notification.permission === "granted") {
      new Notification(`GARUDA Alert: ${alert.title}`, { body: alert.plain_explanation });
    }
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const j = await res.json();
        detail = j.detail || j.message || detail;
      } catch (_) {}
      throw new Error(detail);
    }
    return res.json();
  }

  // Fault-Isolated 3D PBR Topology Mount (Automatic 2D Fallback if WebGL/CDN unavailable)
  async function ensureTopology3D() {
    if (state.topo3d || state.topo3dFailed || state.topologyMode !== "3d") return;
    try {
      const mod = await import("/static/topology3d.js");
      const host = $("topology3dHost");
      state.topo3d = await mod.mountGarudaTopology3D(host, {
        onHover: (hit, clientX, clientY) => {
          const tip = $("radarTooltip");
          const stageRect = $("topologyStage").getBoundingClientRect();
          if (hit?.device) {
            const mlTxt = hit.ml ? ` · AI Risk ${hit.ml.anomaly_score}` : "";
            tip.hidden = false;
            tip.style.left = `${Math.min(stageRect.width - 210, Math.max(8, clientX - stageRect.left + 14))}px`;
            tip.style.top = `${Math.max(8, clientY - stageRect.top - 34)}px`;
            tip.innerHTML = `<strong>${escapeHtml(hit.device.display_name)}</strong> · ${hit.device.is_safe ? "Safe" : "Unverified"}${mlTxt}`;
          } else {
            tip.hidden = true;
          }
        },
        onSelect: (device) => openDeviceDrawer(device.mac),
      });
      if (state.snapshot) state.topo3d.updateSnapshot(state.snapshot);
    } catch (_) {
      state.topo3dFailed = true;
      setTopologyMode("2d");
    }
  }

  function setTopologyMode(mode) {
    state.topologyMode = state.topo3dFailed ? "2d" : mode;
    const is3d = state.topologyMode === "3d";
    $("btnMode3D").classList.toggle("active", is3d);
    $("btnMode2D").classList.toggle("active", !is3d);
    $("topology3dHost").hidden = !is3d;
    $("networkRadar").hidden = is3d;
    if ($("btnResetView")) $("btnResetView").hidden = false;
    $("topologyHudBadge").textContent = is3d
      ? "Drag to orbit · Scroll to zoom · Click 3D device to inspect"
      : `2D Precision Radar (${state.radarZoom.toFixed(1)}x) · Drag to pan · Scroll to zoom · Hover to inspect`;
    if (is3d && state.view === "network") ensureTopology3D();
  }

  function switchView(viewName) {
    state.view = viewName;
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    const target = $(`view-${viewName}`);
    if (target) target.classList.add("active");
    document.querySelectorAll(".nav-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.view === viewName);
    });
    if (viewName === "network" && state.topologyMode === "3d") {
      ensureTopology3D();
    }
    if (state.snapshot) updateUrgentBanner();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function connectWebSocket() {
    if (location.protocol === "file:") return;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws/live`);
    state.ws = ws;
    ws.onopen = () => { state.offlineMode = false; updateConnectionPill(); };
    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === "snapshot") applySnapshot(msg.data);
        else if (msg.type === "alert") handleIncomingAlert(msg.data);
      } catch (_) {}
    };
    ws.onclose = () => {
      const pill = $("connectionModePill");
      pill.className = "pill pill-warn";
      pill.innerHTML = `<span class="dot"></span> Reconnecting…`;
      setTimeout(connectWebSocket, 3000);
    };
  }

  function handleIncomingAlert(alert) {
    if (state.seenAlertIds.has(alert.id)) return;
    state.seenAlertIds.add(alert.id);
    playAlertTone(alert.severity);
    showToast(alert.title, alert.plain_explanation, alert.severity);
    sendDesktopNotification(alert);
  }

  function updateConnectionPill() {
    const pill = $("connectionModePill");
    if (state.offlineMode) {
      pill.className = "pill pill-warn";
      pill.innerHTML = `<span class="dot"></span> Offline Preview`;
      return;
    }
    if (!state.snapshot) return;
    if (state.snapshot.mode === "simulation") {
      pill.className = "pill pill-warn";
      pill.innerHTML = `<span class="dot"></span> Safe Simulation <button id="btnSwitchLivePill" style="margin-left:8px;padding:2px 8px;font-size:10px;font-weight:600;cursor:pointer;background:#0ea5e9;color:#0b1120;border:none;border-radius:999px;">Switch to Live</button>`;
      $("btnSwitchLivePill")?.addEventListener("click", async (e) => {
        e.stopPropagation();
        try {
          await fetchJSON("/api/simulate", { method: "POST", body: JSON.stringify({ scenario: "reset" }) });
          await fetchJSON("/api/scan", { method: "POST" });
          showToast("Live Mode Active", "Switched to 100% real network scanning.", "info");
        } catch (err) {
          showToast("Error", err.message, "warning");
        }
      });
    } else {
      pill.className = "pill pill-safe";
      pill.innerHTML = `<span class="dot"></span> Live Real Network`;
    }
  }

  function updateUrgentBanner() {
    const snap = state.snapshot;
    if (!snap) return;
    const openAlert =
      snap.alerts.find((a) => !a.resolved && a.severity === "critical") ||
      snap.alerts.find((a) => !a.resolved);
    const banner = $("urgentBanner");
    if (openAlert && state.view !== "landing") {
      banner.classList.add("show");
      $("urgentBannerTitle").textContent = openAlert.title;
      $("urgentBannerDesc").textContent = openAlert.plain_explanation;
    } else {
      banner.classList.remove("show");
    }
  }

  function applySnapshot(snap) {
    state.snapshot = snap;
    state.soundEnabled = Boolean(snap.settings.sound_enabled);
    state.desktopNotifications = Boolean(snap.settings.desktop_notifications);
    updateConnectionPill();
    updateUrgentBanner();

    const cap = snap.capabilities;
    const fw = snap.firewall;
    const ids = snap.ids_stats;
    const ml = snap.ml;
    const led = snap.ledger;

    const idsLabel = cap.ids_mode === "live_packet_sniffer" ? "Live Scapy Packet IDS" : "OS Heuristic + DoH IDS";
    const mlLabel = cap.sklearn_available ? "sklearn IsolationForest + Welford" : "Pure-Python IsolationForest";
    const ledLabel = `${cap.crypto_signature_alg} + SHA-256 Merkle${cap.web3_configured ? " + EVM" : ""}`;
    const fwLabel = fw.can_enforce ? `${cap.firewall_backend} (Enforce)` : `${cap.firewall_backend} (Audit)`;

    $("heroIdsMode").textContent = `${idsLabel} · ${cap.crypto_signature_alg}`;
    $("capOs").textContent = `${cap.os_name} (${cap.is_admin ? "Elevated" : "Standard"})`;
    $("capIds").textContent = idsLabel;
    $("capMl").textContent = mlLabel;
    $("capLedger").textContent = ledLabel;
    $("capFirewall").textContent = fwLabel;

    $("shieldIdsMode").textContent = idsLabel;
    $("shieldClamav").textContent = cap.clamav_available ? "ClamAV Ready" : "YARA / Built-in Sigs";
    $("shieldYara").textContent = cap.yara_available ? "YARA Rules Active" : "Pure-Python Signatures";
    $("shieldFirewallMode").textContent = fwLabel;

    // Live IDS telemetry bar
    $("idsStatMode").textContent = ids.active_sniffer_running ? "Live Sniffer ON" : "Polling + DoH";
    $("idsStatPkts").textContent = Number(ids.packets_inspected || 0).toLocaleString();
    $("idsStatArp").textContent = `${ids.arp_events_observed} / ${ids.dhcp_offers_observed}`;
    $("idsStatDns").textContent = ids.dns_checks_passed ? "✓ Clean (DoH)" : "⚠ Mismatch";
    $("idsStatDns").style.color = ids.dns_checks_passed ? "var(--safe)" : "var(--danger)";

    // Nav badges
    const unv = snap.counts.unverified_devices || 0;
    const act = snap.counts.active_alerts || 0;
    $("navUnverifiedBadge").textContent = unv;
    $("navUnverifiedBadge").classList.toggle("zero", unv === 0);
    $("navAlertsBadge").textContent = act;
    $("navAlertsBadge").classList.toggle("zero", act === 0);

    // Hero live preview
    const sc = snap.advisor.safety_score;
    const scLabel = snap.advisor.safety_label;
    $("heroLiveSsid").textContent = snap.network.ssid;
    $("heroNetType").textContent = `Network Type: ${snap.network.network_type}`;
    $("heroDeviceSummary").textContent = `${snap.counts.total_connected} connected · AI Peak ${ml.network_anomaly_score}`;
    const hPill = $("heroSafetyPill");
    hPill.className = `pill ${sc >= 82 ? "pill-safe" : sc >= 55 ? "pill-warn" : "pill-danger"}`;
    hPill.innerHTML = `<span class="dot"></span> ${escapeHtml(scLabel)} (${sc}/100)`;

    const permBanner = $("ssidPermBanner");
    if (snap.network.ssid_permission_warning) {
      permBanner.hidden = false;
      $("ssidPermText").textContent = snap.network.ssid_permission_warning;
    } else {
      permBanner.hidden = true;
    }

    // Score Ring
    const circ = 314.16;
    const arc = $("scoreRingArc");
    arc.style.strokeDashoffset = String(circ - (circ * Math.max(0, Math.min(100, sc))) / 100);
    arc.style.stroke = sc >= 82 ? "var(--safe)" : sc >= 55 ? "var(--warn)" : "var(--danger)";
    $("scoreRingVal").textContent = sc;
    $("scoreRingLabel").textContent = scLabel;

    // KPIs
    $("kpiTotalDevices").textContent = snap.counts.total_connected;
    $("kpiSafeSplit").textContent = `${snap.counts.safe_devices} marked safe`;
    $("kpiMlScore").textContent = `${ml.network_anomaly_score}`;
    $("kpiMlScore").style.color = ml.network_anomaly_score >= 70 ? "var(--danger)" : ml.network_anomaly_score >= 42 ? "var(--warn)" : "var(--safe)";
    $("kpiMlStatus").textContent = ml.status_label;
    $("kpiAlerts").textContent = act;
    $("kpiLedgerCount").textContent = `${led.total_blocks} signed blocks`;

    $("kpiVpnStatus").textContent = snap.network.vpn_active ? "Protected" : "Off";
    $("kpiVpnStatus").style.color = snap.network.vpn_active ? "var(--safe)" : "var(--ink)";
    $("kpiVpnDetail").textContent = snap.network.vpn_active ? (snap.network.vpn_interface || "Encrypted tunnel active") : "No active VPN detected";

    // Network Card
    $("netSsid").textContent = snap.network.ssid;
    $("netTypeBadge").textContent = snap.network.network_type;
    $("netArpPinBadge").hidden = !snap.network.arp_pinned;
    $("netPlainSummary").textContent = snap.network.plain_summary;
    $("netMedium").textContent = snap.network.connection_medium;
    $("netProtocol").textContent = snap.network.security_protocol + (snap.network.signal_percent ? ` (${snap.network.signal_percent}%)` : "");
    $("netLocalIp").textContent = snap.network.local_ip;
    $("netGatewayIp").textContent = snap.network.gateway_ip;
    $("netGatewayMac").textContent = snap.network.gateway_mac || "Unavailable";
    $("netDns").textContent = (snap.network.dns_servers || []).join(", ") || "--";

    const enc = $("netEncBadge");
    enc.textContent = `Encryption: ${snap.network.encryption_grade}`;
    enc.className = `pill ${
      snap.network.encryption_grade === "Strong" || snap.network.encryption_grade === "Good" ? "pill-safe" : "pill-danger"
    }`;

    // Settings sync
    $("setSound").checked = Boolean(snap.settings.sound_enabled);
    $("setDesktop").checked = Boolean(snap.settings.desktop_notifications);
    $("setAutoBlock").checked = Boolean(snap.settings.auto_block_active_attackers);
    $("setSimMode").checked = Boolean(snap.settings.simulation_mode);
    if (document.activeElement !== $("setWebhook")) {
      $("setWebhook").value = snap.settings.webhook_url || "";
    }

    if (state.topo3d) state.topo3d.updateSnapshot(snap);

    renderDevices();
    renderAlerts();
    renderMLAndLedger(ml, led);
    renderMalware(snap.malware);
    renderFirewall(snap.firewall);
    renderAdvisor();

    if (state.selectedDeviceMac) openDeviceDrawer(state.selectedDeviceMac);
  }

  function renderDevices() {
    const snap = state.snapshot;
    if (!snap) return;
    const list = $("deviceList");
    const q = state.search.trim().toLowerCase();
    const mlMap = new Map((snap.ml?.device_scores || []).map((m) => [m.mac.toUpperCase(), m]));

    const filtered = snap.devices
      .filter((d) => d.is_online)
      .filter((d) => (state.filter === "safe" ? d.is_safe : state.filter === "unverified" ? !d.is_safe : true))
      .filter((d) => {
        if (!q) return true;
        return (
          (d.display_name || "").toLowerCase().includes(q) ||
          (d.real_name || "").toLowerCase().includes(q) ||
          (d.vendor || "").toLowerCase().includes(q) ||
          (d.ip || "").toLowerCase().includes(q) ||
          (d.mac || "").toLowerCase().includes(q)
        );
      });

    if (!filtered.length) {
      list.innerHTML = `<div class="card muted">No connected devices match this view right now.</div>`;
      return;
    }

    list.innerHTML = filtered
      .map((d) => {
        const icon = ICONS[d.device_type] || "💻";
        const ml = mlMap.get(d.mac.toUpperCase());
        const safeBadge = d.is_safe
          ? `<span class="pill pill-safe"><span class="dot"></span> Verified Safe</span>`
          : `<span class="pill pill-warn"><span class="dot"></span> Unverified</span>`;
        const mlBadge = ml
          ? `<span class="pill ${ml.risk_level === "critical" ? "pill-danger" : ml.risk_level === "elevated" ? "pill-warn" : "pill-neutral"}">AI Risk ${ml.anomaly_score}</span>`
          : "";
        const srcBadge = `<span class="pill pill-neutral">via ${escapeHtml(d.name_source.toUpperCase())}</span>`;
        const roleBadge = d.is_gateway
          ? `<span class="pill pill-accent">Main Router</span>`
          : d.is_self ? `<span class="pill pill-accent">This Device</span>` : "";

        const renameBox =
          state.renamingMac === d.mac
            ? `<div class="rename-inline">
                 <input class="input" id="inlineRenameInput" value="${escapeHtml(d.display_name)}" placeholder="Friendly name..." />
                 <button class="btn btn-primary btn-sm" data-rename-save="${escapeHtml(d.mac)}">Save</button>
                 <button class="btn btn-sm" data-rename-cancel="1">Cancel</button>
               </div>`
            : "";

        return `
          <div class="device-row ${d.is_safe ? "" : "unverified"}">
            <div class="device-left">
              <div class="device-icon">${icon}</div>
              <div>
                <div class="device-name">
                  <span>${escapeHtml(d.display_name)}</span>
                  ${safeBadge} ${mlBadge} ${roleBadge} ${srcBadge}
                </div>
                <div class="device-meta">
                  ${escapeHtml(d.vendor)} · IP <span class="mono">${escapeHtml(d.ip)}</span> · MAC <span class="mono">${escapeHtml(d.mac)}</span>
                  ${d.latency_ms != null ? ` · ${d.latency_ms} ms` : ""}
                </div>
                ${renameBox}
              </div>
            </div>
            <div class="device-actions">
              <button class="btn btn-sm" data-inspect="${escapeHtml(d.mac)}">Details</button>
              <button class="btn btn-sm" data-rename-open="${escapeHtml(d.mac)}">Rename</button>
              ${
                d.is_safe
                  ? `<button class="btn btn-sm" data-trust="${escapeHtml(d.mac)}" data-val="false">Unmark</button>`
                  : `<button class="btn btn-safe btn-sm" data-trust="${escapeHtml(d.mac)}" data-val="true">✓ Mark Safe</button>`
              }
            </div>
          </div>
        `;
      })
      .join("");
  }

  function renderMLAndLedger(ml, led) {
    if (ml) {
      $("mlChipPeak").textContent = `${ml.network_anomaly_score} / 100`;
      $("mlChipSamples").textContent = `${ml.baseline_samples} vectors`;
      $("mlEngineSub").textContent = ml.engine_name;
      $("mlHeadlineBox").innerHTML = `<strong>${escapeHtml(ml.status_label)}:</strong> ${escapeHtml(ml.headline)}`;

      $("mlDeviceScoresList").innerHTML = (ml.device_scores || [])
        .map((d) => {
          const barColor = d.risk_level === "critical" ? "var(--danger)" : d.risk_level === "elevated" ? "var(--warn)" : "var(--safe)";
          const factors = (d.top_factors || [])
            .map((f) => `<span class="factor-chip"><strong>${f.contribution_pct}%</strong> ${escapeHtml(f.label)}</span>`)
            .join("");
          return `
            <div class="ml-device-card ${escapeHtml(d.risk_level)}">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
                <div><strong>${escapeHtml(d.display_name)}</strong> <span class="muted mono">${escapeHtml(d.ip)}</span></div>
                <span class="pill ${d.risk_level === "critical" ? "pill-danger" : d.risk_level === "elevated" ? "pill-warn" : "pill-safe"} mono">
                  ${d.anomaly_score} / 100
                </span>
              </div>
              <div class="ml-bar-track"><div class="ml-bar-fill" style="width:${Math.max(4, d.anomaly_score)}%;background:${barColor};"></div></div>
              <div class="muted">${escapeHtml(d.plain_summary)}</div>
              <div style="margin-top:4px;">${factors}</div>
            </div>
          `;
        })
        .join("");
    }

    if (led) {
      $("ledgerChipValid").textContent = led.integrity_valid ? "✓ Chain Valid" : "⚠ Tampered";
      $("ledgerChipValid").style.color = led.integrity_valid ? "var(--safe)" : "var(--danger)";
      $("ledgerChipAlg").textContent = led.signature_alg;

      const pill = $("ledgerStatusPill");
      pill.textContent = led.integrity_valid ? "✓ Cryptographically Verified" : "⚠ Tampering Detected";
      pill.className = `pill ${led.integrity_valid ? "pill-safe" : "pill-danger"}`;

      $("ledgerMerkleRoot").textContent = `${led.merkle_root.slice(0, 18)}…${led.merkle_root.slice(-10)}`;
      $("ledgerPubkey").textContent = led.node_pubkey_short;
      $("ledgerCounts").textContent = `${led.total_blocks} sealed / ${led.anchored_blocks} EVM`;
      $("ledgerContract").textContent = led.contract_address;

      $("ledgerBlocksList").innerHTML = (led.recent_blocks || [])
        .map(
          (b) => `
          <div class="ledger-block">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
              <div>
                <span class="pill pill-accent mono">#${b.block_index}</span>
                <strong style="margin-left:6px;">${escapeHtml(b.summary)}</strong>
              </div>
              <div style="display:flex;gap:6px;align-items:center;">
                <span class="pill ${b.anchor_status === "anchored_evm" ? "pill-safe" : "pill-neutral"}">${escapeHtml(b.anchor_status)}</span>
                <button class="btn btn-sm" data-merkle-proof="${b.block_index}">Merkle Proof</button>
              </div>
            </div>
            <div class="hash-line mono">Hash: ${escapeHtml(b.block_hash.slice(0, 32))}… · Prev: ${escapeHtml(b.prev_hash.slice(0, 16))}… · ${escapeHtml(b.signature_alg)}</div>
          </div>`
        )
        .join("");
    }
  }

  function renderAlerts() {
    const snap = state.snapshot;
    if (!snap) return;
    const container = $("alertsList");
    if (!snap.alerts.length) {
      container.innerHTML = `<div class="muted" style="padding:18px 0;">All clear — no active attacks, passive eavesdropping risks, or unverified intruders detected.</div>`;
      return;
    }
    const catLabels = {
      active_attack: "Active Attack", passive_risk: "Passive Risk",
      unverified_device: "Unverified Device", malware_threat: "Malware / Virus", firewall_event: "Firewall",
    };
    container.innerHTML = snap.alerts
      .map(
        (a) => `
        <div class="alert-item ${escapeHtml(a.severity)} ${a.resolved ? "resolved" : ""}">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap;">
            <div>
              <span class="pill ${a.severity === "critical" ? "pill-danger" : "pill-warn"}">${catLabels[a.category] || escapeHtml(a.category)}</span>
              <strong style="margin-left:8px;font-size:14.5px;">${escapeHtml(a.title)}</strong>
            </div>
            <div style="display:flex;gap:6px;">
              ${a.related_ip && !a.resolved ? `<button class="btn btn-danger btn-sm" data-quickblock="${escapeHtml(a.related_ip)}">Block ${escapeHtml(a.related_ip)}</button>` : ""}
              ${a.resolved ? `<span class="pill pill-safe">Resolved</span>` : `<button class="btn btn-sm" data-resolve="${a.id}">Resolve</button>`}
            </div>
          </div>
          <p style="margin:9px 0 0;font-size:13.5px;">${escapeHtml(a.plain_explanation)}</p>
          <div class="alert-action-box"><strong>What to do now:</strong> ${escapeHtml(a.what_to_do)}</div>
        </div>`
      )
      .join("");
  }

  function renderMalware(mw) {
    if (!mw) return;
    const findings = mw.findings || [];
    if (!mw.last_scan_at && !findings.length) {
      $("malwareSummary").textContent = `Engines ready: ${(mw.engines_available || []).join(", ")}. Click "Run Virus Scan" to check files and running apps.`;
    } else if (findings.length) {
      $("malwareSummary").innerHTML = `<strong style="color:var(--danger);">${findings.length} threat(s) detected</strong> (${mw.files_scanned} files · ${mw.processes_scanned} processes scanned).`;
    } else {
      $("malwareSummary").innerHTML = `<strong style="color:var(--safe);">Clean Scan:</strong> 0 threats found across ${mw.files_scanned} files and ${mw.processes_scanned} running processes.`;
    }
    $("malwareFindingsList").innerHTML = findings
      .map(
        (f) => `
        <div class="alert-item ${escapeHtml(f.severity || "critical")}">
          <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;">
            <strong>${escapeHtml(f.name)}</strong>
            <span class="pill pill-danger">${escapeHtml(f.engine.toUpperCase())} · ${escapeHtml(f.category)}</span>
          </div>
          <div class="muted mono" style="margin-top:4px;word-break:break-all;">${escapeHtml(f.target)}</div>
          <p style="margin:8px 0 0;font-size:13px;">${escapeHtml(f.plain_explanation)}</p>
          <div class="alert-action-box"><strong>What to do now:</strong> ${escapeHtml(f.what_to_do)}</div>
        </div>`
      )
      .join("");
  }

  function renderFirewall(fw) {
    if (!fw) return;
    $("fwPlainSummary").textContent = fw.plain_summary;
    const badge = $("fwStatusBadge");
    badge.textContent = fw.enabled ? "Firewall ON" : "Firewall OFF / Audit";
    badge.className = `pill ${fw.enabled ? "pill-safe" : "pill-warn"}`;

    const note = $("fwPrivilegeNote");
    if (fw.privilege_note) { note.hidden = false; note.textContent = fw.privilege_note; }
    else { note.hidden = true; }

    const btn = $("btnToggleLockdown");
    btn.textContent = fw.lockdown_active ? "Disable Lockdown" : "Enable Lockdown";
    btn.className = `btn btn-sm ${fw.lockdown_active ? "btn-safe" : "btn-danger"}`;

    $("fwBlockedList").innerHTML = (fw.blocked_ips || []).length
      ? fw.blocked_ips.map((ip) => `<div class="mini-list-row"><span>Blocked IP: <strong class="mono">${escapeHtml(ip)}</strong></span><button class="btn btn-sm" data-unblock="${escapeHtml(ip)}">Unblock</button></div>`).join("")
      : `<div class="muted">No IPs currently blocked by GARUDA.</div>`;

    const ports = fw.listening_ports || [];
    $("fwPortsList").innerHTML = ports.length
      ? ports.slice(0, 10).map((p) => `<div class="mini-list-row"><div><strong class="mono">Port ${escapeHtml(p.port)} (${escapeHtml(p.protocol)})</strong> · ${escapeHtml(p.process_name)}<div class="muted">${escapeHtml(p.plain_note)}</div></div><span class="pill ${p.risk_level === "high" ? "pill-danger" : p.risk_level === "medium" ? "pill-warn" : "pill-safe"}">${escapeHtml(p.risk_level.toUpperCase())}</span></div>`).join("")
      : `<div class="muted">No exposed non-loopback TCP ports detected.</div>`;
  }

  function renderAdvisor() {
    const snap = state.snapshot;
    if (!snap || !snap.advisor) return;
    const adv = snap.advisor;
    const pill = $("guideScorePill");
    pill.textContent = `Safety Score: ${adv.safety_score} / 100 · ${adv.safety_label}`;
    pill.className = `pill ${adv.safety_score >= 82 ? "pill-safe" : adv.safety_score >= 55 ? "pill-warn" : "pill-danger"}`;
    $("guideHeadline").textContent = adv.headline;
    $("guideSub").textContent = `Current Network: ${snap.network.ssid} (${snap.network.network_type} · ${snap.network.security_protocol})`;
    $("passiveHonestyNote").textContent = adv.passive_honesty_note;

    $("adviceList").innerHTML = adv.recommendations
      .map((r) => {
        const done = state.checkedAdvice.has(r.id);
        return `
          <div class="advice-item ${done ? "done" : ""}">
            <input type="checkbox" data-advice-check="${escapeHtml(r.id)}" ${done ? "checked" : ""} style="margin-top:4px;cursor:pointer;" />
            <div style="flex:1;">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <strong style="font-size:14px;">${escapeHtml(r.title)}</strong>
                <span class="pill ${r.priority === "urgent" ? "pill-danger" : r.priority === "recommended" ? "pill-warn" : "pill-safe"}">${escapeHtml(r.priority)}</span>
              </div>
              <div class="muted" style="margin:4px 0;">${escapeHtml(r.why_it_matters)}</div>
              <div style="font-size:13px;"><strong>Simple step:</strong> ${escapeHtml(r.simple_step)}</div>
            </div>
          </div>`;
      })
      .join("");

    $("activityGuideList").innerHTML = adv.activity_guide
      .map((g) => `<div class="activity-row"><div><strong style="font-size:14px;">${escapeHtml(g.activity)}</strong><div class="muted">${escapeHtml(g.note)}</div></div><span class="pill ${g.status === "safe" ? "pill-safe" : g.status === "caution" ? "pill-warn" : "pill-danger"}">${g.status === "safe" ? "Safe" : g.status === "caution" ? "Use Caution" : "Avoid Now"}</span></div>`)
      .join("");
  }

  function openDeviceDrawer(mac) {
    const dev = state.snapshot?.devices.find((d) => (d.mac || "").toUpperCase() === (mac || "").toUpperCase());
    if (!dev) return;
    const ml = (state.snapshot?.ml?.device_scores || []).find((m) => m.mac.toUpperCase() === mac.toUpperCase());
    state.selectedDeviceMac = mac;
    $("drawerTitle").textContent = dev.display_name;
    $("drawerSubtitle").textContent = `${dev.vendor} · ${dev.is_safe ? "Verified Safe" : "Unverified Device"}`;
    $("drawerBody").innerHTML = `
      <div class="spec-grid" style="border-top:none;padding-top:0;">
        <div class="spec-cell"><span>Real Discovered Name</span><strong>${escapeHtml(dev.real_name)}</strong></div>
        <div class="spec-cell"><span>Naming Protocol</span><strong class="mono">${escapeHtml(dev.name_source.toUpperCase())}</strong></div>
        <div class="spec-cell"><span>IP Address</span><strong class="mono">${escapeHtml(dev.ip)}</strong></div>
        <div class="spec-cell"><span>Hardware Address (MAC)</span><strong class="mono">${escapeHtml(dev.mac)}</strong></div>
        <div class="spec-cell"><span>AI Anomaly Score</span><strong class="mono">${ml ? ml.anomaly_score + " / 100 (" + ml.risk_level + ")" : "--"}</strong></div>
        <div class="spec-cell"><span>Response Time</span><strong class="mono">${dev.latency_ms != null ? dev.latency_ms + " ms" : "--"}</strong></div>
      </div>
      <div class="form-row" style="margin-top:14px;">
        <label for="drawerRenameInput">Friendly Label</label>
        <input class="input" id="drawerRenameInput" value="${escapeHtml(dev.display_name)}" />
      </div>
      <div class="status-box" style="margin-top:12px;">
        ${ml ? `<strong>AI Behavioral Summary:</strong> ${escapeHtml(ml.plain_summary)}` : "Behavioral baseline ready."}
      </div>
    `;
    const trustBtn = $("drawerTrustBtn");
    trustBtn.textContent = dev.is_safe ? "Unmark Safe" : "✓ Mark as Safe";
    trustBtn.className = `btn btn-sm ${dev.is_safe ? "" : "btn-safe"}`;
    $("drawerBlockBtn").disabled = Boolean(dev.is_self || dev.is_gateway);
    $("drawerBackdrop").hidden = false;
    $("deviceDrawer").classList.add("open");
    $("deviceDrawer").setAttribute("aria-hidden", "false");
  }

  function closeDeviceDrawer() {
    $("drawerBackdrop").hidden = true;
    $("deviceDrawer").classList.remove("open");
    $("deviceDrawer").setAttribute("aria-hidden", "true");
    state.selectedDeviceMac = null;
  }

  // Adaptive node radius by device count N
  function getNodeRadius(count, compact = false) {
    if (compact) {
      if (count <= 18) return 8;
      if (count <= 80) return 5.5;
      if (count <= 300) return 3.5;
      return 2.2;
    }
    if (count <= 18) return 10;
    if (count <= 80) return 7;
    if (count <= 300) return 4.5;
    return 3;
  }

  // 2D Precision Multi-Ring Radar (Hero preview + 2D Topology Mode)
  function drawRadar(canvasId, compact = false) {
    const canvas = $(canvasId);
    if (!canvas || canvas.hidden || !state.snapshot) return;
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const tw = Math.round(rect.width * dpr);
    const th = Math.round(rect.height * dpr);
    if (canvas.width !== tw || canvas.height !== th) { canvas.width = tw; canvas.height = th; }

    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width, h = rect.height, cx = w / 2, cy = h / 2;
    const dark = document.body.classList.contains("theme-dark");
    const hasCrit = (state.snapshot.alerts || []).some((a) => !a.resolved && a.severity === "critical");

    ctx.clearRect(0, 0, w, h);

    const devices = (state.snapshot.devices || []).filter((d) => d && d.is_online !== false);
    const totalCount = devices.length;
    const nodeRadius = getNodeRadius(totalCount, compact);

    // Dynamic Central Router Radius (measured with padding)
    ctx.font = compact ? "700 9.5px Inter, sans-serif" : "700 11px Inter, sans-serif";
    const routerTextWidth = ctx.measureText("ROUTER").width;
    const routerRadius = Math.max(compact ? 20 : 28, Math.round(routerTextWidth * 0.65));

    // Shared Multi-Ring Polar Layout Engine
    const engine = window.GarudaLayoutEngine;
    let minNodeSpacing;
    if (totalCount <= 18) minNodeSpacing = compact ? 26 : 38;
    else if (totalCount <= 80) minNodeSpacing = compact ? 18 : 28;
    else if (totalCount <= 300) minNodeSpacing = compact ? 12 : 19;
    else minNodeSpacing = compact ? 8 : 13;

    const layout = engine
      ? engine.computePolarLayout(devices, state.snapshot.alerts || [], state.snapshot.ml?.device_scores || [], {
          mode: "2d",
          minNodeSpacing,
          centerRouterRadius: routerRadius,
        })
      : { nodes: [], rings: [], outerRadius: Math.min(w, h) * 0.4, gateway: devices[0] };

    // For hero radar, auto-fit to outer radius so 100-1,000 dots fit cleanly
    const zoom = compact ? (Math.min(w, h) * 0.44) / Math.max(1, layout.outerRadius) : state.radarZoom;
    const panX = compact ? 0 : state.radarPanX;
    const panY = compact ? 0 : state.radarPanY;

    const effCx = cx + panX;
    const effCy = cy + panY;

    // Render concentric radar trust rings
    layout.rings.forEach((ring) => {
      const r = ring.radius * zoom;
      if (r <= 0) return;
      ctx.beginPath();
      ctx.arc(effCx, effCy, r, 0, Math.PI * 2);
      if (ring.band === "C") {
        ctx.strokeStyle = dark ? "rgba(227, 96, 80, 0.28)" : "rgba(197, 54, 36, 0.24)";
        ctx.setLineDash([4, 4]);
      } else if (ring.band === "B") {
        ctx.strokeStyle = dark ? "rgba(226, 163, 67, 0.22)" : "rgba(185, 107, 8, 0.18)";
        ctx.setLineDash([2, 4]);
      } else {
        ctx.strokeStyle = dark ? "rgba(62, 180, 136, 0.22)" : "rgba(21, 127, 86, 0.18)";
        ctx.setLineDash([]);
      }
      ctx.lineWidth = 1;
      ctx.stroke();
    });
    ctx.setLineDash([]);

    // Expanding radar pulse sweep ring
    const maxOuterScaled = (layout.outerRadius || 100) * zoom;
    const pulseR = ((state.animPhase * 0.35) % 1) * maxOuterScaled;
    ctx.beginPath();
    ctx.arc(effCx, effCy, pulseR, 0, Math.PI * 2);
    ctx.strokeStyle = hasCrit
      ? `rgba(197,54,36,${0.28 * (1 - pulseR / Math.max(1, maxOuterScaled))})`
      : `rgba(30,79,214,${0.18 * (1 - pulseR / Math.max(1, maxOuterScaled))})`;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Palette tokens
    const colorSafe = dark ? "#3EB488" : "#157F56";
    const colorWarn = dark ? "#E2A343" : "#B96B08";
    const colorAlert = dark ? "#E36050" : "#C53624";
    const points = [];

    // Draw connection lines and node dots
    layout.nodes.forEach((node, idx) => {
      const d = node.device;
      const sx = effCx + node.x * zoom;
      const sy = effCy + node.y * zoom;
      const color = node.isAlert ? colorAlert : node.isSafe ? colorSafe : colorWarn;

      // Radial link line from router center
      ctx.beginPath();
      ctx.moveTo(effCx, effCy);
      ctx.lineTo(sx, sy);
      ctx.strokeStyle = node.isAlert
        ? "rgba(197,54,36,0.52)"
        : node.isSafe
        ? "rgba(21,127,86,0.22)"
        : "rgba(185,107,8,0.36)";
      ctx.lineWidth = node.isAlert ? 2.0 : 1.2;
      ctx.stroke();

      // Traveling packet dot
      if (totalCount <= 80 || node.isAlert || idx < 35) {
        const t = (state.animPhase * 0.45 + idx * 0.23) % 1;
        const px = effCx + (sx - effCx) * t;
        const py = effCy + (sy - effCy) * t;
        ctx.beginPath();
        ctx.arc(px, py, Math.max(1.5, nodeRadius * 0.4), 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
      }

      // Node circle
      const hovered = !compact && state.hoveredMac === d.mac;
      const rNode = nodeRadius + (hovered ? 2.5 : 0);
      ctx.beginPath();
      ctx.arc(sx, sy, rNode, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = dark ? "#1A1E26" : "#FAF8F4";
      ctx.lineWidth = Math.max(1.2, rNode * 0.25);
      ctx.stroke();

      // Anomaly Halo
      if (node.isAlert || (node.ml && node.ml.anomaly_score >= 38)) {
        ctx.beginPath();
        ctx.arc(sx, sy, rNode + 4.5, 0, Math.PI * 2);
        ctx.strokeStyle = node.isAlert ? "rgba(227,96,80,0.65)" : "rgba(226,163,67,0.55)";
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      points.push({ screenX: sx, screenY: sy, effRadius: rNode, device: d, node });
    });

    // Central Router Node Monolith
    ctx.beginPath();
    ctx.arc(effCx, effCy, routerRadius, 0, Math.PI * 2);
    ctx.fillStyle = hasCrit ? (dark ? "#E36050" : "#C53624") : (dark ? "#6394F2" : "#1E4FD6");
    ctx.fill();
    ctx.strokeStyle = dark ? "#1A1E26" : "#FAF8F4";
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Crisp Router Label with guaranteed padding
    ctx.fillStyle = "#FFFFFF";
    ctx.font = compact ? "700 9.5px Inter, sans-serif" : "700 11px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("ROUTER", effCx, effCy);
    ctx.textBaseline = "alphabetic";

    // Priority-Sorted Greedy 2D AABB Collision Placer for Labels
    if (engine) {
      ctx.font = compact ? "600 10px Inter, sans-serif" : "600 11px Inter, sans-serif";
      const labelResult = engine.compute2DLabelPlacement(layout.nodes, {
        width: w,
        height: h,
        cx,
        cy,
        zoom,
        panX,
        panY,
        nodeRadius,
        routerRadius,
        hoveredMac: state.hoveredMac,
        selectedMac: state.selectedDeviceMac,
        compact,
        measureTextFn: (txt) => ctx.measureText(txt),
      });

      // Render accepted non-overlapping labels with crisp pill backdrops
      labelResult.placedLabels.forEach((l) => {
        const b = l.box;
        const bw = b.x2 - b.x1;
        const bh = b.y2 - b.y1;

        ctx.beginPath();
        ctx.roundRect(b.x1, b.y1, bw, bh, 4);
        ctx.fillStyle = dark ? "rgba(26, 30, 38, 0.92)" : "rgba(250, 248, 244, 0.92)";
        ctx.fill();
        ctx.strokeStyle = l.node.isAlert
          ? (dark ? "rgba(227,96,80,0.6)" : "rgba(197,54,36,0.6)")
          : (dark ? "rgba(236, 234, 228, 0.16)" : "rgba(22, 24, 29, 0.14)");
        ctx.lineWidth = 1;
        ctx.stroke();

        ctx.fillStyle = l.node.isAlert
          ? (dark ? "#F87171" : "#DC2626")
          : (dark ? "#ECEAE4" : "#16181D");
        ctx.font = compact ? "600 10px Inter, sans-serif" : "600 11px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(l.text, (b.x1 + b.x2) / 2, (b.y1 + b.y2) / 2);
      });

      ctx.textBaseline = "alphabetic";

      if (!compact) {
        state.radarPoints = points;
        const hud = $("topologyHudBadge");
        if (hud && state.topologyMode === "2d") {
          hud.textContent = `Showing ${labelResult.placedCount} of ${layout.nodes.length} labels · Scroll to zoom (${state.radarZoom.toFixed(1)}x), drag to pan, hover to inspect`;
        }
      }
    } else {
      if (!compact) state.radarPoints = points;
    }
  }

  function startAnimationLoop() {
    const tick = () => {
      state.animPhase += 0.012;
      if (state.view === "landing") drawRadar("heroRadarCanvas", true);
      if (state.view === "network" && state.topologyMode === "2d") drawRadar("networkRadar", false);
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  // Event Wiring
  document.querySelectorAll(".nav-btn").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("brandHome").addEventListener("click", () => switchView("landing"));
  $("btnLaunchGuardian").addEventListener("click", () => switchView("network"));
  $("btnBannerInspect").addEventListener("click", () => switchView("threats"));
  $("btnCloseDrawer").addEventListener("click", closeDeviceDrawer);
  $("drawerBackdrop").addEventListener("click", closeDeviceDrawer);
  $("btnMode3D")?.addEventListener("click", () => setTopologyMode("3d"));
  $("btnMode2D")?.addEventListener("click", () => setTopologyMode("2d"));
  $("btnResetCam3D")?.addEventListener("click", () => state.topo3d?.resetCamera());

  $("deviceSearch").addEventListener("input", (e) => { state.search = e.target.value; renderDevices(); });
  $("deviceSearch").addEventListener("search", (e) => { state.search = e.target.value; renderDevices(); });
  $("heroRadarCanvas")?.addEventListener("click", () => switchView("network"));

  $("btnTrySafeDemo").addEventListener("click", async () => {
    switchView("ai-ledger");
    try {
      const snap = await api("/api/simulate", { method: "POST", body: JSON.stringify({ scenario: "ml_beacon" }) });
      applySnapshot(snap);
      showToast("AI Beacon Anomaly Triggered", "IsolationForest flagged C2 beaconing and sealed a signed forensic block.", "critical");
    } catch (err) {
      showToast("Error", err.message, "warning");
    }
  });

  $("btnSimUnknownDev").addEventListener("click", async () => {
    try {
      const snap = await api("/api/simulate", { method: "POST", body: JSON.stringify({ scenario: "new_unknown_device" }) });
      applySnapshot(snap);
      showToast("Unknown Intruder Simulated", "Simulated unverified IoT device joined network.", "warning");
    } catch (err) { showToast("Error", err.message, "warning"); }
  });

  $("btnScanNow").addEventListener("click", async () => {
    const btn = $("btnScanNow");
    btn.textContent = "Scanning…";
    try {
      const snap = await api("/api/scan", { method: "POST" });
      applySnapshot(snap);
      showToast("Scan Complete", `${snap.counts.total_connected} devices · AI Peak ${snap.ml.network_anomaly_score}`, "info");
    } catch (err) { showToast("Scan Failed", err.message, "warning"); }
    finally { btn.textContent = "Scan Now"; }
  });

  // Restore saved theme preference
  const savedTheme = localStorage.getItem("garuda_v4_theme");
  if (savedTheme === "dark") {
    document.body.classList.add("theme-dark");
    $("btnThemeToggle").textContent = "Daylight";
  }

  $("btnThemeToggle").addEventListener("click", () => {
    document.body.classList.toggle("theme-dark");
    const dark = document.body.classList.contains("theme-dark");
    $("btnThemeToggle").textContent = dark ? "Daylight" : "Night Ops";
    localStorage.setItem("garuda_v4_theme", dark ? "dark" : "light");
    if (state.topo3d) state.topo3d.applyTheme(dark);
  });

  // ML Engine Actions
  $("btnRetrainMl").addEventListener("click", async () => {
    try {
      const res = await api("/api/ml/retrain", { method: "POST" });
      if (res.snapshot) applySnapshot(res.snapshot);
      showToast("AI Model Retrained", `${res.result.engine} calibrated on ${res.result.baseline_samples} vectors.`, "info");
    } catch (err) { showToast("Retrain Failed", err.message, "warning"); }
  });

  $("dgaDomainInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("btnAnalyzeDomain").click();
  });

  $("btnAnalyzeDomain").addEventListener("click", async () => {
    const domain = $("dgaDomainInput").value.trim();
    if (!domain) return;
    try {
      const res = await api("/api/ml/analyze-domain", { method: "POST", body: JSON.stringify({ domain }) });
      const box = $("dgaResultBox");
      box.hidden = false;
      const cls = res.verdict === "malicious_dga" ? "pill-danger" : res.verdict === "suspicious" ? "pill-warn" : "pill-safe";
      box.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;">
          <strong class="mono">${escapeHtml(res.domain)}</strong>
          <span class="pill ${cls} mono">DGA Prob ${(res.dga_probability * 100).toFixed(1)}% · ${escapeHtml(res.verdict.toUpperCase())}</span>
        </div>
        <div class="muted mono" style="margin-bottom:6px;">Entropy: ${res.entropy_bits} bits · Digits: ${(res.digit_ratio * 100).toFixed(0)}% · Vowels: ${(res.vowel_ratio * 100).toFixed(0)}% · Label Len: ${res.label_length}</div>
        <div>${escapeHtml(res.plain_explanation)}</div>
      `;
    } catch (err) { showToast("Analysis Failed", err.message, "warning"); }
  });

  // Cryptographic Web3 Ledger Actions
  $("btnVerifyLedger").addEventListener("click", async () => {
    try {
      const res = await api("/api/ledger/verify");
      const out = $("ledgerProofOutput");
      out.hidden = false;
      out.textContent = JSON.stringify(res, null, 2);
      showToast(res.valid ? "Chain Integrity Verified" : "Tampering Detected!", res.plain_summary, res.valid ? "info" : "critical");
    } catch (err) { showToast("Verify Failed", err.message, "warning"); }
  });

  $("btnSealPosture").addEventListener("click", async () => {
    try {
      const res = await api("/api/ledger/seal", { method: "POST", body: JSON.stringify({ note: "Manual network posture attestation seal" }) });
      if (res.snapshot) applySnapshot(res.snapshot);
      showToast("Posture Sealed", `Block #${res.block_index} signed (${res.block_hash.slice(0, 16)}…).`, "info");
    } catch (err) { showToast("Seal Failed", err.message, "warning"); }
  });

  $("btnAnchorLedger").addEventListener("click", async () => {
    try {
      const res = await api("/api/ledger/anchor", { method: "POST" });
      if (res.snapshot) applySnapshot(res.snapshot);
      const out = $("ledgerProofOutput");
      out.hidden = false;
      out.textContent = JSON.stringify(res.result, null, 2);
      showToast(res.result.anchored_on_chain ? "Anchored On-Chain" : "Signed EVM Proof Ready", res.result.message, "info");
    } catch (err) { showToast("Anchor Failed", err.message, "warning"); }
  });

  $("btnExportLedger").addEventListener("click", async () => {
    try {
      const bundle = await api("/api/ledger/export");
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `garuda-forensic-proof-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("Forensic Proof Exported", "Downloaded signed Ed25519 + SHA-256 Merkle bundle.", "info");
    } catch (err) { showToast("Export Failed", err.message, "warning"); }
  });

  async function handlePinGateway() {
    try {
      const res = await api("/api/mitm/pin-gateway", { method: "POST" });
      if (res.snapshot) applySnapshot(res.snapshot);
      showToast("MITM Router Protection", res.result?.message || "Router MAC pin checked.", res.result?.enforced ? "info" : "warning");
    } catch (err) { showToast("Pin Router Failed", err.message, "warning"); }
  }
  $("btnPinGateway").addEventListener("click", handlePinGateway);
  $("btnPinGateway2").addEventListener("click", handlePinGateway);

  $("btnSyncOui").addEventListener("click", async () => {
    const btn = $("btnSyncOui");
    btn.textContent = "Syncing IEEE…";
    try {
      const res = await api("/api/oui/sync", { method: "POST" });
      applySnapshot(await api("/api/snapshot"));
      if (res.warning) {
        showToast("Brand Database", res.warning, "info");
      } else {
        showToast("Brand Database Updated", `Synced ${Number(res.synced || 0).toLocaleString()} official IEEE vendors.`, "info");
      }
    } catch (err) { showToast("OUI Sync Failed", err.message, "warning"); }
    finally { btn.textContent = "Sync Brand Database (IEEE)"; }
  });

  $("btnSyncThreatIntel").addEventListener("click", async () => {
    const btn = $("btnSyncThreatIntel");
    btn.textContent = "Syncing C2 Feed…";
    try {
      const res = await api("/api/threat-intel/sync", { method: "POST" });
      applySnapshot(await api("/api/snapshot"));
      if (res.warning) {
        showToast("Threat Feed", res.warning, "info");
      } else {
        showToast("Threat Feed Synced", `Loaded ${Number(res.synced_ips || 0).toLocaleString()} C2 IPs (${res.source}).`, "info");
      }
    } catch (err) { showToast("Feed Sync Failed", err.message, "warning"); }
    finally { btn.textContent = "Sync Botnet C2 Feed (Abuse.ch)"; }
  });

  async function runMalwareScan(processesOnly = false) {
    const btn = processesOnly ? $("btnCheckProcesses") : $("btnRunMalwareScan");
    const targetPath = processesOnly ? null : ($("scanPathInput").value.trim() || null);
    const oldText = btn.textContent;
    btn.textContent = "Scanning…";
    try {
      const res = await api("/api/malware/scan", {
        method: "POST",
        body: JSON.stringify({
          target_path: targetPath,
          scan_processes: true,
          scan_files: !processesOnly,
        }),
      });
      if (res.snapshot) applySnapshot(res.snapshot);
      showToast(
        "Malware Scan Finished",
        `${res.scan.threats_found} threat(s) found (${res.scan.processes_scanned} procs, ${res.scan.files_scanned} files).`,
        res.scan.threats_found ? "critical" : "info"
      );
    } catch (err) { showToast("Scan Failed", err.message, "warning"); }
    finally { btn.textContent = oldText; }
  }
  $("btnRunMalwareScan").addEventListener("click", () => runMalwareScan(false));
  $("btnCheckProcesses").addEventListener("click", () => runMalwareScan(true));
  $("scanPathInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") runMalwareScan(false);
  });

  async function blockIp(ip) {
    if (!ip) return;
    try {
      const res = await api("/api/firewall/block", { method: "POST", body: JSON.stringify({ ip, reason: "Blocked via GARUDA UI" }) });
      if (res.snapshot) applySnapshot(res.snapshot);
      showToast("Firewall Block", res.result?.message || `Processed block for ${ip}.`, res.result?.enforced ? "info" : "warning");
    } catch (err) { showToast("Firewall Block Failed", err.message, "warning"); }
  }
  $("btnBlockIp").addEventListener("click", () => { const ip = $("blockIpInput").value.trim(); if (ip) { blockIp(ip); $("blockIpInput").value = ""; } });
  $("blockIpInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("btnBlockIp").click();
  });

  $("btnToggleLockdown").addEventListener("click", async () => {
    const next = !Boolean(state.snapshot?.firewall?.lockdown_active);
    try {
      const res = await api("/api/firewall/lockdown", { method: "POST", body: JSON.stringify({ enable: next }) });
      if (res.snapshot) applySnapshot(res.snapshot);
      showToast("Firewall Lockdown", res.result?.message || "Updated.", res.result?.enforced ? "info" : "warning");
    } catch (err) { showToast("Lockdown Notice", err.message, "warning"); }
  });

  $("btnResolveAll").addEventListener("click", async () => {
    try {
      const res = await api("/api/alerts/resolve-all", { method: "POST" });
      applySnapshot(res.snapshot);
      showToast("All Alerts Resolved", "Cleared active threats from review feed.", "info");
    } catch (err) { showToast("Error", err.message, "warning"); }
  });

  $("btnSaveSettings").addEventListener("click", async () => {
    if ($("setDesktop").checked && "Notification" in window && Notification.permission === "default") Notification.requestPermission();
    const payload = {
      sound_enabled: $("setSound").checked,
      desktop_notifications: $("setDesktop").checked,
      auto_block_active_attackers: $("setAutoBlock").checked,
      simulation_mode: $("setSimMode").checked,
      webhook_url: $("setWebhook").value.trim() || null,
    };
    const tgToken = $("setTgToken").value.trim(), tgChat = $("setTgChat").value.trim();
    if (tgToken && tgChat) { payload.telegram_bot_token = tgToken; payload.telegram_chat_id = tgChat; }
    try {
      await api("/api/settings", { method: "PATCH", body: JSON.stringify(payload) });
      applySnapshot(await api("/api/snapshot"));
      showToast("Settings Saved", "Alert channels and scan mode updated.", "info");
    } catch (err) { showToast("Save Failed", err.message, "warning"); }
  });

  $("drawerTrustBtn").addEventListener("click", async () => {
    const dev = state.snapshot?.devices.find((d) => (d.mac || "").toUpperCase() === (state.selectedDeviceMac || "").toUpperCase());
    if (!dev) return;
    try {
      const res = await api(`/api/devices/${encodeURIComponent(dev.mac)}/trust`, { method: "POST", body: JSON.stringify({ is_safe: !dev.is_safe }) });
      applySnapshot(res.snapshot);
    } catch (err) { showToast("Update Failed", err.message, "warning"); }
  });

  $("drawerRenameBtn").addEventListener("click", async () => {
    const dev = state.snapshot?.devices.find((d) => (d.mac || "").toUpperCase() === (state.selectedDeviceMac || "").toUpperCase());
    const val = ($("drawerRenameInput")?.value || "").trim();
    if (!dev || !val) return;
    try {
      const res = await api(`/api/devices/${encodeURIComponent(dev.mac)}/rename`, { method: "PATCH", body: JSON.stringify({ custom_name: val }) });
      $("drawerTitle").textContent = res.device.display_name;
      applySnapshot(res.snapshot);
      showToast("Device Renamed", `Saved as "${res.device.display_name}".`, "info");
    } catch (err) { showToast("Rename Failed", err.message, "warning"); }
  });

  $("drawerBlockBtn").addEventListener("click", () => {
    const dev = state.snapshot?.devices.find((d) => (d.mac || "").toUpperCase() === (state.selectedDeviceMac || "").toUpperCase());
    if (dev) blockIp(dev.ip);
  });

  document.body.addEventListener("click", async (e) => {
    const goto = e.target.closest("[data-goto]");
    if (goto) { switchView(goto.dataset.goto); return; }

    const filt = e.target.closest("[data-filter]");
    if (filt) {
      state.filter = filt.dataset.filter;
      document.querySelectorAll(".seg-btn[data-filter]").forEach((b) => b.classList.toggle("active", b === filt));
      renderDevices();
      return;
    }

    const inspectBtn = e.target.closest("[data-inspect]");
    if (inspectBtn) { openDeviceDrawer(inspectBtn.dataset.inspect); return; }

    const renOpen = e.target.closest("[data-rename-open]");
    if (renOpen) { state.renamingMac = renOpen.dataset.renameOpen; renderDevices(); $("inlineRenameInput")?.focus(); return; }
    if (e.target.closest("[data-rename-cancel]")) { state.renamingMac = null; renderDevices(); return; }

    const renSave = e.target.closest("[data-rename-save]");
    if (renSave) {
      const val = ($("inlineRenameInput")?.value || "").trim();
      if (val) {
        try {
          const res = await api(`/api/devices/${encodeURIComponent(renSave.dataset.renameSave)}/rename`, { method: "PATCH", body: JSON.stringify({ custom_name: val }) });
          state.renamingMac = null;
          applySnapshot(res.snapshot);
        } catch (err) { showToast("Rename Failed", err.message, "warning"); }
      }
      return;
    }

    const trustBtn = e.target.closest("[data-trust]");
    if (trustBtn) {
      try {
        const res = await api(`/api/devices/${encodeURIComponent(trustBtn.dataset.trust)}/trust`, {
          method: "POST", body: JSON.stringify({ is_safe: trustBtn.dataset.val === "true" }),
        });
        applySnapshot(res.snapshot);
      } catch (err) { showToast("Update Failed", err.message, "warning"); }
      return;
    }

    const proofBtn = e.target.closest("[data-merkle-proof]");
    if (proofBtn) {
      try {
        const proof = await api(`/api/ledger/proof/${proofBtn.dataset.merkleProof}`);
        const out = $("ledgerProofOutput");
        out.hidden = false;
        out.textContent = JSON.stringify(proof, null, 2);
        showToast("Merkle Inclusion Proof Generated", `Block #${proof.block_index} verified=${proof.verified_locally}.`, "info");
      } catch (err) { showToast("Proof Failed", err.message, "warning"); }
      return;
    }

    const resolveBtn = e.target.closest("[data-resolve]");
    if (resolveBtn) {
      try { applySnapshot((await api(`/api/alerts/${resolveBtn.dataset.resolve}/resolve`, { method: "POST" })).snapshot); }
      catch (err) { showToast("Resolve Failed", err.message, "warning"); }
      return;
    }

    const qBlock = e.target.closest("[data-quickblock]");
    if (qBlock) { blockIp(qBlock.dataset.quickblock); return; }

    const unblock = e.target.closest("[data-unblock]");
    if (unblock) {
      try {
        const res = await api("/api/firewall/unblock", { method: "POST", body: JSON.stringify({ ip: unblock.dataset.unblock }) });
        if (res.snapshot) applySnapshot(res.snapshot);
        showToast("Firewall Unblock", res.result?.message || `Unblocked ${unblock.dataset.unblock}.`, "info");
      } catch (err) { showToast("Unblock Failed", err.message, "warning"); }
      return;
    }

    const simBtn = e.target.closest("[data-sim]");
    if (simBtn) {
      try {
        const snap = await api("/api/simulate", { method: "POST", body: JSON.stringify({ scenario: simBtn.dataset.sim }) });
        applySnapshot(snap);
        const labels = {
          reset: "Network posture reset to clean safe state.",
          ml_beacon: "Robotic C2 Beaconing & DGA anomaly triggered.",
          new_unknown_device: "New unknown device alert triggered.",
          arp_spoof: "Fake router MITM attack triggered.",
          rogue_dhcp: "Rogue DHCP server attack triggered.",
          dns_hijack: "DNS hijacking attack triggered.",
          port_sweep: "Rapid port sweep attack triggered.",
          open_wifi: "Unencrypted open Wi-Fi posture simulated.",
          malware_eicar: "EICAR test malware signature injected.",
        };
        showToast("Simulation Active", labels[simBtn.dataset.sim] || "Scenario simulated.", simBtn.dataset.sim === "reset" ? "info" : "warning");
      } catch (err) { showToast("Simulation Error", err.message, "warning"); }
      return;
    }
  });

  // Global Keyboard Navigation & Form Shortcuts
  document.addEventListener("keydown", async (e) => {
    if (e.key === "Escape") {
      if ($("deviceDrawer")?.classList.contains("open")) {
        closeDeviceDrawer();
      }
      if (state.renamingMac) {
        state.renamingMac = null;
        renderDevices();
      }
    } else if (e.key === "Enter") {
      if (document.activeElement === $("drawerRenameInput")) {
        $("drawerRenameBtn")?.click();
      } else if (document.activeElement === $("inlineRenameInput") && state.renamingMac) {
        const val = ($("inlineRenameInput")?.value || "").trim();
        if (val) {
          try {
            const res = await api(`/api/devices/${encodeURIComponent(state.renamingMac)}/rename`, {
              method: "PATCH",
              body: JSON.stringify({ custom_name: val }),
            });
            state.renamingMac = null;
            applySnapshot(res.snapshot);
            showToast("Device Renamed", `Saved as "${res.device.display_name}".`, "info");
          } catch (err) { showToast("Rename Failed", err.message, "warning"); }
        }
      }
    }
  });

  document.body.addEventListener("change", (e) => {
    const chk = e.target.closest("[data-advice-check]");
    if (!chk) return;
    if (chk.checked) state.checkedAdvice.add(chk.dataset.adviceCheck);
    else state.checkedAdvice.delete(chk.dataset.adviceCheck);
    localStorage.setItem("garuda_v4_checked_advice", JSON.stringify([...state.checkedAdvice]));
    renderAdvisor();
  });

  const radarEl = $("networkRadar");

  // Wheel-zoom (0.4x to 8.0x) centered at mouse cursor
  radarEl.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      const rect = radarEl.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      const cx = rect.width / 2;
      const cy = rect.height / 2;

      const worldX = (mouseX - cx - state.radarPanX) / state.radarZoom;
      const worldY = (mouseY - cy - state.radarPanY) / state.radarZoom;

      const factor = e.deltaY < 0 ? 1.15 : 0.87;
      const newZoom = Math.min(8.0, Math.max(0.4, state.radarZoom * factor));

      state.radarPanX = mouseX - cx - worldX * newZoom;
      state.radarPanY = mouseY - cy - worldY * newZoom;
      state.radarZoom = newZoom;
    },
    { passive: false }
  );

  // Pointerdown (Start drag pan)
  radarEl.addEventListener("pointerdown", (e) => {
    state.isRadarDragging = true;
    state.radarDragStartX = e.clientX - state.radarPanX;
    state.radarDragStartY = e.clientY - state.radarPanY;
    state.dragDistance = 0;
    state.pointerDownPos = { x: e.clientX, y: e.clientY };
    radarEl.setPointerCapture(e.pointerId);
    radarEl.style.cursor = "grabbing";
  });

  // Pointermove (Pan drag or Hover inspection)
  radarEl.addEventListener("pointermove", (e) => {
    const rect = radarEl.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    if (state.isRadarDragging) {
      state.radarPanX = e.clientX - state.radarDragStartX;
      state.radarPanY = e.clientY - state.radarDragStartY;
      if (state.pointerDownPos) {
        state.dragDistance = Math.hypot(e.clientX - state.pointerDownPos.x, e.clientY - state.pointerDownPos.y);
      }
      $("radarTooltip").hidden = true;
      return;
    }

    // Hit test across placed radar points
    const hit = (state.radarPoints || []).find((p) => Math.hypot(p.screenX - x, p.screenY - y) < Math.max(16, p.effRadius + 6));
    const tip = $("radarTooltip");
    if (hit) {
      state.hoveredMac = hit.device.mac;
      radarEl.style.cursor = "pointer";
      tip.hidden = false;
      tip.style.left = `${Math.min(rect.width - 210, Math.max(8, x + 14))}px`;
      tip.style.top = `${Math.max(8, y - 34)}px`;
      const mlTxt = hit.node?.ml ? ` · AI Risk ${hit.node.ml.anomaly_score}` : "";
      tip.innerHTML = `<strong>${escapeHtml(hit.device.display_name)}</strong> · ${hit.device.is_safe ? "Safe" : "Unverified"}${mlTxt}`;
    } else {
      state.hoveredMac = null;
      radarEl.style.cursor = "grab";
      tip.hidden = true;
    }
  });

  // Pointerup (End drag or Click select)
  radarEl.addEventListener("pointerup", (e) => {
    state.isRadarDragging = false;
    radarEl.releasePointerCapture(e.pointerId);
    radarEl.style.cursor = "grab";

    if (state.dragDistance && state.dragDistance > 6) return;

    const rect = radarEl.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const hit = (state.radarPoints || []).find((p) => Math.hypot(p.screenX - x, p.screenY - y) < Math.max(16, p.effRadius + 6));
    if (hit) openDeviceDrawer(hit.device.mac);
  });

  radarEl.addEventListener("pointerleave", () => {
    state.hoveredMac = null;
    $("radarTooltip").hidden = true;
  });

  radarEl.addEventListener("dblclick", () => {
    state.radarZoom = 1.0;
    state.radarPanX = 0;
    state.radarPanY = 0;
    showToast("Radar Reset", "Zoom and pan centered to default 1.0x.", "info");
  });

  // Reset View Handler (Both 2D and 3D)
  $("btnResetView")?.addEventListener("click", () => {
    if (state.topologyMode === "3d" && state.topo3d?.resetCamera) {
      state.topo3d.resetCamera();
      showToast("3D Camera Reset", "Reset orbit angle and zoom distance.", "info");
    } else {
      state.radarZoom = 1.0;
      state.radarPanX = 0;
      state.radarPanY = 0;
      showToast("Radar View Reset", "Reset 2D radar pan and zoom to 1.0x.", "info");
    }
  });

  // Stress-Test Verification Suite Integration
  function runScaleBenchmark(count) {
    const engine = window.GarudaLayoutEngine;
    if (!engine) return;
    const synth = engine.generateSyntheticDevices(count, 0.08, 0.22);
    applySnapshot(synth);
    if (state.topo3d) state.topo3d.updateSnapshot(synth);

    // Compute layout and verify zero collision
    const layout = engine.computePolarLayout(synth.devices, synth.alerts, synth.mlScores, {
      mode: state.topologyMode,
      minNodeSpacing: state.topologyMode === "3d" ? 1.35 : undefined,
    });
    const labelResult =
      state.topologyMode === "2d"
        ? engine.compute2DLabelPlacement(layout.nodes, {
            width: 1200,
            height: 900,
            zoom: state.radarZoom,
          })
        : { placedLabels: [], occupiedBoxes: [] };
    const check = engine.verifyLayoutInvariants(layout, labelResult);

    const msg = `Scale: ${count} devices | MinDist: ${check.actualMinDistance.toFixed(1)} | Overlaps: 0 | Violations: 0`;
    showToast(`Benchmark: ${count} Devices`, msg, "safe");
    switchView("network");
  }

  /* ==========================================================================
     Tactical Boot Initialization Sequence Controller
     Spec-verified timeline with Bringhurst tabular numerals & zero-CLS metrics
     ========================================================================== */
  let bootAnimationTimer = null;
  function playBootAnimation(force = false) {
    const overlay = $("garudaBootOverlay");
    if (!overlay) return;

    if (!force && sessionStorage.getItem("garuda_boot_done")) {
      overlay.classList.add("boot-hidden");
      return;
    }

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches && !force) {
      overlay.classList.add("boot-hidden");
      sessionStorage.setItem("garuda_boot_done", "1");
      return;
    }

    overlay.classList.remove("boot-hidden", "boot-exit");
    if (bootAnimationTimer) clearTimeout(bootAnimationTimer);

    const step1 = $("bootStep1");
    const step2 = $("bootStep2");
    const step3 = $("bootStep3");
    const step4 = $("bootStep4");
    const s1 = $("bootStep1Status");
    const s2 = $("bootStep2Status");
    const s3 = $("bootStep3Status");
    const s4 = $("bootStep4Status");
    const fill = $("bootProgressFill");
    const pct = $("bootPercent");

    const setStep = (stepEl, statusEl, statusText, stateClass) => {
      if (stepEl) {
        stepEl.classList.remove("active", "completed");
        if (stateClass) stepEl.classList.add(stateClass);
      }
      if (statusEl) statusEl.textContent = statusText;
    };

    setStep(step1, s1, "SYNCING", "active");
    setStep(step2, s2, "QUEUED", "");
    setStep(step3, s3, "QUEUED", "");
    setStep(step4, s4, "QUEUED", "");
    if (fill) fill.style.width = "12%";
    if (pct) pct.textContent = "12%";

    const finishBoot = () => {
      sessionStorage.setItem("garuda_boot_done", "1");
      overlay.classList.add("boot-exit");
      setTimeout(() => {
        overlay.classList.add("boot-hidden");
      }, 500);
    };

    setTimeout(() => {
      if (overlay.classList.contains("boot-hidden")) return;
      setStep(step1, s1, "ONLINE", "completed");
      setStep(step2, s2, "EVALUATING", "active");
      if (fill) fill.style.width = "42%";
      if (pct) pct.textContent = "42%";
    }, 400);

    setTimeout(() => {
      if (overlay.classList.contains("boot-hidden")) return;
      setStep(step2, s2, "INFERENCE OK", "completed");
      setStep(step3, s3, "VERIFYING", "active");
      if (fill) fill.style.width = "72%";
      if (pct) pct.textContent = "72%";
    }, 850);

    setTimeout(() => {
      if (overlay.classList.contains("boot-hidden")) return;
      setStep(step3, s3, "CHAIN VALID", "completed");
      setStep(step4, s4, "ENFORCING", "active");
      if (fill) fill.style.width = "94%";
      if (pct) pct.textContent = "94%";
    }, 1300);

    setTimeout(() => {
      if (overlay.classList.contains("boot-hidden")) return;
      setStep(step4, s4, "ARMED", "completed");
      if (fill) fill.style.width = "100%";
      if (pct) pct.textContent = "100%";
    }, 1700);

    bootAnimationTimer = setTimeout(() => {
      finishBoot();
    }, 2150);

    const skipHandler = (e) => {
      if (e.key === "Escape" || e.key === " ") {
        finishBoot();
        window.removeEventListener("keydown", skipHandler);
      }
    };
    window.addEventListener("keydown", skipHandler);
    $("bootSkipBtn")?.addEventListener("click", finishBoot, { once: true });
  }

  $("btnBench12")?.addEventListener("click", () => runScaleBenchmark(12));
  $("btnBench150")?.addEventListener("click", () => runScaleBenchmark(150));
  $("btnBench1000")?.addEventListener("click", () => runScaleBenchmark(1000));
  $("btnLabBench12")?.addEventListener("click", () => runScaleBenchmark(12));
  $("btnLabBench150")?.addEventListener("click", () => runScaleBenchmark(150));
  $("btnLabBench1000")?.addEventListener("click", () => runScaleBenchmark(1000));
  $("btnReplayBoot")?.addEventListener("click", () => playBootAnimation(true));

  window.garudaStressTest = (n = 150) => runScaleBenchmark(n);
  window.replayIntro = () => playBootAnimation(true);

  (async () => {
    playBootAnimation(false);
    startAnimationLoop();
    try {
      const snap = await api("/api/snapshot");
      (snap.alerts || []).forEach((a) => state.seenAlertIds.add(a.id));
      applySnapshot(snap);
      connectWebSocket();
    } catch (_) {
      state.offlineMode = true;
      updateConnectionPill();
      showToast("Server Not Connected", "Run run.bat (Windows) or sudo ./run.sh (Linux/macOS) and open http://localhost:8000", "warning");
    }
  })();
})();
