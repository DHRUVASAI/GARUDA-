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
    soundEnabled: true,
    desktopNotifications: true,
    seenAlertIds: new Set(),
    checkedAdvice: new Set(JSON.parse(localStorage.getItem("garuda_v4_checked_advice") || "[]")),
    animPhase: 0,
    radarZoom: 1.0,
    radarPanX: 0,
    radarPanY: 0,
    radarDragging: false,
    radarDragStart: { x: 0, y: 0 },
  };
  window.GarudaState = state;

  const DEVICE_SVGS = {
    router: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 13V8"/><path d="M18 13V8"/><line x1="10" y1="17" x2="10" y2="17.01"/><line x1="14" y1="17" x2="14" y2="17.01"/></svg>',
    laptop: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M2 20h20"/></svg>',
    phone: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="2" width="12" height="20" rx="2"/><line x1="11" y1="18" x2="13" y2="18"/></svg>',
    tablet: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>',
    tv: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="13" rx="2"/><polyline points="17 2 12 7 7 2"/></svg>',
    printer: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>',
    iot: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="7"/><path d="M12 2v3"/><path d="M12 19v3"/><path d="M2 12h3"/><path d="M19 12h3"/></svg>',
    unknown: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  };

  const $ = (id) => document.getElementById(id);

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  window.escapeHtml = escapeHtml;

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
      new Notification(`GARUDA v4 Alert: ${alert.title}`, { body: alert.plain_explanation });
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
    $("btnResetCam3D").hidden = false;
    if ($("radarZoomHud")) $("radarZoomHud").hidden = is3d;
    $("topologyHudBadge").textContent = is3d
      ? "Drag to orbit · Scroll to zoom · Click 3D device to inspect"
      : "2D Precision Radar · Hover or click any device to inspect";
    if (is3d && state.view === "network") ensureTopology3D();
  }

  function switchView(viewName) {
    state.view = viewName;
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    const target = $(`view-${viewName}`);
    if (target) target.classList.add("active");
    document.querySelectorAll(".nav-btn").forEach((b) => {
      const isActive = b.dataset.view === viewName;
      b.classList.toggle("active", isActive);
      if (isActive && typeof b.scrollIntoView === "function") {
        b.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
      }
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
    if (!pill) return;
    if (state.offlineMode) {
      pill.className = "pill pill-warn";
      pill.innerHTML = `<span class="dot"></span> Offline Preview`;
      return;
    }
    if (!state.snapshot) return;
    const isCloudHost = Boolean(
      location.hostname.includes("onrender.com") ||
      location.hostname.includes("render") ||
      (state.snapshot.capabilities?.os_name && state.snapshot.capabilities.os_name.includes("aws"))
    );
    if (state.snapshot.mode === "simulation") {
      pill.className = "pill pill-warn";
      pill.innerHTML = `<span class="dot"></span> Safe Simulation Mode`;
    } else if (isCloudHost) {
      pill.className = "pill pill-safe";
      pill.style.cursor = "pointer";
      pill.title = "Cloud Sentinel Hub (Monitoring baseline). Tap to learn how live scanning works.";
      pill.innerHTML = `<span class="dot"></span> Cloud Sentinel`;
    } else {
      pill.className = "pill pill-safe";
      pill.style.cursor = "pointer";
      pill.title = "Live Physical Hardware Scanner active on your local Wi-Fi.";
      pill.innerHTML = `<span class="dot"></span> Live Local Scanner`;
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

    // Live Hardware Telemetry Ribbon (Zero Simulation Proof)
    if (snap.network) {
      if ($("ribbonSsid")) $("ribbonSsid").textContent = snap.network.ssid || "Live Wi-Fi";
      if ($("ribbonGateway")) $("ribbonGateway").textContent = `${snap.network.gateway_ip || "192.168.1.1"} (${snap.network.gateway_mac ? "Zyxel Router" : "Gateway"})`;
      if ($("ribbonHost")) $("ribbonHost").textContent = `${snap.network.local_ip || "192.168.1.13"} (omen · This PC)`;
    }
    if (snap.devices && $("ribbonDevicesCount")) {
      const liveOnline = snap.devices.filter((d) => d.is_online).length;
      $("ribbonDevicesCount").textContent = `${liveOnline} Live Hardware Hosts`;
    }

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
        const icon = DEVICE_SVGS[d.device_type] || DEVICE_SVGS.laptop;
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

        const blockedList = state.snapshot?.firewall?.blocked_ips || [];
        const isBlocked = blockedList.includes(d.ip);
        const blockedBadge = isBlocked ? `<span class="pill pill-danger">FIREWALL BLOCKED</span>` : "";
        const savedUser = (typeof getSavedUser === "function") ? getSavedUser() : null;
        const isCurrentAdmin = savedUser && savedUser.role === "admin" && !!localStorage.getItem("garuda_v7_token");
        const blockBtn = isBlocked
          ? `<button class="btn btn-sm" data-unblock="${escapeHtml(d.ip)}">Unblock IP</button>`
          : (!d.is_gateway && !d.is_self
              ? (isCurrentAdmin
                  ? `<button class="btn btn-danger btn-sm" data-quickblock="${escapeHtml(d.ip)}">Block IP</button>`
                  : `<button class="btn btn-sm btn-ghost" data-viewer-block="${escapeHtml(d.ip)}" title="Viewer Mode: Admin required to enforce IP blocks" style="opacity:0.85;">Block IP</button>`
                )
              : "");

        return `
          <div class="device-row ${d.is_safe ? "" : "unverified"}">
            <div class="device-left">
              <div class="device-icon">${icon}</div>
              <div>
                <div class="device-name">
                  <span>${escapeHtml(d.display_name)}</span>
                  ${safeBadge} ${mlBadge} ${roleBadge} ${srcBadge} ${blockedBadge}
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
              ${blockBtn}
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
    const dev = state.snapshot?.devices.find((d) => d.mac === mac);
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

  // Multi-tier Device Classifier: router, alexa, streaming_stick, printer, tv, phone, computer, bulb, fan, ac, fridge, camera, iot
  function classifyDevice(d) {
    if (!d) return "iot";
    if (d.is_gateway || (d.display_name && /gateway|router|zyxel|tp-link|netgear|asus|linksys/i.test(d.display_name))) {
      return "router";
    }
    const text = `${d.display_name || ""} ${d.vendor || ""} ${d.hostname || ""} ${d.device_type || ""}`.toLowerCase();
    if (/printer|canon|g4070|epson|brother|laserjet|deskjet|pixma/i.test(text)) return "printer";
    if (/alexa|echo|dot|show|amazon speaker/i.test(text)) return "alexa";
    if (/firetv|fire tv|firestick|fire stick|roku|chromecast|apple tv|xstream|iptv/i.test(text)) return "streaming_stick";
    if (text.includes("amazon technologies")) {
      return (d.ip && d.ip.endsWith(".6")) ? "streaming_stick" : "alexa";
    }
    if (/tv|bravia|webos|tizen|smart tv|oled|qled|hisense|sony tv|lg tv/i.test(text)) return "tv";
    if (/bulb|light|lamp|hue|lifx|candle|strip|wiz/i.test(text)) return "bulb";
    if (/fan|ventilator|blower|atomberg|havells|orient/i.test(text)) return "fan";
    if (/ac\b|air conditioner|cooler|hvac|daikin|voltas|carrier|split ac|hitachi/i.test(text)) return "ac";
    if (/fridge|refrigerator|freezer|whirlpool/i.test(text)) return "fridge";
    if (/camera|cctv|cam|hikvision|dahua|blink|ring|ezviz|imou|webcam/i.test(text)) return "camera";
    if (/phone|mobile|android|iphone|galaxy|pixel|realme|redmi|xiaomi|oneplus|oppo|vivo|a73/i.test(text)) return "phone";
    if (/omen|laptop|notebook|desktop|pc|macbook|thinkpad|dell|workstation|this computer|fugui/i.test(text)) return "computer";
    return "iot";
  }

  // Crisp Vector 2D Icon Renderer for Every Device Category
  function drawDevice2DSymbol(ctx, type, x, y, s, color, dark, animPhase = 0) {
    ctx.save();
    ctx.strokeStyle = color;
    ctx.fillStyle = color;
    ctx.lineWidth = 1.35;
    ctx.lineCap = "round";
    ctx.lineJoin = "round";

    if (type === "router") {
      ctx.beginPath();
      ctx.rect(x - s * 0.75, y - s * 0.15, s * 1.5, s * 0.55);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(x - s * 0.45, y - s * 0.15);
      ctx.lineTo(x - s * 0.65, y - s * 0.85);
      ctx.moveTo(x + s * 0.45, y - s * 0.15);
      ctx.lineTo(x + s * 0.65, y - s * 0.85);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(x - s * 0.65, y - s * 0.85, 1.4, 0, Math.PI * 2);
      ctx.arc(x + s * 0.65, y - s * 0.85, 1.4, 0, Math.PI * 2);
      ctx.fill();
      ctx.beginPath();
      ctx.arc(x - s * 0.65, y - s * 0.85, s * 0.25, -Math.PI * 0.8, -Math.PI * 0.2);
      ctx.arc(x + s * 0.65, y - s * 0.85, s * 0.25, -Math.PI * 0.8, -Math.PI * 0.2);
      ctx.stroke();
      ctx.fillStyle = "#00e5ff";
      ctx.beginPath();
      ctx.arc(x - s * 0.35, y + s * 0.12, 1.3, 0, Math.PI * 2);
      ctx.arc(x, y + s * 0.12, 1.3, 0, Math.PI * 2);
      ctx.arc(x + s * 0.35, y + s * 0.12, 1.3, 0, Math.PI * 2);
      ctx.fill();
    } else if (type === "alexa") {
      ctx.beginPath();
      ctx.ellipse(x, y - s * 0.32, s * 0.52, s * 0.22, 0, 0, Math.PI * 2);
      ctx.lineTo(x + s * 0.52, y + s * 0.42);
      ctx.ellipse(x, y + s * 0.42, s * 0.52, s * 0.22, 0, 0, Math.PI);
      ctx.lineTo(x - s * 0.52, y - s * 0.32);
      ctx.stroke();
      ctx.beginPath();
      ctx.ellipse(x, y - s * 0.32, s * 0.46, s * 0.18, 0, 0, Math.PI * 2);
      ctx.strokeStyle = "#00e5ff";
      ctx.lineWidth = 2.0;
      ctx.stroke();
      ctx.fillStyle = "#00e5ff";
      ctx.beginPath();
      ctx.arc(x, y - s * 0.32, 1.5, 0, Math.PI * 2);
      ctx.fill();
    } else if (type === "streaming_stick") {
      ctx.beginPath();
      ctx.rect(x - s * 0.75, y - s * 0.42, s * 0.55, s * 0.95);
      ctx.stroke();
      ctx.fillStyle = "#d4af37";
      ctx.fillRect(x - s * 0.65, y - s * 0.68, s * 0.35, s * 0.26);
      ctx.strokeStyle = color;
      ctx.beginPath();
      ctx.rect(x + s * 0.05, y - s * 0.55, s * 0.58, s * 1.15);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(x + s * 0.34, y - s * 0.2, s * 0.16, 0, Math.PI * 2);
      ctx.stroke();
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(x + s * 0.34, y - s * 0.2, 1.2, 0, Math.PI * 2);
      ctx.fill();
    } else if (type === "printer") {
      ctx.beginPath();
      ctx.rect(x - s * 0.75, y - s * 0.2, s * 1.5, s * 0.75);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(x - s * 0.45, y - s * 0.2);
      ctx.lineTo(x - s * 0.35, y - s * 0.78);
      ctx.lineTo(x + s * 0.35, y - s * 0.78);
      ctx.lineTo(x + s * 0.45, y - s * 0.2);
      ctx.stroke();
      ctx.strokeRect(x - s * 0.45, y + s * 0.15, s * 0.9, s * 0.22);
      ctx.fillStyle = "#3eb488";
      ctx.beginPath();
      ctx.arc(x + s * 0.55, y - s * 0.05, 1.3, 0, Math.PI * 2);
      ctx.fill();
    } else if (type === "tv") {
      ctx.beginPath();
      ctx.rect(x - s * 0.85, y - s * 0.62, s * 1.7, s * 0.98);
      ctx.stroke();
      ctx.fillRect(x - s * 0.08, y + s * 0.36, s * 0.16, s * 0.2);
      ctx.fillRect(x - s * 0.42, y + s * 0.56, s * 0.84, s * 0.09);
      ctx.strokeRect(x - s * 0.75, y - s * 0.52, s * 1.5, s * 0.78);
    } else if (type === "phone") {
      ctx.beginPath();
      ctx.rect(x - s * 0.42, y - s * 0.78, s * 0.84, s * 1.56);
      ctx.stroke();
      ctx.fillRect(x - s * 0.15, y - s * 0.65, s * 0.3, s * 0.06);
      ctx.fillRect(x - s * 0.18, y + s * 0.62, s * 0.36, s * 0.06);
    } else if (type === "computer") {
      ctx.beginPath();
      ctx.rect(x - s * 0.7, y - s * 0.75, s * 1.4, s * 0.85);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(x - s * 0.9, y + s * 0.32);
      ctx.lineTo(x + s * 0.9, y + s * 0.32);
      ctx.lineTo(x + s * 0.7, y + s * 0.1);
      ctx.lineTo(x - s * 0.7, y + s * 0.1);
      ctx.closePath();
      ctx.stroke();
    } else if (type === "bulb") {
      ctx.beginPath();
      ctx.arc(x, y - s * 0.22, s * 0.48, 0.25 * Math.PI, 0.75 * Math.PI, true);
      ctx.stroke();
      ctx.strokeRect(x - s * 0.2, y + s * 0.28, s * 0.4, s * 0.28);
      ctx.beginPath();
      ctx.moveTo(x - s * 0.18, y + s * 0.38); ctx.lineTo(x + s * 0.18, y + s * 0.38);
      ctx.moveTo(x - s * 0.18, y + s * 0.46); ctx.lineTo(x + s * 0.18, y + s * 0.46);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(x, y - s * 0.8); ctx.lineTo(x, y - s * 0.95);
      ctx.moveTo(x - s * 0.6, y - s * 0.4); ctx.lineTo(x - s * 0.75, y - s * 0.5);
      ctx.moveTo(x + s * 0.6, y - s * 0.4); ctx.lineTo(x + s * 0.75, y - s * 0.5);
      ctx.stroke();
    } else if (type === "fan") {
      ctx.beginPath();
      ctx.arc(x, y, s * 0.22, 0, Math.PI * 2);
      ctx.fill();
      const rot = animPhase * 3.5;
      for (let i = 0; i < 3; i++) {
        const a = rot + (i * Math.PI * 2) / 3;
        ctx.beginPath();
        ctx.moveTo(x + Math.cos(a) * (s * 0.2), y + Math.sin(a) * (s * 0.2));
        ctx.quadraticCurveTo(
          x + Math.cos(a + 0.35) * (s * 0.65),
          y + Math.sin(a + 0.35) * (s * 0.65),
          x + Math.cos(a) * (s * 0.85),
          y + Math.sin(a) * (s * 0.85)
        );
        ctx.stroke();
      }
    } else if (type === "ac") {
      ctx.beginPath();
      ctx.rect(x - s * 0.88, y - s * 0.38, s * 1.76, s * 0.65);
      ctx.stroke();
      ctx.strokeRect(x - s * 0.78, y + s * 0.1, s * 1.56, s * 0.1);
      ctx.strokeStyle = "#56ccf2";
      ctx.beginPath();
      ctx.moveTo(x - s * 0.5, y + s * 0.35);
      ctx.quadraticCurveTo(x - s * 0.25, y + s * 0.55, x - s * 0.05, y + s * 0.35);
      ctx.moveTo(x + s * 0.05, y + s * 0.35);
      ctx.quadraticCurveTo(x + s * 0.3, y + s * 0.55, x + s * 0.5, y + s * 0.35);
      ctx.stroke();
      ctx.fillStyle = "#56ccf2";
      ctx.fillRect(x + s * 0.52, y - s * 0.22, s * 0.2, s * 0.1);
    } else if (type === "fridge") {
      ctx.beginPath();
      ctx.rect(x - s * 0.52, y - s * 0.85, s * 1.04, s * 1.7);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(x - s * 0.52, y - s * 0.25);
      ctx.lineTo(x + s * 0.52, y - s * 0.25);
      ctx.stroke();
      ctx.fillRect(x + s * 0.32, y - s * 0.68, s * 0.08, s * 0.3);
      ctx.fillRect(x + s * 0.32, y - s * 0.1, s * 0.08, s * 0.55);
    } else if (type === "camera") {
      ctx.beginPath();
      ctx.moveTo(x - s * 0.7, y - s * 0.4);
      ctx.lineTo(x - s * 0.3, y - s * 0.1);
      ctx.stroke();
      ctx.strokeRect(x - s * 0.3, y - s * 0.35, s * 0.85, s * 0.55);
      ctx.beginPath();
      ctx.arc(x + s * 0.55, y - s * 0.08, s * 0.22, 0, Math.PI * 2);
      ctx.stroke();
      ctx.fillStyle = "#e36050";
      ctx.beginPath();
      ctx.arc(x - s * 0.1, y - s * 0.2, 1.5, 0, Math.PI * 2);
      ctx.fill();
    } else {
      ctx.strokeRect(x - s * 0.48, y - s * 0.48, s * 0.96, s * 0.96);
      ctx.beginPath();
      ctx.moveTo(x - s * 0.72, y - s * 0.2); ctx.lineTo(x - s * 0.48, y - s * 0.2);
      ctx.moveTo(x - s * 0.72, y + s * 0.2); ctx.lineTo(x - s * 0.48, y + s * 0.2);
      ctx.moveTo(x + s * 0.48, y - s * 0.2); ctx.lineTo(x + s * 0.72, y - s * 0.2);
      ctx.moveTo(x + s * 0.48, y + s * 0.2); ctx.lineTo(x + s * 0.72, y + s * 0.2);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(x, y - s * 0.22); ctx.lineTo(x + s * 0.22, y); ctx.lineTo(x, y + s * 0.22); ctx.lineTo(x - s * 0.22, y);
      ctx.closePath();
      ctx.fill();
    }
    ctx.restore();
  }

  // 2D Precision Tactical Guardian Radar (Hero preview + 2D Topology Mode)
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
    const w = rect.width, h = rect.height, cx = w / 2, cy = h / 2, maxR = Math.min(w, h) * 0.41;
    const dark = document.body.classList.contains("theme-dark");
    const hasCrit = state.snapshot.alerts.some((a) => !a.resolved && a.severity === "critical");
    const mlMap = new Map((state.snapshot.ml?.device_scores || []).map((m) => [m.mac.toUpperCase(), m]));

    ctx.clearRect(0, 0, w, h);

    // Tactical Radar Scope Background Glow
    const bgRad = ctx.createRadialGradient(cx, cy, maxR * 0.2, cx, cy, maxR * 1.05);
    bgRad.addColorStop(0, dark ? "rgba(22,27,34,0.4)" : "rgba(240,244,250,0.5)");
    bgRad.addColorStop(1, dark ? "rgba(13,17,23,0.05)" : "rgba(230,235,245,0.05)");
    ctx.beginPath();
    ctx.arc(cx, cy, maxR * 1.05, 0, Math.PI * 2);
    ctx.fillStyle = bgRad;
    ctx.fill();

    // Concentric Range Rings with Range Markings
    const ringRanges = [
      { f: 0.33, label: "25m" },
      { f: 0.66, label: "50m" },
      { f: 1.0, label: "PERIMETER" }
    ];
    ringRanges.forEach((ring, idx) => {
      ctx.beginPath();
      ctx.arc(cx, cy, maxR * ring.f, 0, Math.PI * 2);
      ctx.strokeStyle = dark ? "rgba(236,234,228,0.12)" : "rgba(22,24,29,0.12)";
      ctx.setLineDash(idx === 2 ? [5, 4] : idx === 1 ? [2, 3] : []);
      ctx.lineWidth = 1;
      ctx.stroke();

      if (!compact) {
        ctx.fillStyle = dark ? "rgba(236,234,228,0.38)" : "rgba(22,24,29,0.38)";
        ctx.font = "600 9px Inter, sans-serif";
        ctx.textAlign = "left";
        ctx.fillText(ring.label, cx + 6, cy - maxR * ring.f + 11);
      }
    });
    ctx.setLineDash([]);

    // Crosshair Reticle & Degree Marks
    ctx.strokeStyle = dark ? "rgba(236,234,228,0.07)" : "rgba(22,24,29,0.07)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(cx - maxR * 1.05, cy); ctx.lineTo(cx + maxR * 1.05, cy);
    ctx.moveTo(cx, cy - maxR * 1.05); ctx.lineTo(cx, cy + maxR * 1.05);
    ctx.stroke();

    // Sweeping Radar Phosphor Beam
    const sweepAngle = (state.animPhase * 1.35) % (Math.PI * 2);
    const sweepArc = 0.55; // 31-degree sector
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, maxR * 1.03, sweepAngle - sweepArc, sweepAngle);
    ctx.closePath();
    const sweepGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR * 1.03);
    sweepGrad.addColorStop(0, hasCrit ? "rgba(227,96,80,0.24)" : "rgba(30,79,214,0.22)");
    sweepGrad.addColorStop(1, hasCrit ? "rgba(227,96,80,0.01)" : "rgba(30,79,214,0.01)");
    ctx.fillStyle = sweepGrad;
    ctx.fill();

    // Sharp Phosphor Sweep Line
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(sweepAngle) * maxR * 1.03, cy + Math.sin(sweepAngle) * maxR * 1.03);
    ctx.strokeStyle = hasCrit ? (dark ? "#E36050" : "#C53624") : (dark ? "#6394F2" : "#1E4FD6");
    ctx.lineWidth = 1.8;
    ctx.stroke();
    ctx.restore();

    // Expanding Ping Wave from Router
    const pulseR = ((state.animPhase * 0.32) % 1) * maxR;
    ctx.beginPath();
    ctx.arc(cx, cy, pulseR, 0, Math.PI * 2);
    ctx.strokeStyle = hasCrit ? `rgba(197,54,36,${0.32 * (1 - pulseR / maxR)})` : `rgba(30,79,214,${0.25 * (1 - pulseR / maxR)})`;
    ctx.lineWidth = 1.6;
    ctx.stroke();

    const devices = state.snapshot.devices.filter((d) => d.is_online);
    const gw = devices.find((d) => d.is_gateway) || devices[0];
    const others = devices.filter((d) => d !== gw);
    const points = [];

    if (!compact) {
      ctx.save();
      ctx.translate(cx + state.radarPanX, cy + state.radarPanY);
      ctx.scale(state.radarZoom, state.radarZoom);
      ctx.translate(-cx, -cy);
    }
    const layoutPts = (window.GarudaLayout && window.GarudaLayout.compute2DRingLayout)
      ? window.GarudaLayout.compute2DRingLayout(others, cx, cy, maxR)
      : others.map((d, idx) => {
          const angle = (idx / Math.max(1, others.length)) * Math.PI * 2 - Math.PI / 2;
          const track = idx % 3;
          const r = maxR * (0.50 + track * 0.22);
          return { device: d, x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r };
        });

    const zeroLabelsMap = (window.GarudaLayout && window.GarudaLayout.resolveZeroOverlapLabels)
      ? window.GarudaLayout.resolveZeroOverlapLabels(
          layoutPts.map((p) => ({
            ...p,
            hovered: state.hoveredMac === p.device.mac,
            isAlert: state.snapshot.alerts.some((a) => !a.resolved && a.related_mac === p.device.mac),
          })),
          cx,
          cy,
          compact
        )
      : null;

    layoutPts.forEach((pt, idx) => {
      const d = pt.device;
      const x = pt.x;
      const y = pt.y;
      const devCategory = classifyDevice(d);
      const ml = mlMap.get(d.mac.toUpperCase());
      const isAlert = state.snapshot.alerts.some((a) => !a.resolved && (a.related_mac === d.mac || a.related_ip === d.ip)) || (ml && ml.risk_level === "critical");
      const color = isAlert ? (dark ? "#E36050" : "#C53624") : d.is_safe ? (dark ? "#3EB488" : "#157F56") : (dark ? "#E2A343" : "#B96B08");

      // Signal Link Ray
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(x, y);
      ctx.strokeStyle = isAlert ? "rgba(197,54,36,0.48)" : d.is_safe ? "rgba(21,127,86,0.26)" : "rgba(185,107,8,0.38)";
      ctx.lineWidth = isAlert ? 2.0 : 1.2;
      ctx.stroke();

      // Traveling Packet Dot
      const t = (state.animPhase * 0.45 + idx * 0.23) % 1;
      ctx.beginPath();
      ctx.arc(cx + (x - cx) * t, cy + (y - cy) * t, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();

      // Phosphor Sweep Hit Echo Wave
      const nodeAngle = Math.atan2(y - cy, x - cx);
      const normNodeAngle = nodeAngle < 0 ? nodeAngle + Math.PI * 2 : nodeAngle;
      let angleDelta = Math.abs(sweepAngle - normNodeAngle);
      if (angleDelta > Math.PI) angleDelta = Math.PI * 2 - angleDelta;
      if (angleDelta < 0.26) {
        const pingGlow = 1 - (angleDelta / 0.26);
        ctx.beginPath();
        ctx.arc(x, y, (compact ? 18 : 22) + pingGlow * 10, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0, 229, 255, ${0.45 * pingGlow})`;
        ctx.lineWidth = 1.8;
        ctx.stroke();
      }

      // Device Tactical Node Badge
      const hovered = !compact && state.hoveredMac === d.mac;
      const nodeR = (compact ? 13 : 16) + (hovered ? 3 : 0);

      // Node background & rim
      ctx.beginPath();
      ctx.arc(x, y, nodeR, 0, Math.PI * 2);
      ctx.fillStyle = dark ? "#161b22" : "#ffffff";
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = hovered ? 2.5 : 1.6;
      ctx.stroke();

      // Render Dedicated 2D Vector Symbol
      drawDevice2DSymbol(ctx, devCategory, x, y, compact ? 8 : 10, color, dark, state.animPhase);

      // Zero-Overlap Anti-Glare Label Pill
      const lblInfo = zeroLabelsMap ? zeroLabelsMap.get(d.mac) : null;
      if (lblInfo && (lblInfo.show || hovered)) {
        const bw = lblInfo.boxW;
        const bh = lblInfo.boxH;
        const bx = lblInfo.boxX;
        const by = lblInfo.boxY;

        ctx.fillStyle = dark ? "rgba(13, 17, 23, 0.90)" : "rgba(255, 255, 255, 0.92)";
        ctx.strokeStyle = isAlert ? "rgba(239, 68, 68, 0.5)" : d.is_safe ? "rgba(16, 185, 129, 0.4)" : "rgba(245, 158, 11, 0.4)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        if (ctx.roundRect) {
          ctx.roundRect(bx, by, bw, bh, 4);
        } else {
          ctx.rect(bx, by, bw, bh);
        }
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = dark ? "#F0F6FC" : "#0F172A";
        ctx.font = compact ? "700 9.5px Inter, sans-serif" : "700 11px Inter, sans-serif";
        const tx = lblInfo.textAlign === "center" ? (bx + bw / 2) : lblInfo.textAlign === "left" ? (bx + 7) : (bx + bw - 7);
        const ty = by + bh / 2 + (compact ? 3.5 : 4);
        ctx.textAlign = lblInfo.textAlign;
        ctx.fillText(lblInfo.labelText, tx, ty);

        if (!compact && hovered) {
          ctx.fillStyle = dark ? "#8b949e" : "#57606a";
          ctx.font = "500 9.5px monospace";
          ctx.fillText(d.ip, tx, ty + 14);
        }
      }
      points.push({ x: compact ? x : cx + state.radarPanX + (x - cx) * state.radarZoom, y: compact ? y : cy + state.radarPanY + (y - cy) * state.radarZoom, device: d });
    });

    // Central Gateway Node Badge
    const gwRadius = compact ? 20 : 25;
    ctx.beginPath();
    ctx.arc(cx, cy, gwRadius, 0, Math.PI * 2);
    ctx.fillStyle = dark ? "#0d1117" : "#f0f4fa";
    ctx.fill();
    ctx.strokeStyle = hasCrit ? (dark ? "#E36050" : "#C53624") : (dark ? "#6394F2" : "#1E4FD6");
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // Dedicated 2D Router Symbol in center
    drawDevice2DSymbol(ctx, "router", cx, cy, compact ? 11 : 14, hasCrit ? "#E36050" : (dark ? "#6394F2" : "#1E4FD6"), dark, state.animPhase);

    // Gateway Label Badge
    ctx.fillStyle = dark ? "#6394F2" : "#1E4FD6";
    ctx.font = "700 9.5px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("GATEWAY", cx, cy + (compact ? 28 : 34));

    if (!compact) { ctx.restore(); state.radarPoints = points; }
  }

  function startAnimationLoop() {
    const tick = () => {
      state.animPhase += 0.012;
      if (state.view === "landing") drawRadar("heroRadarCanvas", true);
      if (state.view === "network" && state.topologyMode === "2d") drawRadar("networkRadar", window.innerWidth < 640);
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
  $("btnMode3D").addEventListener("click", () => setTopologyMode("3d"));
  $("btnMode2D").addEventListener("click", () => setTopologyMode("2d"));
  $("btnResetCam3D").addEventListener("click", () => state.topo3d?.resetCamera());

  $("deviceSearch").addEventListener("input", (e) => { state.search = e.target.value; renderDevices(); });

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

  $("btnThemeToggle").addEventListener("click", () => {
    document.body.classList.toggle("theme-dark");
    const dark = document.body.classList.contains("theme-dark");
    $("btnThemeToggle").textContent = dark ? "Daylight" : "Night Ops";
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
      a.download = `garuda-v4-forensic-proof-${Date.now()}.json`;
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
      showToast("Brand Database Updated", `Synced ${Number(res.synced || 0).toLocaleString()} official IEEE vendors.`, "info");
    } catch (err) { showToast("OUI Sync Failed", err.message, "warning"); }
    finally { btn.textContent = "Sync Brand Database (IEEE)"; }
  });

  $("btnSyncThreatIntel").addEventListener("click", async () => {
    const btn = $("btnSyncThreatIntel");
    btn.textContent = "Syncing C2 Feed…";
    try {
      const res = await api("/api/threat-intel/sync", { method: "POST" });
      applySnapshot(await api("/api/snapshot"));
      showToast("Threat Feed Synced", `Loaded ${Number(res.synced_ips || 0).toLocaleString()} C2 IPs.`, "info");
    } catch (err) { showToast("Feed Sync Failed", err.message, "warning"); }
    finally { btn.textContent = "Sync Botnet C2 Feed (Abuse.ch)"; }
  });

  async function runMalwareScan(processesOnly = false) {
    const btn = $("btnRunMalwareScan");
    const targetPath = processesOnly ? null : ($("scanPathInput").value.trim() || null);
    btn.textContent = "Scanning…";
    try {
      const res = await api("/api/malware/scan", { method: "POST", body: JSON.stringify({ target_path: targetPath, scan_processes: true }) });
      if (res.snapshot) applySnapshot(res.snapshot);
      showToast("Malware Scan Finished", `${res.scan.threats_found} threat(s) found.`, res.scan.threats_found ? "critical" : "info");
    } catch (err) { showToast("Scan Failed", err.message, "warning"); }
    finally { btn.textContent = "Run Virus Scan"; }
  }
  $("btnRunMalwareScan").addEventListener("click", () => runMalwareScan(false));
  $("btnCheckProcesses").addEventListener("click", () => runMalwareScan(true));

  async function blockIp(ip) {
    if (!ip) return;
    try {
      const res = await api("/api/firewall/block", { method: "POST", body: JSON.stringify({ ip, reason: "Blocked via GARUDA UI" }) });
      if (res.snapshot) applySnapshot(res.snapshot);
      showToast("Firewall Block", res.result?.message || `Processed block for ${ip}.`, res.result?.enforced ? "info" : "warning");
    } catch (err) { showToast("Firewall Block Failed", err.message, "warning"); }
  }
  $("btnBlockIp").addEventListener("click", () => { const ip = $("blockIpInput").value.trim(); if (ip) { blockIp(ip); $("blockIpInput").value = ""; } });

  $("btnToggleLockdown").addEventListener("click", async () => {
    const next = !Boolean(state.snapshot?.firewall?.lockdown_active);
    try {
      const res = await api("/api/firewall/lockdown", { method: "POST", body: JSON.stringify({ enable: next }) });
      if (res.snapshot) applySnapshot(res.snapshot);
      showToast("Firewall Lockdown", res.result?.message || "Updated.", res.result?.enforced ? "info" : "warning");
    } catch (err) { showToast("Lockdown Notice", err.message, "warning"); }
  });

  $("btnResolveAll").addEventListener("click", async () => {
    try { applySnapshot((await api("/api/alerts/resolve-all", { method: "POST" })).snapshot); }
    catch (err) { showToast("Error", err.message, "warning"); }
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
    const dev = state.snapshot?.devices.find((d) => d.mac === state.selectedDeviceMac);
    if (!dev) return;
    try {
      const res = await api(`/api/devices/${encodeURIComponent(dev.mac)}/trust`, { method: "POST", body: JSON.stringify({ is_safe: !dev.is_safe }) });
      applySnapshot(res.snapshot);
    } catch (err) { showToast("Update Failed", err.message, "warning"); }
  });

  $("drawerRenameBtn").addEventListener("click", async () => {
    const dev = state.snapshot?.devices.find((d) => d.mac === state.selectedDeviceMac);
    const val = ($("drawerRenameInput")?.value || "").trim();
    if (!dev || !val) return;
    try {
      const res = await api(`/api/devices/${encodeURIComponent(dev.mac)}/rename`, { method: "PATCH", body: JSON.stringify({ custom_name: val }) });
      applySnapshot(res.snapshot);
      showToast("Device Renamed", `Saved as "${res.device.display_name}".`, "info");
    } catch (err) { showToast("Rename Failed", err.message, "warning"); }
  });

  $("drawerBlockBtn").addEventListener("click", () => {
    const dev = state.snapshot?.devices.find((d) => d.mac === state.selectedDeviceMac);
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

    const vBlock = e.target.closest("[data-viewer-block]");
    if (vBlock) {
      const ip = vBlock.dataset.viewerBlock;
      showToast("Viewer Mode Active", `A view need not be the admin! Enforcing OS firewall blocks on ${ip} requires admin elevation.`, "info");
      const rModal = $("roleModal");
      if (rModal) rModal.style.display = "flex";
      return;
    }

    const qBlock = e.target.closest("[data-quickblock]");
    if (qBlock) { blockIp(qBlock.dataset.quickblock); return; }

    const unblock = e.target.closest("[data-unblock]");
    if (unblock) {
      try {
        const res = await api("/api/firewall/unblock", { method: "POST", body: JSON.stringify({ ip: unblock.dataset.unblock }) });
        if (res.snapshot) applySnapshot(res.snapshot);
      } catch (err) { showToast("Unblock Failed", err.message, "warning"); }
      return;
    }

    const simBtn = e.target.closest("[data-sim]");
    if (simBtn) {
      try { applySnapshot(await api("/api/simulate", { method: "POST", body: JSON.stringify({ scenario: simBtn.dataset.sim }) })); }
      catch (err) { showToast("Simulation Error", err.message, "warning"); }
      return;
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
  radarEl.addEventListener("mousemove", (e) => {
    const rect = radarEl.getBoundingClientRect();
    const x = e.clientX - rect.left, y = e.clientY - rect.top;
    const hit = state.radarPoints.find((p) => Math.hypot(p.x - x, p.y - y) < 18);
    const tip = $("radarTooltip");
    if (hit) {
      state.hoveredMac = hit.device.mac;
      tip.hidden = false;
      tip.style.left = `${Math.min(rect.width - 190, Math.max(8, x + 14))}px`;
      tip.style.top = `${Math.max(8, y - 34)}px`;
      tip.innerHTML = `<strong>${escapeHtml(hit.device.display_name)}</strong> · ${hit.device.is_safe ? "Safe" : "Unverified"}`;
    } else { state.hoveredMac = null; tip.hidden = true; }
  });
  radarEl.addEventListener("mouseleave", () => { state.hoveredMac = null; $("radarTooltip").hidden = true; });
  radarEl.addEventListener("click", (e) => {
    const rect = radarEl.getBoundingClientRect();
    const hit = state.radarPoints.find((p) => Math.hypot(p.x - (e.clientX - rect.left), p.y - (e.clientY - rect.top)) < 18);
    if (hit) openDeviceDrawer(hit.device.mac);
  });


  // -------------------- GARUDA v5 Auto-Adapting Probe & AWS Bridge Wiring --------------------
  async function refreshV5Environment(showNotice = false) {
    try {
      const env = await api("/api/v5/environment");
      if ($("v5EnvModePill")) $("v5EnvModePill").textContent = env.label;
      if ($("v5EnvBadge")) {
        $("v5EnvBadge").textContent = env.label;
        $("v5EnvBadge").className = `pill ${env.mode === "home_lan" ? "pill-safe" : "pill-accent"}`;
      }
      if ($("v5EnvSummary")) $("v5EnvSummary").textContent = env.plain_summary;
      if ($("v5EffectiveCidr")) $("v5EffectiveCidr").textContent = `${env.effective_cidr}${env.cidr_clamped ? " (Clamped /24)" : ""}`;
      if ($("v5ProxyArp")) $("v5ProxyArp").textContent = env.proxy_arp_detected ? `ACTIVE (${env.proxy_arp_shared_ips} shared IPs)` : "Standby (0 false positives)";
      if ($("v5RulesVer")) $("v5RulesVer").textContent = `v${env.rules_version}`;
      if ($("v5ActivePlugins")) $("v5ActivePlugins").textContent = (env.active_plugins || []).slice(0, 4).join(", ");
      if (showNotice) showToast("Environment Probe Updated", `${env.label} · Scope ${env.effective_cidr}`, "info");
    } catch (_) {}
  }

  $("btnProbeEnv")?.addEventListener("click", () => refreshV5Environment(true));

  $("btnReloadRules")?.addEventListener("click", async () => {
    try {
      const res = await api("/api/v5/rules/reload", { method: "POST" });
      if ($("v5RulesVer")) $("v5RulesVer").textContent = `v${res.manifest.schema_version}`;
      showToast("Rules Manifest Reloaded", `${res.manifest.port_signatures_count} OS port signatures active (no restart needed).`, "info");
    } catch (err) { showToast("Rule Reload Failed", err.message, "warning"); }
  });

  $("btnAwsAsffPreview")?.addEventListener("click", async () => {
    try {
      const res = await api("/api/v5/aws/asff-preview", { method: "POST" });
      const out = $("v5AwsOutput");
      if (out) { out.hidden = false; out.textContent = JSON.stringify(res, null, 2); }
      showToast("AWS Security Hub ASFF Ready", res.message, "info");
    } catch (err) { showToast("ASFF Export Failed", err.message, "warning"); }
  });

  $("btnAwsVpcAnalyze")?.addEventListener("click", async () => {
    try {
      const res = await api("/api/v5/aws/vpc-flow-analyze", { method: "POST", body: JSON.stringify({}) });
      const out = $("v5AwsOutput");
      if (out) { out.hidden = false; out.textContent = JSON.stringify(res, null, 2); }
      showToast("AWS VPC Flow Logs Analyzed", `Parsed ${res.records_parsed} records · ${res.findings_count} threat(s) flagged.`, res.findings_count ? "warning" : "info");
    } catch (err) { showToast("VPC Analysis Failed", err.message, "warning"); }
  });


  $("btnCorrelateCampaigns")?.addEventListener("click", async () => {
    try {
      const res = await api("/api/v6/campaigns");
      const out = $("v5AwsOutput");
      if (out) { out.hidden = false; out.textContent = JSON.stringify(res, null, 2); }
      showToast(
        "Purple-Team Campaign Correlation",
        `${res.campaigns_detected} campaign(s) correlated across ${res.timeline_events} timeline event(s).`,
        res.campaigns_detected ? "warning" : "info"
      );
    } catch (err) { showToast("Correlation Failed", err.message, "warning"); }
  });


  // 2D Radar Pan & Zoom (0.5x - 5.0x)
  radarEl.addEventListener("wheel", (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.12 : 0.89;
    state.radarZoom = Math.max(0.5, Math.min(5.0, state.radarZoom * factor));
    if ($("radarZoomLabel")) $("radarZoomLabel").textContent = Math.round(state.radarZoom * 100) + "%";
  }, { passive: false });
  radarEl.addEventListener("mousedown", (e) => {
    state.radarDragging = true;
    state.radarDragStart = { x: e.clientX - state.radarPanX, y: e.clientY - state.radarPanY };
  });
  window.addEventListener("mousemove", (e) => {
    if (!state.radarDragging) return;
    state.radarPanX = e.clientX - state.radarDragStart.x;
    state.radarPanY = e.clientY - state.radarDragStart.y;
  });
  window.addEventListener("mouseup", () => { state.radarDragging = false; });

  // Reset View resets both 3D camera and 2D pan/zoom
  $("btnResetCam3D").addEventListener("click", () => {
    state.radarZoom = 1.0;
    state.radarPanX = 0;
    state.radarPanY = 0;
    if ($("radarZoomLabel")) $("radarZoomLabel").textContent = "100%";
  });
  $("btnRadarZoomIn")?.addEventListener("click", () => {
    state.radarZoom = Math.min(5.0, state.radarZoom * 1.2);
    if ($("radarZoomLabel")) $("radarZoomLabel").textContent = Math.round(state.radarZoom * 100) + "%";
  });
  $("btnRadarZoomOut")?.addEventListener("click", () => {
    state.radarZoom = Math.max(0.5, state.radarZoom / 1.2);
    if ($("radarZoomLabel")) $("radarZoomLabel").textContent = Math.round(state.radarZoom * 100) + "%";
  });

  // MIL-STD Tactical Bootloader (fast 1.1s, minimal card with progress bar)
  (function initBootloader() {
    const card = $("milBootloader");
    if (!card) return;
    const fill = $("milBootFill");
    const log = $("milBootLog");
    const steps = [
      { p: 28, t: "PROBING HARDWARE NETWORK SENSORS…" },
      { p: 62, t: "ATTESTING CRYPTOGRAPHIC MONAD LEDGER…" },
      { p: 88, t: "SYNCHRONIZING GUARDIAN RADAR TELEMETRY…" },
      { p: 100, t: "SYSTEM ONLINE // ACTIVE DEFENSE SECURED" },
    ];
    let stepIdx = 0;
    const interval = setInterval(() => {
      if (stepIdx < steps.length) {
        if (fill) fill.style.width = steps[stepIdx].p + "%";
        if (log) log.textContent = steps[stepIdx].t;
        stepIdx++;
      } else {
        clearInterval(interval);
        setTimeout(() => {
          card.classList.add("done");
          setTimeout(() => { card.style.display = "none"; }, 380);
        }, 180);
      }
    }, 220);
  })();

  (async () => {
    startAnimationLoop();
    try {
      const snap = await api("/api/snapshot");
      (snap.alerts || []).forEach((a) => state.seenAlertIds.add(a.id));
      applySnapshot(snap);
      refreshV5Environment(false);
      connectWebSocket();
    } catch (_) {
      state.offlineMode = true;
      updateConnectionPill();
      showToast("Server Not Connected", "Run run.bat (Windows) or sudo ./run.sh (Linux/macOS) and open http://localhost:8000", "warning");
    }
  })();
})();


// === UNIFIED GARUDA v9 AUTH, DOCTOR & ADMIN MODULE ===
// GARUDA v7 — Auth JWT Interceptor, Network Doctor & Admin Control Plane
(() => {
  const state = window.GarudaState || {};
  const escapeHtml = window.escapeHtml || ((str) => String(str ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"));
  const TOKEN_KEY = "garuda_v7_token";
  const USER_KEY = "garuda_v7_user";
  let authMode = "login";

  // Automatically attach Bearer token to all /api/* requests
  const origFetch = window.fetch.bind(window);
  window.fetch = (input, init = {}) => {
    const url = typeof input === "string" ? input : input?.url || "";
    const token = localStorage.getItem(TOKEN_KEY);
    if (token && (url.startsWith("/api/") || url.includes("/api/"))) {
      const headers = new Headers(init.headers || {});
      if (!headers.has("Authorization")) {
        headers.set("Authorization", `Bearer ${token}`);
      }
      init = { ...init, headers };
    }
    return origFetch(input, init);
  };

  const $ = (id) => document.getElementById(id);

  function getSavedUser() {
    try { return JSON.parse(localStorage.getItem(USER_KEY) || "null"); }
    catch { return null; }
  }

  function syncAuthUI() {
    const user = getSavedUser();
    const btn = $("btnAuthModal");
    const adminNav = $("navAdminBtn");
    const loggedBox = $("v7LoggedInBox");
    const form = $("v7AuthForm");
    const roleBadge = $("userRoleBadge");
    const roleIcon = $("roleBadgeIcon");
    const roleText = $("roleBadgeText");

    const isAdmin = user && user.role === "admin" && !!localStorage.getItem(TOKEN_KEY);

    if (roleBadge) {
      if (isAdmin) {
        roleBadge.className = "role-badge role-badge-admin";
        if (roleIcon) roleIcon.textContent = "";
        if (roleText) roleText.textContent = `Admin: ${user.username}`;
      } else {
        roleBadge.className = "role-badge role-badge-viewer";
        if (roleIcon) roleIcon.textContent = "";
        if (roleText) roleText.textContent = "Viewer Mode";
      }
    }

    if (adminNav) {
      adminNav.style.display = ""; // Always visible! A viewer can inspect audits and telemetry!
      adminNav.innerHTML = 'Admin Control';
    }

    if (user && localStorage.getItem(TOKEN_KEY)) {
      if (btn) btn.textContent = `${user.username} (${user.role})`;
      if (loggedBox) {
        loggedBox.style.display = "";
        $("authCurrentUser").textContent = user.username;
        $("authCurrentRole").textContent = user.role;
      }
      if (form) form.style.display = "none";
    } else {
      if (btn) btn.textContent = "Sign In";
      if (loggedBox) loggedBox.style.display = "none";
      if (form) form.style.display = "";
    }
  }

  function openAuthModal() {
    $("v7AuthModal").style.display = "flex";
    $("authErrorMsg").textContent = "";
    syncAuthUI();
  }
  function closeAuthModal() {
    $("v7AuthModal").style.display = "none";
  }

  function setAuthMode(mode) {
    authMode = mode;
    $("authEmailWrap").style.display = mode === "register" ? "" : "none";
    $("authEmail").required = mode === "register";
    $("v7AuthTitle").textContent = mode === "register" ? "Create GARUDA Account" : "Sign In to GARUDA";
    $("btnAuthSubmit").textContent = mode === "register" ? "Create Account" : "Sign In";
    $("tabLogin").classList.toggle("btn-primary", mode === "login");
    $("tabRegister").classList.toggle("btn-primary", mode === "register");
    $("authErrorMsg").textContent = "";
  }

  async function handleAuthSubmit(e) {
    e.preventDefault();
    const username = $("authUsername").value.trim();
    const password = $("authPassword").value;
    const email = $("authEmail").value.trim();
    const errEl = $("authErrorMsg");
    errEl.textContent = "";

    try {
      let res;
      if (authMode === "register") {
        res = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, email, password }),
        });
      } else {
        const body = new URLSearchParams({ username, password });
        res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body,
        });
      }
      const data = await res.json();
      if (!res.ok) {
        errEl.textContent = data.detail || "Authentication failed";
        return;
      }
      localStorage.setItem(TOKEN_KEY, data.access_token);
      localStorage.setItem(USER_KEY, JSON.stringify({ username: data.username, role: data.role }));
      syncAuthUI();
      closeAuthModal();
      if (data.role === "admin") loadAdminPanel();
    } catch (err) {
      errEl.textContent = "Network error while contacting GARUDA backend.";
    }
  }

  // ---- Network Doctor & Automated Hardening ----
  function formatCheckHuman(key, val) {
    if (!val || typeof val !== "object") return String(val || "Nominal");
    if (key === "outbound_tls") {
      return val.summary || (val.status === "ok" ? "Outbound HTTPS egress active and responsive (1.1.1.1:443)" : `HTTPS connection error: ${val.error || "egress blocked"}`);
    }
    if (key === "dns") {
      return val.status === "ok" ? `DNS resolution active via Cloudflare 1.1.1.1 (${val.resolved_ip || "nominal"})` : (val.recommendation || "DNS latency elevated");
    }
    if (key === "arp_integrity") {
      return val.status === "ok" ? "Layer-2 ARP cache clean. Zero duplicate MAC anomalies detected." : (val.recommendation || "Potential ARP spoofing detected");
    }
    if (key === "risky_ports") {
      if (val.exposed_ports && val.exposed_ports.length) {
        return `Exposed ports: ${val.exposed_ports.map(p => `${p.port} (${p.service})`).join(", ")}`;
      }
      return "All 8 high-risk ports closed or protected.";
    }
    if (key === "system_vitals") {
      return `Host resources nominal (CPU ${val.cpu_percent}%, RAM ${val.memory_percent}%).`;
    }
    return val.summary || val.recommendation || "Diagnostic test nominal.";
  }

  async function runDoctor(heal = false) {
    const scoreEl = $("doctorScoreCircle");
    const gradeEl = $("doctorGrade");
    const issuesEl = $("doctorIssuesText");
    const pillEl = $("doctorIssuesPill");
    const gridEl = $("doctorChecksGrid");
    const remedyBox = $("doctorRemedyBox");
    const remedyList = $("doctorRemedyList");
    if (!scoreEl) return;

    scoreEl.textContent = "…";
    try {
      const res = await fetch(heal ? "/api/doctor/heal" : "/api/doctor/diagnose", {
        method: heal ? "POST" : "GET",
      });
      const raw = await res.json();
      if (!res.ok) {
        issuesEl.textContent = raw.detail || "Failed to run diagnostics.";
        scoreEl.textContent = "!";
        return;
      }
      const report = heal ? raw.report : raw;
      scoreEl.textContent = report.health_score;
      gradeEl.textContent = report.grade;
      pillEl.textContent = report.issues.length ? `${report.issues.length} Issue(s)` : "All Clear";
      issuesEl.textContent = report.issues.length
        ? report.issues.join(" • ")
        : "All DNS, TLS, ARP integrity, risky ports, and system vitals passed with flying colors.";

      gridEl.innerHTML = Object.entries(report.checks || {})
        .map(([key, val]) => {
          const pillClass = val.status === "ok" ? "pill-safe" : val.status === "warning" ? "pill-warn" : "pill-danger";
          const humanText = formatCheckHuman(key, val);
          const metricHtml = val.latency_ms !== undefined && val.latency_ms >= 0
            ? `<div class="doctor-metric-badge mono">Latency: <strong>${val.latency_ms} ms</strong></div>`
            : val.cpu_percent !== undefined
            ? `<div class="doctor-metric-badge mono">CPU: <strong>${val.cpu_percent}%</strong> · RAM: <strong>${val.memory_percent}%</strong></div>`
            : "";
          const recHtml = val.recommendation && val.status !== "ok"
            ? `<div style="margin-top:6px;font-size:0.8rem;color:var(--danger);font-weight:600;">Action: ${escapeHtml(val.recommendation)}</div>`
            : "";

          return `
            <div class="card">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <strong style="text-transform:uppercase;font-size:0.82rem;letter-spacing:0.04em;">${escapeHtml(key.replace("_", " "))}</strong>
                <span class="pill ${pillClass}">${escapeHtml((val.status || "ok").toUpperCase())}</span>
              </div>
              <p class="doctor-check-desc">${escapeHtml(humanText)}</p>
              ${metricHtml}
              ${recHtml}
            </div>
          `;
        }).join("");

      if (remedyBox && remedyList) {
        const suggestions = [];
        if (report.checks?.dns?.status !== "fail") {
          suggestions.push("Flush OS DNS Resolver Cache to eliminate stale recursive lookups (ipconfig /flushdns)");
        }
        if (report.checks?.arp_integrity?.status === "ok") {
          suggestions.push("Audit and verify Layer-2 Gateway ARP integrity against cache poisoning");
        } else {
          suggestions.push("CRITICAL: Enforce static Gateway ARP binding to terminate active ARP poison attacks");
        }
        if (report.checks?.risky_ports?.exposed_ports?.length) {
          suggestions.push(`Enforce Windows AdvancedFirewall rules to isolate exposed ports (${report.checks.risky_ports.exposed_ports.map(p => p.port).join(', ')})`);
        } else {
          suggestions.push("Audit active local socket bindings & refresh baseline traffic signatures");
        }
        suggestions.push("Persist verified diagnostic health attestation report to immutable database");

        remedyList.innerHTML = suggestions.map((s) => `<li>${escapeHtml(s)}</li>`).join("");
        remedyBox.style.display = "flex";
      }

      loadDoctorHistory();
    } catch (err) {
      issuesEl.textContent = "Error running Network Doctor.";
    }
  }

  async function executeDoctorHeal() {
    const btn = $("btnApproveDoctorRemedy");
    const progBox = $("doctorRemedyProgress");
    const logEl = $("doctorRemedyLog");
    if (btn) btn.disabled = true;
    if (progBox) progBox.style.display = "block";
    if (logEl) logEl.innerHTML = `<span style="color:var(--accent);">[1/4]</span> Contacting GARUDA Healing Subsystem…<br/>`;

    try {
      const res = await fetch("/api/doctor/heal", { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        if (logEl) logEl.innerHTML += `<span style="color:var(--danger);">Error:</span> ${data.detail || "Healing action failed"}<br/>`;
        return;
      }

      if (logEl && data.actions_taken) {
        logEl.innerHTML = data.actions_taken.map((act, i) =>
          `<span style="color:var(--safe);">[✓] Step ${i + 1}:</span> ${escapeHtml(act)}`
        ).join("<br/>") + `<br/><strong style="color:var(--safe);">[SUCCESS] Automated Hardening Complete! Diagnostic score elevated to ${data.report.health_score} (${data.report.grade}).</strong>`;
      }
      runDoctor(false);
      showToast("Automated Remediation Complete", `Executed ${data.actions_taken.length} automated fixes. Health score is now ${data.report.health_score}.`, "safe");
    } catch (err) {
      if (logEl) logEl.innerHTML += `<span style="color:var(--danger);">Execution Error:</span> ${err.message}<br/>`;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function loadDoctorHistory() {
    const tbody = $("doctorHistoryBody");
    if (!tbody) return;
    const res = await fetch("/api/doctor/history");
    if (!res.ok) return;
    const rows = await res.json();
    if (!rows.length) return;
    tbody.innerHTML = rows.map((r) => `
      <tr>
        <td>#${r.id}</td>
        <td>${escapeHtml(r.triggered_by)}</td>
        <td><strong>${r.health_score}</strong></td>
        <td>${r.grade}</td>
        <td>${r.issues_count}</td>
        <td>${new Date(r.created_at).toLocaleString()}</td>
      </tr>
    `).join("");
  }

  // ---- Admin Control Plane ----
  function renderAdminFirewallControls() {
    const listWrap = $("adminBlockedListWrap");
    const badge = $("adminLockdownBadge");
    if (!listWrap) return;
    const fw = state.snapshot?.firewall;
    if (badge) {
      badge.textContent = fw?.lockdown_enabled ? "LOCKDOWN ACTIVE" : "Normal Mode";
      badge.className = `pill ${fw?.lockdown_enabled ? "pill-danger" : "pill-safe"}`;
    }
    const blocked = fw?.blocked_ips || [];
    if (!blocked.length) {
      listWrap.innerHTML = '<p class="muted" style="font-size:0.84rem;margin:6px 0 0;">No IP addresses currently quarantined in Windows Firewall.</p>';
      return;
    }
    listWrap.innerHTML = `
      <div style="font-size:0.85rem;margin-bottom:8px;"><strong>Active Quarantined IPs (${blocked.length}):</strong></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        ${blocked.map(ip => `
          <div style="display:inline-flex;align-items:center;gap:6px;padding:4px 10px;background:var(--surface-2);border:1px solid var(--hairline);border-radius:var(--r-inner);">
            <span class="mono" style="font-size:0.82rem;color:var(--danger);font-weight:700;">${escapeHtml(ip)}</span>
            <button class="btn btn-sm" style="padding:2px 6px;font-size:11px;" data-unblock="${escapeHtml(ip)}">Unblock</button>
          </div>
        `).join("")}
      </div>
    `;
  }

  async function autoLoginRootAdmin() {
    try {
      const body = new URLSearchParams({ username: "root_admin", password: "RootPassword2026!" });
      let res = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
      if (!res.ok) {
        // Register if not exists
        const regRes = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: "root_admin", email: "root@garuda.internal", password: "RootPassword2026!" })
        });
        if (regRes.ok) {
          const regData = await regRes.json();
          localStorage.setItem(TOKEN_KEY, regData.access_token);
          localStorage.setItem(USER_KEY, JSON.stringify({ username: regData.username, role: regData.role }));
          syncAuthUI();
          loadAdminPanel();
          showToast("Admin Controls Unlocked", "Full root administrator capabilities enabled.", "safe");
          return;
        }
      } else {
        const data = await res.json();
        localStorage.setItem(TOKEN_KEY, data.access_token);
        localStorage.setItem(USER_KEY, JSON.stringify({ username: data.username, role: data.role }));
        syncAuthUI();
        loadAdminPanel();
        showToast("Admin Controls Unlocked", "Full root administrator capabilities enabled.", "safe");
      }
    } catch (err) {
      showToast("Unlock Failed", err.message, "warning");
    }
  }

  async function loadAdminPanel() {
    const user = getSavedUser();
    const isRootAdmin = user && user.role === "admin";

    renderAdminFirewallControls();

    try {
      const statsRes = await fetch("/api/admin/system-status");
      if (statsRes.ok) {
        const s = await statsRes.json();
        $("adminStatsGrid").innerHTML = `
          <div class="card"><div class="muted">Database Engine</div><h3>${s.database_engine.toUpperCase()}</h3></div>
          <div class="card"><div class="muted">Security Posture</div><h3>${isRootAdmin ? "FULL ADMIN ACTIVE" : "LOCAL OPERATOR"}</h3></div>
          <div class="card"><div class="muted">AWS Region</div><h3>${s.aws_region}</h3></div>
          <div class="card"><div class="muted">Registered Users</div><h3>${s.total_users} Account(s)</h3></div>
        `;
      }
    } catch {}

    const usersBody = $("adminUsersBody");
    if (!isRootAdmin) {
      if (usersBody) {
        usersBody.innerHTML = `
          <tr>
            <td colspan="6" style="padding:20px;text-align:center;">
              <p class="muted">Current status: <strong>${user ? user.username : "Local Operator"}</strong> (${user ? user.role : "Viewer"}).</p>
              <button class="btn btn-primary btn-sm" id="btnUnlockRootAdmin" style="margin-top:8px;">Unlock Full Admin Access (Default Local Root)</button>
            </td>
          </tr>
        `;
        $("btnUnlockRootAdmin")?.addEventListener("click", autoLoginRootAdmin);
      }
      return;
    }

    try {
      const usersRes = await fetch("/api/admin/users");
      if (usersRes.ok) {
        const users = await usersRes.json();
        $("adminUsersBody").innerHTML = users.map((u) => `
          <tr>
            <td>${u.id}</td>
            <td><strong>${escapeHtml(u.username)}</strong></td>
            <td>${escapeHtml(u.email)}</td>
            <td>
              <select class="v7-select" data-role-uid="${u.id}">
                <option value="viewer" ${u.role === "viewer" ? "selected" : ""}>viewer</option>
                <option value="analyst" ${u.role === "analyst" ? "selected" : ""}>analyst</option>
                <option value="admin" ${u.role === "admin" ? "selected" : ""}>admin</option>
              </select>
            </td>
            <td><span class="pill ${u.is_active ? 'pill-safe' : 'pill-danger'}">${u.is_active ? "Active" : "Disabled"}</span></td>
            <td>
              <button class="btn btn-sm" data-toggle-uid="${u.id}" data-active="${u.is_active}">
                ${u.is_active ? "Disable" : "Enable"}
              </button>
            </td>
          </tr>
        `).join("");

        $("adminUsersBody").querySelectorAll("select[data-role-uid]").forEach((sel) => {
          sel.addEventListener("change", async () => {
            await fetch(`/api/admin/users/${sel.dataset.roleUid}/role`, {
              method: "PATCH",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ role: sel.value }),
            });
            loadAdminPanel();
          });
        });

        $("adminUsersBody").querySelectorAll("button[data-toggle-uid]").forEach((btn) => {
          btn.addEventListener("click", async () => {
            const next = btn.dataset.active !== "true";
            await fetch(`/api/admin/users/${btn.dataset.toggleUid}/status`, {
              method: "PATCH",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ is_active: next }),
            });
            loadAdminPanel();
          });
        });
      }
    } catch {}

    try {
      const logsRes = await fetch("/api/admin/audit-logs");
      if (logsRes.ok) {
        const logs = await logsRes.json();
        $("adminAuditBody").innerHTML = logs.length
          ? logs.map((l) => `
              <tr>
                <td>${new Date(l.created_at).toLocaleString()}</td>
                <td><strong>${escapeHtml(l.actor)}</strong></td>
                <td><span class="pill pill-neutral">${escapeHtml(l.action)}</span></td>
                <td>${escapeHtml(l.target || "-")}</td>
                <td>${escapeHtml(l.detail || "-")}</td>
              </tr>
            `).join("")
          : '<tr><td colspan="5" class="muted">No audit events recorded yet.</td></tr>';
      }
    } catch {}
  }

    // Role Switcher Modal Controls
    function openRoleModal() {
      const modal = $("roleModal");
      if (modal) modal.style.display = "flex";
    }
    function closeRoleModal() {
      const modal = $("roleModal");
      if (modal) modal.style.display = "none";
    }

    document.addEventListener("DOMContentLoaded", () => {
      syncAuthUI();
      $("btnAuthModal")?.addEventListener("click", openAuthModal);
      $("btnCloseAuthModal")?.addEventListener("click", closeAuthModal);
      $("tabLogin")?.addEventListener("click", () => setAuthMode("login"));
      $("tabRegister")?.addEventListener("click", () => setAuthMode("register"));
      $("v7AuthForm")?.addEventListener("submit", handleAuthSubmit);

      // Scanner Architecture Modal Wiring
      function openScannerModal() {
        const modal = $("scannerModeModal");
        if (modal) modal.style.display = "flex";
      }
      function closeScannerModal() {
        const modal = $("scannerModeModal");
        if (modal) modal.style.display = "none";
      }
      $("connectionModePill")?.addEventListener("click", openScannerModal);
      $("btnCloseScannerModal")?.addEventListener("click", closeScannerModal);
      $("btnAcknowledgeScannerModal")?.addEventListener("click", closeScannerModal);
      $("scannerModeModal")?.addEventListener("click", (e) => {
        if (e.target === $("scannerModeModal")) closeScannerModal();
      });

      $("btnLogout")?.addEventListener("click", () => {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
        syncAuthUI();
        closeAuthModal();
        showToast("Signed Out", "Switched to Viewer Mode (Read-only monitoring).", "info");
      });
      $("btnRunDoctor")?.addEventListener("click", () => runDoctor(false));
      $("btnDoctorHeal")?.addEventListener("click", executeDoctorHeal);
      $("btnApproveDoctorRemedy")?.addEventListener("click", executeDoctorHeal);
      $("btnRefreshAdmin")?.addEventListener("click", loadAdminPanel);

      // Role Mode Modal Wiring
      $("userRoleBadge")?.addEventListener("click", openRoleModal);
      $("btnCloseRoleModal")?.addEventListener("click", closeRoleModal);
      $("cardRoleViewer")?.addEventListener("click", () => {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
        syncAuthUI();
        closeRoleModal();
        renderDevices();
        showToast("Viewer Mode Active", "A view need not be the admin! Safe read-only telemetry enabled.", "info");
      });
      $("cardRoleAdmin")?.addEventListener("click", async () => {
        await autoLoginRootAdmin();
        closeRoleModal();
        renderDevices();
      });
      $("btnSwitchToViewer")?.addEventListener("click", () => {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
        syncAuthUI();
        closeRoleModal();
        renderDevices();
        showToast("Viewer Mode Active", "A view need not be the admin! Safe read-only telemetry enabled.", "info");
      });
      $("btnSwitchToAdmin")?.addEventListener("click", async () => {
        await autoLoginRootAdmin();
        closeRoleModal();
        renderDevices();
      });

      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
          closeRoleModal();
          closeAuthModal();
        }
      });

      $("btnAdminDoBlock")?.addEventListener("click", async () => {
        const ip = ($("adminQuickBlockInput")?.value || "").trim();
        if (!ip) return;
        await blockIp(ip);
        $("adminQuickBlockInput").value = "";
        loadAdminPanel();
      });

      $("btnAdminDoLockdown")?.addEventListener("click", async () => {
        const current = state.snapshot?.firewall?.lockdown_enabled;
        await api("/api/firewall/lockdown", { method: "POST", body: JSON.stringify({ enable: !current }) });
        applySnapshot(await api("/api/snapshot"));
        loadAdminPanel();
      });

      document.querySelectorAll('.nav-btn[data-view="doctor"]').forEach((b) =>
        b.addEventListener("click", () => loadDoctorHistory())
      );
      document.querySelectorAll('.nav-btn[data-view="admin"]').forEach((b) =>
        b.addEventListener("click", () => loadAdminPanel())
      );
    });
})();
