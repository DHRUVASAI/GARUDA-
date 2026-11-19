/**
 * GARUDA — Multi-Ring Collision-Free Layout & AABB Collision Placer Engine
 * 
 * Provides guaranteed non-overlapping polar coordinates in 2D and 3D at ANY scale
 * (10, 100, 500, 1,000+ devices). Implements:
 * 1. Deterministic 3-Band Trust Partitioning (Safe -> Unverified -> Alert perimeter)
 * 2. Circumference Ring-Capacity Staggered Packing (Euclidean dist >= minSpacing)
 * 3. Priority-Sorted Greedy 2D AABB Collision Placer for crisp, non-clashing labels
 * 4. Synthetic Device Generator and Verification Suite
 */

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else if (typeof define === "function" && define.amd) {
    define([], factory);
  } else {
    const exports = factory();
    root.GarudaLayoutEngine = exports;
    if (typeof window !== "undefined") window.GarudaLayoutEngine = exports;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /**
   * Deterministic partitioning into 3 trust bands:
   * Band A (Inner): Safe devices
   * Band B (Middle): Unverified devices
   * Band C (Outer): Active Alert / Critical ML Risk devices
   */
  function partitionTrustBands(devices, alerts = [], mlScores = []) {
    const mlMap = new Map();
    (mlScores || []).forEach((m) => {
      if (m && m.mac) mlMap.set(m.mac.toUpperCase(), m);
    });

    const activeAlertMacs = new Set();
    const activeAlertIps = new Set();
    (alerts || []).forEach((a) => {
      if (!a.resolved) {
        if (a.related_mac) activeAlertMacs.add(a.related_mac.toUpperCase());
        if (a.related_ip) activeAlertIps.add(a.related_ip);
      }
    });

    const online = (devices || []).filter((d) => d && d.is_online !== false);
    const gw = online.find((d) => d.is_gateway) || online[0] || null;
    const nonGw = online.filter((d) => d !== gw);

    const bandA = []; // Safe
    const bandB = []; // Unverified
    const bandC = []; // Active Alert / Critical ML Risk (Outermost Perimeter)

    nonGw.forEach((d) => {
      const macU = (d.mac || "").toUpperCase();
      const ip = d.ip || "";
      const ml = mlMap.get(macU);

      const isAlert =
        activeAlertMacs.has(macU) ||
        activeAlertIps.has(ip) ||
        Boolean(ml && (ml.risk_level === "critical" || ml.anomaly_score >= 70));

      const enriched = {
        device: d,
        ml,
        isAlert,
        isSafe: Boolean(d.is_safe && !isAlert),
      };

      if (isAlert) {
        enriched.band = "C";
        bandC.push(enriched);
      } else if (d.is_safe) {
        enriched.band = "A";
        bandA.push(enriched);
      } else {
        enriched.band = "B";
        bandB.push(enriched);
      }
    });

    return {
      gateway: gw,
      safe: bandA,
      unverified: bandB,
      alert: bandC,
      totalCount: nonGw.length,
    };
  }

  /**
   * Computes capacity of a ring at radius r given min Euclidean spacing s.
   * Exact geometric formula: chord = 2 * r * sin(pi / cap) >= s
   */
  function computeRingCapacity(r, minSpacing) {
    if (r <= 0 || minSpacing <= 0) return 1;
    const ratio = minSpacing / (2 * r);
    if (ratio >= 0.999) return 1;
    const maxK = Math.floor(Math.PI / Math.asin(ratio));
    return Math.max(1, maxK);
  }

  /**
   * Computes guaranteed non-overlapping polar coordinates across all 3 trust bands.
   */
  function computePolarLayout(devices, alerts = [], mlScores = [], options = {}) {
    const mode = options.mode || "2d"; // '2d' or '3d'
    const is3D = mode === "3d";
    const totalDevices = (devices || []).length;

    // Adaptive spacing invariants
    let minSpacing = options.minNodeSpacing;
    if (!minSpacing) {
      if (is3D) {
        minSpacing = 1.35; // 3D world units (mesh width <= 0.86, guarantee dist >= 1.35)
      } else {
        if (totalDevices <= 18) minSpacing = 36;
        else if (totalDevices <= 80) minSpacing = 26;
        else if (totalDevices <= 300) minSpacing = 18;
        else minSpacing = 13;
      }
    }

    const ringStep = options.ringStep || (is3D ? 1.45 : Math.max(minSpacing * 1.15, minSpacing + 4));
    const bandMargin = options.bandMargin || (is3D ? 1.85 : Math.max(minSpacing * 1.4, minSpacing + 12));
    const centerRouterRadius = options.centerRouterRadius || (is3D ? 0.56 : 30);

    const partition = partitionTrustBands(devices, alerts, mlScores);
    const placedNodes = [];
    const ringList = [];

    let currentRadius = centerRouterRadius + minSpacing + (is3D ? 0.85 : 10);
    let globalRingIndex = 0;

    function layoutBand(bandItems, bandId) {
      if (!bandItems.length) return;
      let remaining = [...bandItems];
      let bandRingIndex = 0;

      while (remaining.length > 0) {
        const cap = computeRingCapacity(currentRadius, minSpacing);
        const countOnRing = Math.min(remaining.length, cap);
        const slice = remaining.splice(0, countOnRing);

        // Half-step angular staggering on alternating concentric rings to form hexagonal interlock
        const angleOffset = countOnRing > 1 ? (bandRingIndex % 2) * (Math.PI / countOnRing) : 0;

        for (let i = 0; i < countOnRing; i++) {
          const angle = (i / countOnRing) * Math.PI * 2 + angleOffset - Math.PI / 2;
          const x = Math.cos(angle) * currentRadius;
          const zOrY = Math.sin(angle) * currentRadius;

          const item = slice[i];
          placedNodes.push({
            device: item.device,
            ml: item.ml,
            isAlert: item.isAlert,
            isSafe: item.isSafe,
            band: bandId,
            radius: currentRadius,
            angle,
            ringIndex: globalRingIndex,
            bandRingIndex,
            x: is3D ? x : x,
            y: is3D ? 0.02 : zOrY,
            z: is3D ? zOrY : 0,
          });
        }

        ringList.push({
          radius: currentRadius,
          band: bandId,
          count: countOnRing,
          ringIndex: globalRingIndex,
        });

        bandRingIndex++;
        globalRingIndex++;

        if (remaining.length > 0) {
          currentRadius += ringStep;
        }
      }

      // Add inter-band clear separation margin
      currentRadius += bandMargin;
    }

    // Deterministic Layout Order:
    // Band A (Safe Inner) -> Band B (Unverified Middle) -> Band C (Active Alert Outer Perimeter)
    layoutBand(partition.safe, "A");
    layoutBand(partition.unverified, "B");
    layoutBand(partition.alert, "C");

    const outerRadius = Math.max(currentRadius - bandMargin + minSpacing * 0.5, currentRadius);

    return {
      nodes: placedNodes,
      rings: ringList,
      gateway: partition.gateway,
      partition,
      outerRadius,
      centerRouterRadius,
      minNodeSpacing: minSpacing,
      ringStep,
      mode,
    };
  }

  /**
   * Helper: checks if two 2D Axis-Aligned Bounding Boxes intersect
   */
  function aabbIntersect(a, b) {
    return !(a.x2 < b.x1 || a.x1 > b.x2 || a.y2 < b.y1 || a.y1 > b.y2);
  }

  /**
   * Priority-Sorted Greedy 2D AABB Collision Placer for Canvas Labels
   * Guarantees zero overlapping labels, zero overlapping node dots, and zero router text overlap.
   */
  function compute2DLabelPlacement(nodes, options = {}) {
    const width = options.width || 800;
    const height = options.height || 600;
    const cx = options.cx !== undefined ? options.cx : width / 2;
    const cy = options.cy !== undefined ? options.cy : height / 2;
    const zoom = options.zoom || 1.0;
    const panX = options.panX || 0;
    const panY = options.panY || 0;
    const nodeRadius = options.nodeRadius || 7;
    const routerRadius = options.routerRadius || 30;
    const hoveredMac = (options.hoveredMac || "").toUpperCase();
    const selectedMac = (options.selectedMac || "").toUpperCase();
    const isCompact = Boolean(options.compact);
    const measureTextFn = options.measureTextFn || ((txt) => ({ width: txt.length * 6.5 }));
    const margin = 8;

    const occupied = [];

    // 1. Router circular node bounding box (padded)
    const routerScreenX = cx + panX;
    const routerScreenY = cy + panY;
    occupied.push({
      x1: routerScreenX - routerRadius - 6,
      y1: routerScreenY - routerRadius - 6,
      x2: routerScreenX + routerRadius + 6,
      y2: routerScreenY + routerRadius + 6,
      type: "router",
    });

    // 2. Pre-populate occupied with all visible node dots padded by +4px
    const projectedNodes = (nodes || []).map((node) => {
      const sx = cx + panX + node.x * zoom;
      const sy = cy + panY + node.y * zoom;
      const macU = (node.device?.mac || "").toUpperCase();
      const isHovered = Boolean(hoveredMac && macU === hoveredMac);
      const isSelected = Boolean(selectedMac && macU === selectedMac);
      const effRadius = nodeRadius * (isHovered ? 1.3 : 1.0);

      // Add node circle bounding box so no label can ever cross a dot
      occupied.push({
        x1: sx - effRadius - 4,
        y1: sy - effRadius - 4,
        x2: sx + effRadius + 4,
        y2: sy + effRadius + 4,
        type: "dot",
      });

      // Assign strict placement priority rank
      let rank = 4; // Safe default
      if (isHovered || isSelected) rank = 1;
      else if (node.isAlert) rank = 2;
      else if (!node.isSafe) rank = 3;

      return {
        ...node,
        screenX: sx,
        screenY: sy,
        effRadius,
        isHovered,
        isSelected,
        rank,
      };
    });

    // Sort devices strictly by priority
    projectedNodes.sort((a, b) => a.rank - b.rank);

    const placedLabels = [];
    let placedCount = 0;
    const maxCompactLabels = 12;

    for (let i = 0; i < projectedNodes.length; i++) {
      const pNode = projectedNodes[i];
      if (isCompact && placedCount >= maxCompactLabels && pNode.rank > 2) {
        continue;
      }

      const rawName = pNode.device?.display_name || pNode.device?.ip || "Unknown";
      const lbl = rawName.length > 17 ? rawName.slice(0, 16) + "…" : rawName;
      const textDim = measureTextFn(lbl);
      const textW = textDim.width || 60;
      const boxW = textW + 12; // 6px padding on each side
      const boxH = isCompact ? 16 : 18;

      const sx = pNode.screenX;
      const sy = pNode.screenY;
      const nr = pNode.effRadius;
      const angle = pNode.angle;

      // 5 Candidate Anchor Boxes in Radial Order:
      // [outward-radial, below, above, right, left]
      const candidates = [];

      // 0: Outward-radial
      const cosA = Math.cos(angle);
      const sinA = Math.sin(angle);
      const radDist = nr + 6;
      candidates.push({
        x1: sx + cosA * radDist + (cosA < -0.2 ? -boxW : cosA > 0.2 ? 0 : -boxW / 2),
        y1: sy + sinA * radDist + (sinA < -0.2 ? -boxH : sinA > 0.2 ? 0 : -boxH / 2),
        x2: 0,
        y2: 0,
        anchor: "radial",
      });

      // 1: Below
      candidates.push({
        x1: sx - boxW / 2,
        y1: sy + nr + 4,
        x2: 0,
        y2: 0,
        anchor: "below",
      });

      // 2: Above
      candidates.push({
        x1: sx - boxW / 2,
        y1: sy - nr - 4 - boxH,
        x2: 0,
        y2: 0,
        anchor: "above",
      });

      // 3: Right
      candidates.push({
        x1: sx + nr + 5,
        y1: sy - boxH / 2,
        x2: 0,
        y2: 0,
        anchor: "right",
      });

      // 4: Left
      candidates.push({
        x1: sx - nr - 5 - boxW,
        y1: sy - boxH / 2,
        x2: 0,
        y2: 0,
        anchor: "left",
      });

      let acceptedCandidate = null;

      for (let c = 0; c < candidates.length; c++) {
        const cand = candidates[c];
        cand.x2 = cand.x1 + boxW;
        cand.y2 = cand.y1 + boxH;

        // Boundary constraint
        if (
          cand.x1 < margin ||
          cand.y1 < margin ||
          cand.x2 > width - margin ||
          cand.y2 > height - margin
        ) {
          continue;
        }

        // Collision check against all occupied boxes
        let collision = false;
        for (let o = 0; o < occupied.length; o++) {
          if (aabbIntersect(cand, occupied[o])) {
            collision = true;
            break;
          }
        }

        if (!collision) {
          acceptedCandidate = cand;
          break;
        }
      }

      if (acceptedCandidate) {
        occupied.push({
          x1: acceptedCandidate.x1,
          y1: acceptedCandidate.y1,
          x2: acceptedCandidate.x2,
          y2: acceptedCandidate.y2,
          type: "label",
        });

        placedLabels.push({
          node: pNode,
          box: acceptedCandidate,
          text: lbl,
          screenX: sx,
          screenY: sy,
        });
        placedCount++;
      }
    }

    return {
      placedLabels,
      placedCount,
      totalCount: projectedNodes.length,
      projectedNodes,
      occupiedBoxes: occupied,
    };
  }

  /**
   * Generates realistic synthetic devices for stress-testing.
   */
  function generateSyntheticDevices(count, alertRatio = 0.08, unverifiedRatio = 0.22) {
    const devices = [];
    const alerts = [];
    const mlScores = [];

    const vendors = [
      { vendor: "Apple, Inc.", types: ["phone", "laptop", "tablet"] },
      { vendor: "Samsung Electronics", types: ["phone", "tv", "iot"] },
      { vendor: "Intel Corporate", types: ["laptop"] },
      { vendor: "Espressif Systems", types: ["iot"] },
      { vendor: "Google LLC", types: ["phone", "iot"] },
      { vendor: "Amazon Technologies", types: ["iot", "tv"] },
      { vendor: "HP Inc.", types: ["printer", "laptop"] },
    ];

    // Always include a Gateway Router
    devices.push({
      id: 1,
      ip: "192.168.1.1",
      mac: "70:85:C2:44:10:01",
      display_name: "GARUDA Gateway Core",
      vendor: "Cisco Systems",
      device_type: "router",
      is_online: true,
      is_safe: true,
      is_gateway: true,
      trust_score: 99,
    });

    const alertCount = Math.max(alertRatio > 0 ? 1 : 0, Math.floor(count * alertRatio));
    const unverifiedCount = Math.floor(count * unverifiedRatio);

    for (let i = 2; i <= count; i++) {
      const vObj = vendors[(i - 2) % vendors.length];
      const dType = vObj.types[(i - 2) % vObj.types.length];
      const octet3 = Math.floor((i + 1) / 254);
      const octet4 = ((i + 1) % 254) + 1;
      const ip = `192.168.${octet3}.${octet4}`;
      const mac = [
        "00",
        "E0",
        (i & 0xff).toString(16).padStart(2, "0"),
        ((i >> 8) & 0xff).toString(16).padStart(2, "0"),
        ((i * 7) & 0xff).toString(16).padStart(2, "0"),
        ((i * 13) & 0xff).toString(16).padStart(2, "0"),
      ]
        .join(":")
        .toUpperCase();

      const isAlert = i <= alertCount + 1;
      const isUnverified = !isAlert && i <= alertCount + unverifiedCount + 1;
      const isSafe = !isAlert && !isUnverified;

      const dev = {
        id: i,
        ip,
        mac,
        display_name: isAlert
          ? `Hostile-${dType}-${i}`
          : `${vObj.vendor.split(" ")[0]}-${dType}-${i}`,
        vendor: vObj.vendor,
        device_type: dType,
        is_online: true,
        is_safe: isSafe,
        is_gateway: false,
        trust_score: isAlert ? 15 : isUnverified ? 45 : 92,
      };
      devices.push(dev);

      if (isAlert) {
        alerts.push({
          id: i,
          title: "Malicious Beacon Detected",
          severity: "critical",
          related_mac: mac,
          related_ip: ip,
          resolved: false,
        });
        mlScores.push({
          mac,
          anomaly_score: 88,
          risk_level: "critical",
          heuristic_penalties: ["C2_BEACONING", "DGA_DOMAIN"],
        });
      } else if (isUnverified) {
        mlScores.push({
          mac,
          anomaly_score: 42,
          risk_level: "elevated",
          heuristic_penalties: ["UNKNOWN_VENDOR"],
        });
      } else {
        mlScores.push({
          mac,
          anomaly_score: 8,
          risk_level: "nominal",
          heuristic_penalties: [],
        });
      }
    }

    return {
      devices,
      alerts,
      mlScores,
      ml: {
        device_scores: mlScores,
        anomaly_detected: alertCount > 0,
        training_samples: 1200,
        model_version: "IsolationForest-v4",
        last_trained: new Date().toISOString(),
      },
      settings: {
        sound_enabled: true,
        desktop_notifications: true,
        auto_block: false,
        simulation_mode: true,
      },
      capabilities: {
        ids_mode: "live_packet_sniffer",
        sklearn_available: true,
        crypto_signature_alg: "Ed25519",
        web3_configured: false,
      },
      firewall: { active_blocks: [], available: true },
      ids_stats: { packets_analyzed: count * 350, alerts_fired: alertCount },
      ledger: { total_blocks: 65, verified: true, chain_head_hash: "0x4a7f...e92b" },
      network: { ssid: "GARUDA-Scale-Lab", interface: "Wi-Fi", ip: "192.168.1.100" },
    };
  }

  /**
   * Rigorous automated invariant verification suite:
   * 1. Zero pairwise Euclidean distance violations (dist >= minSpacing)
   * 2. Zero pairwise AABB overlaps between placed labels and node dots
   */
  function verifyLayoutInvariants(layoutResult, labelResult) {
    const nodes = layoutResult.nodes || [];
    const minSpacing = layoutResult.minNodeSpacing;
    const is3D = layoutResult.mode === "3d";

    let minCalculatedDist = Infinity;
    let distanceViolations = 0;
    const violationDetails = [];

    // Pairwise Euclidean distance check across all node pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        const dx = a.x - b.x;
        const dy = is3D ? (a.z || 0) - (b.z || 0) : (a.y || 0) - (b.y || 0);
        const dist = Math.hypot(dx, dy);

        if (dist < minCalculatedDist) {
          minCalculatedDist = dist;
        }

        // Allow tiny floating point epsilon (0.0001)
        if (dist < minSpacing - 1e-4) {
          distanceViolations++;
          if (violationDetails.length < 5) {
            violationDetails.push({ i, j, dist, minSpacing });
          }
        }
      }
    }

    // Pairwise AABB check across all placed labels
    let aabbOverlaps = 0;
    const labelBoxes = (labelResult?.placedLabels || []).map((l) => l.box);
    const overlapDetails = [];

    for (let i = 0; i < labelBoxes.length; i++) {
      for (let j = i + 1; j < labelBoxes.length; j++) {
        if (aabbIntersect(labelBoxes[i], labelBoxes[j])) {
          aabbOverlaps++;
          if (overlapDetails.length < 5) {
            overlapDetails.push({ i, j, boxA: labelBoxes[i], boxB: labelBoxes[j] });
          }
        }
      }
    }

    // Check that placed labels don't overlap with any node dot box
    const dotBoxes = (labelResult?.occupiedBoxes || []).filter((b) => b.type === "dot" || b.type === "router");
    let labelDotOverlaps = 0;
    for (let i = 0; i < labelBoxes.length; i++) {
      for (let j = 0; j < dotBoxes.length; j++) {
        if (aabbIntersect(labelBoxes[i], dotBoxes[j])) {
          labelDotOverlaps++;
        }
      }
    }

    const passed = distanceViolations === 0 && aabbOverlaps === 0 && labelDotOverlaps === 0;

    return {
      passed,
      nodeCount: nodes.length,
      placedLabelsCount: labelBoxes.length,
      minSpacingTarget: minSpacing,
      actualMinDistance: minCalculatedDist === Infinity ? minSpacing : minCalculatedDist,
      distanceViolations,
      aabbOverlaps,
      labelDotOverlaps,
      violationDetails,
      overlapDetails,
    };
  }

  return {
    partitionTrustBands,
    computeRingCapacity,
    computePolarLayout,
    compute2DLabelPlacement,
    aabbIntersect,
    generateSyntheticDevices,
    verifyLayoutInvariants,
  };
});
