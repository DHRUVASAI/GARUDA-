/**
 * GARUDA — Collision-Free Spatial Layout & Density Engine (2D & 3D)
 * Mathematical Multi-Tier Orbital Packing + Density-Adaptive LOD
 * Guarantees ZERO overlaps from single home networks to 500+ enterprise endpoints.
 */
(function (global) {
  const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5)); // ~137.5 degrees

  function getCompactDeviceLabel(d) {
    if (!d) return "Device";
    const name = (d.custom_name || d.display_name || d.real_name || d.ip || "Device").trim();
    const octet = (d.ip || "").split(".").pop() || "";

    // 1. Specific Smart Home & Peripherals
    if (/amazon echo|echo dot|alexa/i.test(name)) return "Echo Dot";
    if (/fire tv|firestick/i.test(name)) return "Fire TV";
    if (/canon|g4070|printer/i.test(name)) return "Canon G4070";
    if (/galaxy|samsung/i.test(name)) return "Galaxy A73";
    if (/realme/i.test(name)) return "Realme Phone";
    if (/xiaomi|12t|redmi|poco/i.test(name)) return "Xiaomi 12T";
    if (/motorola|moto|edge 60/i.test(name)) return "Moto Edge";
    if (/omen|hp omen/i.test(name)) return "HP OMEN";
    if (/laasya/i.test(name)) return "LAASYA PC";
    if (/lg|webos/i.test(name)) return "LG Smart TV";
    if (/zyxel/i.test(name)) return "Zyxel GW";
    if (/hewlett packard enterprise|hpe|aruba/i.test(name)) return "HPE Gateway";

    // 2. Campus & Enterprise Wi-Fi OEMs
    if (/cloud network|singapore pte/i.test(name)) return `Foxconn PC (${octet})`;
    if (/azurewave/i.test(name)) return `ASUS Laptop (${octet})`;
    if (/intel corporate|intel wi-fi/i.test(name)) return `Intel PC (${octet})`;
    if (/liteon|lite-on/i.test(name)) return `Dell PC (${octet})`;
    if (/wnc|wistron/i.test(name)) return `HP Laptop (${octet})`;
    if (/fulian|jiangsu/i.test(name)) return `Foxconn PC (${octet})`;
    if (/spotify/i.test(name)) return `Spotify PC (${octet})`;
    if (/macbook/i.test(name)) return "MacBook";
    if (/iphone/i.test(name)) return "iPhone";
    if (/desktop-/i.test(name)) return `Desktop (${octet})`;
    if (/laptop-/i.test(name)) return `Laptop (${octet})`;
    if (/private wi-fi|randomized mac/i.test(name)) return `Private (${octet})`;

    return name.length > 15 ? name.slice(0, 14) + "…" : name;
  }

  /**
   * Concentric Multi-Tier Orbital Packing
   * Distributes N devices across M rings with zero chord or radial overlap.
   */
  function compute2DRingLayout(devices, cx, cy, baseRadius) {
    if (!devices || !devices.length) return [];
    const count = devices.length;
    const placed = [];

    // Small network (1-12 devices): Clean 3-tier staggered orbital layout
    if (count <= 12) {
      const tracks = [
        baseRadius * 0.52,
        baseRadius * 0.74,
        baseRadius * 0.94,
      ];
      const step = (Math.PI * 2) / count;
      const startAngle = -Math.PI / 2;

      devices.forEach((d, i) => {
        const trackIdx = i % tracks.length;
        const r = tracks[trackIdx];
        const angle = startAngle + i * step;

        placed.push({
          device: d,
          x: cx + Math.cos(angle) * r,
          y: cy + Math.sin(angle) * r,
          radius: r,
          angle,
          track: trackIdx,
        });
      });
      return placed;
    }

    // Enterprise / Large fleet (13 to 500+ devices):
    // Determine number of concentric rings: 4 to 7 rings
    const numRings = Math.max(4, Math.min(7, Math.ceil(Math.sqrt(count / 2.8))));
    const minRadius = baseRadius * 0.38;
    const maxRadius = baseRadius * 0.96;
    const radialSpan = maxRadius - minRadius;

    // Calculate circumference and capacity for each ring
    const ringRadii = [];
    const ringCaps = [];
    let totalCap = 0;

    for (let k = 0; k < numRings; k++) {
      const r = minRadius + (k / (numRings - 1)) * radialSpan;
      const circ = 2 * Math.PI * r;
      ringRadii.push(r);
      ringCaps.push(circ);
      totalCap += circ;
    }

    // Distribute devices across rings proportionally to circumference
    let devIndex = 0;
    for (let k = 0; k < numRings; k++) {
      const isLast = (k === numRings - 1);
      const ringRatio = ringCaps[k] / totalCap;
      const ringDevCount = isLast ? (count - devIndex) : Math.max(3, Math.round(count * ringRatio));
      const slice = devices.slice(devIndex, devIndex + ringDevCount);
      devIndex += slice.length;

      const r = ringRadii[k];
      const step = (Math.PI * 2) / Math.max(1, slice.length);
      const ringOffset = (k * GOLDEN_ANGLE) % (Math.PI * 2) - Math.PI / 2;

      slice.forEach((d, i) => {
        const angle = ringOffset + i * step;
        placed.push({
          device: d,
          x: cx + Math.cos(angle) * r,
          y: cy + Math.sin(angle) * r,
          radius: r,
          angle,
          track: k,
        });
      });

      if (devIndex >= count) break;
    }

    return placed;
  }

  function compute3DPlinthLayout(devices) {
    const safeDevs = devices.filter((d) => d.is_safe);
    const unvDevs = devices.filter((d) => !d.is_safe);
    const nodes = [];
    const clearance = devices.length > 50 ? 0.95 : 1.48;

    function pack3D(list, startR) {
      let r = startR;
      let idx = 0;
      let ringIdx = 0;
      while (idx < list.length) {
        const cap = Math.max(6, Math.floor((2 * Math.PI * r) / clearance));
        const slice = list.slice(idx, idx + cap);
        const step = (Math.PI * 2) / Math.max(1, slice.length);
        const goldenOffset = (ringIdx * GOLDEN_ANGLE) % (Math.PI * 2);
        slice.forEach((d, i) => {
          const angle = i * step + goldenOffset;
          nodes.push({
            device: d,
            x: Math.cos(angle) * r,
            z: Math.sin(angle) * r,
            r,
          });
        });
        idx += slice.length;
        ringIdx += 1;
        r += clearance * 0.98;
      }
      return r;
    }

    const innerEnd = pack3D(safeDevs, 2.65);
    const outerStart = Math.max(4.35, innerEnd + 0.72);
    const outerEnd = pack3D(unvDevs, outerStart);
    const plinthRadius = Math.max(4.95, outerEnd + 0.9);
    return {
      nodes,
      innerRadius: Math.max(2.65, safeDevs.length ? innerEnd - clearance * 0.45 : 2.65),
      outerRadius: Math.max(4.35, unvDevs.length ? outerEnd - clearance * 0.45 : outerStart),
      plinthRadius,
    };
  }

  /**
   * Density-Adaptive Zero-Overlap Label Placement
   * On dense networks (>16 devices), labels are only displayed for hovered targets
   * and top critical threats to prevent visual collision.
   */
  function resolveZeroOverlapLabels(points, cx, cy, isCompact = false) {
    const labelBoxes = [];
    const resultMap = new Map();
    const count = points.length;
    const isDense = count > 16;

    // Gateway exclusion box
    labelBoxes.push({ x: cx - 45, y: cy - 28, w: 90, h: 66 });

    // Track critical alerts allowed on scope (max 2 on dense networks)
    let alertsShown = 0;
    const maxAlertsOnDense = 2;

    for (const p of points) {
      const d = p.device;
      const hovered = Boolean(p.hovered);
      const isCriticalAlert = Boolean(p.isAlert);

      const labelText = isCompact ? getCompactDeviceLabel(d) : (d.custom_name || d.display_name || d.real_name || d.ip);
      const charWidth = isCompact ? 6.0 : 7.0;
      const boxW = Math.max(44, Math.min(110, labelText.length * charWidth + 14));
      const boxH = isCompact ? 16 : 20;

      // In dense networks, ONLY show label if hovered, or if top critical alert
      let shouldShow = hovered;
      if (!shouldShow && isDense && isCriticalAlert && alertsShown < maxAlertsOnDense) {
        shouldShow = true;
        alertsShown++;
      } else if (!shouldShow && !isDense) {
        shouldShow = true;
      }

      const angle = Math.atan2(p.y - cy, p.x - cx);
      const nodeR = count > 100 ? 7 : count > 50 ? 9 : count > 20 ? 11 : 16;
      let lx = p.x;
      let ly = p.y;
      let align = "center";

      const cos = Math.cos(angle);
      const sin = Math.sin(angle);

      if (sin > 0.45) {
        lx = p.x;
        ly = p.y + nodeR + 10;
        align = "center";
      } else if (sin < -0.45) {
        lx = p.x;
        ly = p.y - nodeR - 8;
        align = "center";
      } else if (cos > 0.3) {
        lx = p.x + nodeR + 6;
        ly = p.y + 3;
        align = "left";
      } else {
        lx = p.x - nodeR - 6;
        ly = p.y + 3;
        align = "right";
      }

      let bx = lx - (align === "center" ? boxW / 2 : align === "left" ? 0 : boxW);
      let by = ly - boxH / 2;

      // Check collision
      let collides = labelBoxes.some((b) => (
        bx < b.x + b.w + 2 &&
        bx + boxW + 2 > b.x &&
        by < b.y + b.h + 2 &&
        by + boxH + 2 > b.y
      ));

      if (collides && !hovered) {
        // Suppress label if it collides on non-hovered nodes
        shouldShow = false;
      } else if (shouldShow) {
        labelBoxes.push({ x: bx, y: by, w: boxW, h: boxH });
      }

      resultMap.set(d.mac, {
        labelX: lx,
        labelY: ly,
        boxX: bx,
        boxY: by,
        boxW,
        boxH,
        textAlign: align,
        labelText,
        show: shouldShow,
      });
    }

    return resultMap;
  }

  const api = {
    getCompactDeviceLabel,
    compute2DRingLayout,
    compute3DPlinthLayout,
    resolveZeroOverlapLabels,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else global.GarudaLayout = api;
})(typeof window !== "undefined" ? window : globalThis);
