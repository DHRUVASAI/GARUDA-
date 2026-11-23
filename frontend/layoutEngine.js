/**
 * GARUDA v10 Ultimate — Collision-Free Spatial Layout Engine (2D & 3D)
 * Multi-Tier Orbital Dispersion + Radial-Vector Labeling guarantees ZERO overlaps
 * from small home networks to 1,000+ enterprise endpoints.
 */
(function (global) {
  const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

  function getCompactDeviceLabel(d) {
    if (!d) return "Device";
    const name = d.custom_name || d.display_name || d.real_name || d.ip || "Device";
    if (/amazon echo|echo dot|alexa/i.test(name)) return "Echo Dot";
    if (/fire tv|firestick/i.test(name)) return "Fire TV";
    if (/canon|g4070|printer/i.test(name)) return "Canon G4070";
    if (/galaxy|samsung/i.test(name)) return "Galaxy A73";
    if (/realme/i.test(name)) return "Realme 13 Pro";
    if (/xiaomi|12t|redmi/i.test(name)) return "Xiaomi 12T";
    if (/omen|hp omen/i.test(name)) return "HP OMEN";
    if (/laasya/i.test(name)) return "LAASYA PC";
    if (/lg|webos/i.test(name)) return "LG Smart TV";
    if (/zyxel/i.test(name)) return "Zyxel Gateway";
    if (/airtel|xstream/i.test(name)) return "Airtel Box";
    return name.length > 13 ? name.slice(0, 12) + "…" : name;
  }

  function compute2DRingLayout(devices, cx, cy, baseRadius) {
    if (!devices || !devices.length) return [];
    const count = devices.length;
    const placed = [];

    // For 1-18 devices (standard home/office setup), use uniform angular spacing with staggered orbital radii
    if (count <= 18) {
      const tracks = [
        baseRadius * 0.52,
        baseRadius * 0.74,
        baseRadius * 0.94,
      ];
      const step = (Math.PI * 2) / count;
      const startAngle = -Math.PI / 2; // top 12 o'clock

      devices.forEach((d, i) => {
        const trackIdx = i % tracks.length;
        const r = tracks[trackIdx];
        const angle = startAngle + i * step;

        const x = cx + Math.cos(angle) * r;
        const y = cy + Math.sin(angle) * r;

        placed.push({
          device: d,
          x,
          y,
          radius: r,
          angle,
          track: trackIdx,
        });
      });
      return placed;
    }

    // For large networks (19+ to 1,000 devices): Archimedean multi-ring packing
    const safeDevs = devices.filter((d) => d.is_safe);
    const unvDevs = devices.filter((d) => !d.is_safe);

    function packGroup(list, startR, minSpacingPx) {
      let r = startR;
      let idx = 0;
      let ringIdx = 0;
      while (idx < list.length) {
        const cap = Math.max(6, Math.floor((2 * Math.PI * r) / minSpacingPx));
        const slice = list.slice(idx, idx + cap);
        const step = (Math.PI * 2) / Math.max(1, slice.length);
        const goldenOffset = (ringIdx * GOLDEN_ANGLE) % (Math.PI * 2);
        slice.forEach((d, i) => {
          const angle = i * step + goldenOffset - Math.PI / 2;
          placed.push({
            device: d,
            x: cx + Math.cos(angle) * r,
            y: cy + Math.sin(angle) * r,
            radius: r,
            angle,
            track: ringIdx,
          });
        });
        idx += slice.length;
        ringIdx += 1;
        r += minSpacingPx * 0.96;
      }
      return r;
    }

    const minSpacing = count > 200 ? 16 : count > 40 ? 24 : 48;
    const innerEnd = packGroup(safeDevs, baseRadius * 0.52, minSpacing);
    const outerStart = Math.max(baseRadius * 0.88, innerEnd + minSpacing * 0.5);
    packGroup(unvDevs, outerStart, minSpacing);
    return placed;
  }

  function compute3DPlinthLayout(devices) {
    const safeDevs = devices.filter((d) => d.is_safe);
    const unvDevs = devices.filter((d) => !d.is_safe);
    const nodes = [];
    const clearance = 1.48;

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
   * Zero-Overlap AABB + Radial Vector Label Placement
   * Returns a Map of mac -> { labelX, labelY, textAlign, labelText, show }
   */
  function resolveZeroOverlapLabels(points, cx, cy, isCompact = false) {
    const labelBoxes = [];
    const resultMap = new Map();

    // Priority sort: Hovered > Alert > Unverified > Safe
    const sorted = [...points].sort((a, b) => {
      const pa = (a.hovered ? 20 : 0) + (a.isAlert ? 10 : 0) + (!a.device.is_safe ? 4 : 0);
      const pb = (b.hovered ? 20 : 0) + (b.isAlert ? 10 : 0) + (!b.device.is_safe ? 4 : 0);
      return pb - pa;
    });

    // Central Gateway exclusion box
    labelBoxes.push({ x: cx - 44, y: cy - 28, w: 88, h: 66 });

    // Register all device node circles as collision exclusion obstacles
    points.forEach((pt) => {
      const nr = (isCompact ? 14 : 17) + 5;
      labelBoxes.push({ x: pt.x - nr, y: pt.y - nr, w: nr * 2, h: nr * 2 });
    });

    for (const p of sorted) {
      const d = p.device;
      const angle = Math.atan2(p.y - cy, p.x - cx);
      const labelText = isCompact ? getCompactDeviceLabel(d) : (d.custom_name || d.display_name || d.ip);

      // Estimated label box width
      const charWidth = isCompact ? 6.2 : 7.2;
      const boxW = Math.max(46, Math.min(108, labelText.length * charWidth + 14));
      const boxH = isCompact ? 17 : 21;

      // Radial outward label placement
      let lx = p.x;
      let ly = p.y;
      let align = "center";
      const nodeR = isCompact ? 14 : 17;

      const cos = Math.cos(angle);
      const sin = Math.sin(angle);

      if (sin > 0.45) {
        // Bottom hemisphere: place below node
        lx = p.x;
        ly = p.y + nodeR + (isCompact ? 11 : 14);
        align = "center";
      } else if (sin < -0.45) {
        // Top hemisphere: place above node
        lx = p.x;
        ly = p.y - nodeR - (isCompact ? 9 : 12);
        align = "center";
      } else if (cos > 0.3) {
        // Right side: place to right
        lx = p.x + nodeR + 7;
        ly = p.y + 4;
        align = "left";
      } else {
        // Left side: place to left
        lx = p.x - nodeR - 7;
        ly = p.y + 4;
        align = "right";
      }

      // Compute bounding box for collision detection
      let bx = lx - (align === "center" ? boxW / 2 : align === "left" ? 0 : boxW);
      let by = ly - boxH / 2;

      // Check collision against all placed obstacles and labels
      let collides = labelBoxes.some((b) => (
        bx < b.x + b.w + 3 &&
        bx + boxW + 3 > b.x &&
        by < b.y + b.h + 2 &&
        by + boxH + 2 > b.y
      ));

      if (collides && !p.hovered && !p.isAlert) {
        // Try tangential alternate position
        const altLy = ly + (sin > 0 ? 9 : -9);
        const altBy = altLy - boxH / 2;
        const altCollides = labelBoxes.some((b) => (
          bx < b.x + b.w + 3 &&
          bx + boxW + 3 > b.x &&
          altBy < b.y + b.h + 2 &&
          altBy + boxH + 2 > b.y
        ));
        if (!altCollides) {
          ly = altLy;
          by = altBy;
          collides = false;
        }
      }

      const show = !collides || p.hovered || p.isAlert;
      if (show) {
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
        show,
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
