/**
 * GARUDA v4 — Studio PBR 3D Spatial Network Topology (High-Scale Multi-Ring Engine)
 * 
 * Features:
 * - Shared Multi-Ring Collision-Free Polar Layout Engine (minSpacing3D = 1.35 world units)
 * - Deterministic 3-Band Trust Separation (Safe Inner -> Unverified Middle -> Alert Outer Perimeter)
 * - Dynamic Plinth, Rings, Camera, and OrbitControls auto-framing from N=5 to N=1,000+
 * - Dual Rendering Pipeline:
 *    * Rich sculpted 3D silhouettes for N <= 60 (laptops, phones, tvs, printers, IoT)
 *    * GPU-accelerated THREE.InstancedMesh batches + merged THREE.LineSegments for N > 60 (locked 60 FPS!)
 * - Raycaster instanceId hit-testing for seamless tooltips and click-to-inspect at 1,000 devices
 * - AgXToneMapping, PMREM softbox lighting, and dynamic ML anomaly halos
 */

export async function mountGarudaTopology3D(containerEl, hooks) {
  const THREE = await import("https://esm.sh/three@0.170.0");
  const { OrbitControls } = await import("https://esm.sh/three@0.170.0/examples/jsm/controls/OrbitControls.js");
  const { RoomEnvironment } = await import("https://esm.sh/three@0.170.0/examples/jsm/environments/RoomEnvironment.js");

  const layoutEngine = window.GarudaLayoutEngine;

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.toneMapping = THREE.AgXToneMapping;
  renderer.toneMappingExposure = 1.08;
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.domElement.style.width = "100%";
  renderer.domElement.style.height = "100%";
  renderer.domElement.style.display = "block";
  containerEl.innerHTML = "";
  containerEl.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;

  const camera = new THREE.PerspectiveCamera(35, 1, 0.1, 300);
  camera.setFocalLength(60);
  camera.position.set(0, 8.5, 12.5);

  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.06;
  controls.minDistance = 3.5;
  controls.maxDistance = 60;
  controls.maxPolarAngle = Math.PI * 0.46;
  controls.target.set(0, 0.35, 0);

  // Calibrated Architectural Studio Lighting
  const hemi = new THREE.HemisphereLight(0xfaf8f4, 0x262b36, 0.75);
  scene.add(hemi);
  const key = new THREE.DirectionalLight(0xfff7ea, 1.4);
  key.position.set(8, 16, 9);
  scene.add(key);

  // Base Architectural Drafting Platform
  const gridGroup = new THREE.Group();
  scene.add(gridGroup);

  const ringGroup = new THREE.Group();
  gridGroup.add(ringGroup);

  const plinthBaseRadius = 5.0;
  const plinthDisk = new THREE.Mesh(
    new THREE.CylinderGeometry(plinthBaseRadius - 0.05, plinthBaseRadius + 0.05, 0.14, 96),
    new THREE.MeshPhysicalMaterial({ color: 0xe6e1d7, roughness: 0.78, metalness: 0.06, clearcoat: 0.12 })
  );
  plinthDisk.position.y = -0.09;
  gridGroup.add(plinthDisk);

  // Expanding Radar Sweep Ring on Plinth Plane
  const sweepMat = new THREE.MeshBasicMaterial({
    color: 0x1e4fd6,
    transparent: true,
    opacity: 0.25,
    side: THREE.DoubleSide,
  });
  const sweepRing = new THREE.Mesh(new THREE.RingGeometry(0.52, 0.62, 64), sweepMat);
  sweepRing.rotation.x = -Math.PI / 2;
  sweepRing.position.y = 0.01;
  scene.add(sweepRing);

  // Central Router Monolith
  const routerGroup = new THREE.Group();
  const routerBody = new THREE.Mesh(
    new THREE.CylinderGeometry(0.52, 0.62, 1.15, 32),
    new THREE.MeshPhysicalMaterial({ color: 0x1e4fd6, metalness: 0.62, roughness: 0.28, clearcoat: 0.5 })
  );
  routerBody.position.y = 0.58;
  const routerCap = new THREE.Mesh(
    new THREE.TorusGeometry(0.54, 0.05, 16, 48),
    new THREE.MeshStandardMaterial({ color: 0xf4f1ea, metalness: 0.8, roughness: 0.2 })
  );
  routerCap.rotation.x = Math.PI / 2;
  routerCap.position.y = 1.12;
  routerGroup.add(routerBody, routerCap);
  scene.add(routerGroup);

  const dynamicGroup = new THREE.Group();
  scene.add(dynamicGroup);

  let interactables = [];
  let packets = [];
  let halos = [];
  let currentThemeDark = false;
  let visible = true;
  let animId = 0;
  let currentOuterRadius = 6.0;

  function makeRingTorus(radius, colorHex, opacity = 0.45, thickness = 0.022) {
    const geo = new THREE.TorusGeometry(radius, thickness, 16, Math.min(256, Math.max(64, Math.floor(radius * 16))));
    const mat = new THREE.MeshStandardMaterial({
      color: colorHex,
      roughness: 0.35,
      metalness: 0.5,
      transparent: true,
      opacity,
    });
    const m = new THREE.Mesh(geo, mat);
    m.rotation.x = Math.PI / 2;
    return m;
  }

  // High-fidelity sculpted models for N <= 60
  function buildDeviceMesh(deviceType, colorHex) {
    const mat = new THREE.MeshPhysicalMaterial({
      color: colorHex,
      metalness: 0.45,
      roughness: 0.32,
      clearcoat: 0.45,
      clearcoatRoughness: 0.25,
    });
    const accentMat = new THREE.MeshStandardMaterial({ color: 0xfaf8f4, metalness: 0.7, roughness: 0.25 });
    const g = new THREE.Group();

    if (deviceType === "laptop") {
      const base = new THREE.Mesh(new THREE.BoxGeometry(0.68, 0.06, 0.48), mat);
      base.position.y = 0.04;
      const lid = new THREE.Mesh(new THREE.BoxGeometry(0.66, 0.42, 0.04), mat);
      lid.position.set(0, 0.26, -0.22);
      lid.rotation.x = -0.18;
      g.add(base, lid);
    } else if (deviceType === "phone" || deviceType === "tablet") {
      const w = deviceType === "tablet" ? 0.52 : 0.28;
      const h = deviceType === "tablet" ? 0.66 : 0.54;
      const slab = new THREE.Mesh(new THREE.BoxGeometry(w, h, 0.06), mat);
      slab.position.y = h / 2 + 0.06;
      g.add(slab);
    } else if (deviceType === "tv") {
      const scr = new THREE.Mesh(new THREE.BoxGeometry(0.86, 0.5, 0.06), mat);
      scr.position.y = 0.36;
      const stand = new THREE.Mesh(new THREE.CylinderGeometry(0.18, 0.24, 0.1, 16), accentMat);
      stand.position.y = 0.05;
      g.add(scr, stand);
    } else if (deviceType === "printer") {
      const body = new THREE.Mesh(new THREE.BoxGeometry(0.64, 0.34, 0.52), mat);
      body.position.y = 0.18;
      const tray = new THREE.Mesh(new THREE.BoxGeometry(0.42, 0.05, 0.28), accentMat);
      tray.position.set(0, 0.38, -0.06);
      g.add(body, tray);
    } else if (deviceType === "iot") {
      const cyl = new THREE.Mesh(new THREE.CylinderGeometry(0.26, 0.3, 0.44, 24), mat);
      cyl.position.y = 0.22;
      g.add(cyl);
    } else {
      const oct = new THREE.Mesh(new THREE.OctahedronGeometry(0.36, 0), mat);
      oct.position.y = 0.42;
      g.add(oct);
    }
    return g;
  }

  function applyTheme(isDark) {
    currentThemeDark = isDark;
    plinthDisk.material.color.setHex(isDark ? 0x1a1e26 : 0xe8e3da);
    plinthDisk.material.roughness = isDark ? 0.62 : 0.78;
    scene.background = new THREE.Color(isDark ? 0x12151b : 0xf3f0ea);
  }

  function updateSnapshot(snap) {
    if (!snap) return;

    // Clear previous dynamic children
    while (dynamicGroup.children.length) dynamicGroup.remove(dynamicGroup.children[0]);
    while (ringGroup.children.length) ringGroup.remove(ringGroup.children[0]);
    interactables = [];
    packets = [];
    halos = [];

    const hasCrit = (snap.alerts || []).some((a) => !a.resolved && a.severity === "critical");
    const routerColorHex = hasCrit ? 0xc53624 : currentThemeDark ? 0x6394f2 : 0x1e4fd6;
    routerBody.material.color.setHex(routerColorHex);
    sweepMat.color.setHex(routerColorHex);

    const online = (snap.devices || []).filter((d) => d && d.is_online !== false);
    if (!online.length) return;

    // Run shared Multi-Ring Polar Layout Engine with minSpacing3D = 1.35
    const engine = window.GarudaLayoutEngine || layoutEngine;
    const layout = engine.computePolarLayout(online, snap.alerts || [], snap.ml?.device_scores || [], {
      mode: "3d",
      minNodeSpacing: 1.35,
      centerRouterRadius: 0.65,
      ringStep: 1.45,
      bandMargin: 1.85,
    });

    currentOuterRadius = layout.outerRadius;

    // Dynamically resize plinth disk
    const targetPlinthRadius = Math.max(5.2, layout.outerRadius + 1.8);
    plinthDisk.scale.set(targetPlinthRadius / plinthBaseRadius, 1, targetPlinthRadius / plinthBaseRadius);

    // Dynamically generate trust boundary rings
    const bandRingsMap = new Map();
    layout.rings.forEach((r) => {
      if (!bandRingsMap.has(r.band)) bandRingsMap.set(r.band, []);
      bandRingsMap.get(r.band).push(r.radius);
    });

    // Ring colors by band
    const colorSafe = currentThemeDark ? 0x3eb488 : 0x157f56;
    const colorWarn = currentThemeDark ? 0xe2a343 : 0xb96b08;
    const colorAlert = currentThemeDark ? 0xe36050 : 0xc53624;

    bandRingsMap.forEach((radii, band) => {
      const bandColor = band === "C" ? colorAlert : band === "B" ? colorWarn : colorSafe;
      // Draw outer boundary ring of each band with clear styling
      const minR = Math.min(...radii);
      const maxR = Math.max(...radii);
      ringGroup.add(makeRingTorus(minR, bandColor, 0.42, 0.024));
      if (maxR > minR) {
        ringGroup.add(makeRingTorus(maxR, bandColor, 0.52, 0.028));
      }
    });

    // Update Gateway router userData
    if (layout.gateway) {
      const mlMap = new Map((snap.ml?.device_scores || []).map((m) => [m.mac.toUpperCase(), m]));
      routerBody.userData = { device: layout.gateway, ml: mlMap.get(layout.gateway.mac.toUpperCase()) };
      interactables.push(routerBody);
    }

    const totalCount = layout.nodes.length;
    const isHighScale = totalCount > 60;

    if (!isHighScale) {
      // -------------------------------------------------------------
      // SCULPTED FIDELITY PIPELINE (N <= 60)
      // -------------------------------------------------------------
      layout.nodes.forEach((node, idx) => {
        const d = node.device;
        const colorHex = node.isAlert ? colorAlert : node.isSafe ? colorSafe : colorWarn;

        const nodeGroup = buildDeviceMesh(d.device_type, colorHex);
        nodeGroup.position.set(node.x, 0.02, node.z);
        nodeGroup.lookAt(0, 0.02, 0);

        nodeGroup.traverse((child) => {
          if (child.isMesh) {
            child.userData = { device: d, ml: node.ml, isAlert: node.isAlert };
            interactables.push(child);
          }
        });
        dynamicGroup.add(nodeGroup);

        // ML Anomaly Halo
        if (node.isAlert || (node.ml && node.ml.anomaly_score >= 38)) {
          const score = node.ml ? node.ml.anomaly_score : 85;
          const haloMat = new THREE.MeshBasicMaterial({
            color: score >= 70 ? colorAlert : colorWarn,
            transparent: true,
            opacity: 0.45,
            side: THREE.DoubleSide,
          });
          const halo = new THREE.Mesh(new THREE.RingGeometry(0.48, 0.68, 32), haloMat);
          halo.rotation.x = -Math.PI / 2;
          halo.position.set(node.x, 0.03, node.z);
          halo.userData = { baseScale: 1 + score / 180 };
          dynamicGroup.add(halo);
          halos.push(halo);
        }

        // Parabolic Bezier data arc
        const start = new THREE.Vector3(0, 0.72, 0);
        const mid = new THREE.Vector3(node.x * 0.5, node.isAlert ? 2.25 : 1.55, node.z * 0.5);
        const end = new THREE.Vector3(node.x, 0.35, node.z);
        const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
        const arcGeo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(24));
        const arcLine = new THREE.Line(
          arcGeo,
          new THREE.LineBasicMaterial({ color: colorHex, transparent: true, opacity: node.isAlert ? 0.65 : 0.32 })
        );
        dynamicGroup.add(arcLine);

        // Traveling packet sphere
        const pkt = new THREE.Mesh(
          new THREE.SphereGeometry(node.isAlert ? 0.085 : 0.06, 12, 12),
          new THREE.MeshBasicMaterial({ color: colorHex })
        );
        dynamicGroup.add(pkt);
        packets.push({ mesh: pkt, curve, speed: node.isAlert ? 0.55 : 0.28, offset: idx * 0.21 });
      });
    } else {
      // -------------------------------------------------------------
      // GPU INSTANCED PIPELINE FOR HIGH SCALE (N > 60 up to 1,000+)
      // -------------------------------------------------------------
      const instancedPuckGeo = new THREE.CylinderGeometry(0.38, 0.44, 0.32, 16);
      const dummy = new THREE.Object3D();

      const batches = [
        { band: "A", colorHex: colorSafe, nodes: layout.nodes.filter((n) => n.band === "A") },
        { band: "B", colorHex: colorWarn, nodes: layout.nodes.filter((n) => n.band === "B") },
        { band: "C", colorHex: colorAlert, nodes: layout.nodes.filter((n) => n.band === "C") },
      ];

      batches.forEach((b) => {
        if (!b.nodes.length) return;
        const mat = new THREE.MeshPhysicalMaterial({
          color: b.colorHex,
          metalness: 0.48,
          roughness: 0.3,
          clearcoat: 0.45,
        });

        const instMesh = new THREE.InstancedMesh(instancedPuckGeo, mat, b.nodes.length);
        instMesh.instanceMatrix.setUsage(THREE.StaticDrawUsage);

        const instanceMap = [];

        b.nodes.forEach((node, idx) => {
          dummy.position.set(node.x, 0.16, node.z);
          dummy.lookAt(0, 0.16, 0);
          dummy.updateMatrix();
          instMesh.setMatrixAt(idx, dummy.matrix);

          instanceMap.push({
            device: node.device,
            ml: node.ml,
            isAlert: node.isAlert,
          });

          // ML halos for alert devices in high-scale
          if (node.isAlert && halos.length < 50) {
            const haloMat = new THREE.MeshBasicMaterial({
              color: colorAlert,
              transparent: true,
              opacity: 0.5,
              side: THREE.DoubleSide,
            });
            const halo = new THREE.Mesh(new THREE.RingGeometry(0.48, 0.68, 24), haloMat);
            halo.rotation.x = -Math.PI / 2;
            halo.position.set(node.x, 0.03, node.z);
            halo.userData = { baseScale: 1.25 };
            dynamicGroup.add(halo);
            halos.push(halo);
          }
        });

        instMesh.instanceMatrix.needsUpdate = true;
        instMesh.userData = { isInstanced: true, instanceMap };
        interactables.push(instMesh);
        dynamicGroup.add(instMesh);
      });

      // Single Merged LineSegments BufferGeometry for all 1,000 connection arcs
      const SAMPLES = 8;
      const segCount = (SAMPLES - 1) * layout.nodes.length;
      const positions = new Float32Array(segCount * 6);
      const colors = new Float32Array(segCount * 6);

      const pStart = new THREE.Vector3(0, 0.72, 0);
      let ptr = 0;

      layout.nodes.forEach((node) => {
        const pMid = new THREE.Vector3(node.x * 0.5, node.isAlert ? 2.25 : 1.55, node.z * 0.5);
        const pEnd = new THREE.Vector3(node.x, 0.28, node.z);
        const curve = new THREE.QuadraticBezierCurve3(pStart, pMid, pEnd);
        const pts = curve.getPoints(SAMPLES - 1);

        const c = new THREE.Color(node.isAlert ? colorAlert : node.isSafe ? colorSafe : colorWarn);

        for (let i = 0; i < pts.length - 1; i++) {
          const ptA = pts[i];
          const ptB = pts[i + 1];

          positions[ptr] = ptA.x;
          positions[ptr + 1] = ptA.y;
          positions[ptr + 2] = ptA.z;
          colors[ptr] = c.r;
          colors[ptr + 1] = c.g;
          colors[ptr + 2] = c.b;

          positions[ptr + 3] = ptB.x;
          positions[ptr + 4] = ptB.y;
          positions[ptr + 5] = ptB.z;
          colors[ptr + 3] = c.r;
          colors[ptr + 4] = c.g;
          colors[ptr + 5] = c.b;

          ptr += 6;
        }
      });

      const linesGeo = new THREE.BufferGeometry();
      linesGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
      linesGeo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
      const linesMat = new THREE.LineBasicMaterial({
        vertexColors: true,
        transparent: true,
        opacity: 0.38,
      });
      const mergedLines = new THREE.LineSegments(linesGeo, linesMat);
      dynamicGroup.add(mergedLines);

      // Traveling packet spheres capped to active alerts + top 35 active devices
      const priorityNodes = layout.nodes
        .filter((n) => n.isAlert)
        .concat(layout.nodes.filter((n) => !n.isAlert).slice(0, 35));

      priorityNodes.forEach((node, idx) => {
        const colorHex = node.isAlert ? colorAlert : node.isSafe ? colorSafe : colorWarn;
        const mid = new THREE.Vector3(node.x * 0.5, node.isAlert ? 2.25 : 1.55, node.z * 0.5);
        const end = new THREE.Vector3(node.x, 0.28, node.z);
        const curve = new THREE.QuadraticBezierCurve3(pStart, mid, end);

        const pkt = new THREE.Mesh(
          new THREE.SphereGeometry(node.isAlert ? 0.085 : 0.06, 10, 10),
          new THREE.MeshBasicMaterial({ color: colorHex })
        );
        dynamicGroup.add(pkt);
        packets.push({ mesh: pkt, curve, speed: node.isAlert ? 0.55 : 0.28, offset: idx * 0.21 });
      });
    }

    // Dynamic camera auto-framing
    const camDist = Math.max(11, layout.outerRadius * 1.85);
    controls.maxDistance = Math.max(25, layout.outerRadius * 3.5);
    controls.target.set(0, 0.35, 0);
  }

  // Raycaster Hover & Click with InstancedMesh instanceId support
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();

  function pickHit(clientX, clientY) {
    const rect = renderer.domElement.getBoundingClientRect();
    pointer.x = ((clientX - rect.left) / rect.width) * 2 - 1;
    pointer.y = -((clientY - rect.top) / rect.height) * 2 + 1;
    raycaster.setFromCamera(pointer, camera);

    const hits = raycaster.intersectObjects(interactables, false);
    if (!hits.length) return null;

    const hit = hits[0];
    if (hit.object.userData?.isInstanced && hit.instanceId !== undefined) {
      const data = hit.object.userData.instanceMap[hit.instanceId];
      return data || null;
    }
    return hit.object.userData || null;
  }

  renderer.domElement.addEventListener("pointermove", (e) => {
    const hit = pickHit(e.clientX, e.clientY);
    renderer.domElement.style.cursor = hit ? "pointer" : "grab";
    if (hooks?.onHover) hooks.onHover(hit, e.clientX, e.clientY);
  });

  renderer.domElement.addEventListener("pointerleave", () => {
    if (hooks?.onHover) hooks.onHover(null, 0, 0);
  });

  let downX = 0;
  let downY = 0;
  renderer.domElement.addEventListener("pointerdown", (e) => {
    downX = e.clientX;
    downY = e.clientY;
  });
  renderer.domElement.addEventListener("pointerup", (e) => {
    if (Math.hypot(e.clientX - downX, e.clientY - downY) > 6) return;
    const hit = pickHit(e.clientX, e.clientY);
    if (hit?.device && hooks?.onSelect) hooks.onSelect(hit.device);
  });

  function resize() {
    const rect = containerEl.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    camera.aspect = rect.width / rect.height;
    camera.updateProjectionMatrix();
    renderer.setSize(rect.width, rect.height, false);
  }
  const ro = new ResizeObserver(resize);
  ro.observe(containerEl);

  const io = new IntersectionObserver((entries) => {
    visible = entries[0]?.isIntersecting ?? true;
  });
  io.observe(containerEl);

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let phase = 0;

  function animate() {
    animId = requestAnimationFrame(animate);
    if (!visible) return;
    phase += reducedMotion ? 0.002 : 0.011;

    // Expanding sweep ring
    const s = 1 + ((phase * 0.65) % 1) * Math.max(9.0, currentOuterRadius * 1.5);
    sweepRing.scale.set(s, s, 1);
    sweepMat.opacity = Math.max(0, 0.26 * (1 - ((phase * 0.65) % 1)));

    // Traveling packets
    for (let i = 0; i < packets.length; i++) {
      const p = packets[i];
      const t = (phase * p.speed + p.offset) % 1;
      p.curve.getPoint(t, p.mesh.position);
    }

    // Anomaly halos
    for (let i = 0; i < halos.length; i++) {
      const h = halos[i];
      const pulse = h.userData.baseScale + Math.sin(phase * 4.5) * 0.12;
      h.scale.set(pulse, pulse, 1);
    }

    controls.update();
    renderer.render(scene, camera);
  }

  applyTheme(document.body.classList.contains("theme-dark"));
  resize();
  animate();

  return {
    updateSnapshot,
    applyTheme,
    resetCamera: () => {
      const targetDist = Math.max(11, currentOuterRadius * 1.85);
      camera.position.set(0, targetDist * 0.65, targetDist * 0.85);
      controls.target.set(0, 0.35, 0);
      controls.update();
    },
    destroy: () => {
      cancelAnimationFrame(animId);
      ro.disconnect();
      io.disconnect();
      renderer.dispose();
    },
  };
}
