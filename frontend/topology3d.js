/**
 * GARUDA v4 — Studio PBR 3D Spatial Network Topology (Fault-Isolated ES Module)
 * Uses AgXToneMapping, PMREMGenerator RoomEnvironment softboxes, 65mm product optics,
 * sculpted per-device silhouettes, concentric trust plates, curved animated packet arcs,
 * dynamic ML anomaly halos, OrbitControls, and Raycaster click-to-inspect.
 */

export async function mountGarudaTopology3D(containerEl, hooks) {
  const THREE = await import("https://esm.sh/three@0.170.0");
  const { OrbitControls } = await import("https://esm.sh/three@0.170.0/examples/jsm/controls/OrbitControls.js");
  const { RoomEnvironment } = await import("https://esm.sh/three@0.170.0/examples/jsm/environments/RoomEnvironment.js");

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

  const camera = new THREE.PerspectiveCamera(35, 1, 0.1, 100);
  camera.setFocalLength(60);
  camera.position.set(0, 7.6, 10.6);

  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.06;
  controls.minDistance = 5.5;
  controls.maxDistance = 18;
  controls.maxPolarAngle = Math.PI * 0.46;
  controls.target.set(0, 0.35, 0);

  // Subtle calibrated architectural lighting
  const hemi = new THREE.HemisphereLight(0xfaf8f4, 0x262b36, 0.75);
  scene.add(hemi);
  const key = new THREE.DirectionalLight(0xfff7ea, 1.35);
  key.position.set(6, 11, 7);
  scene.add(key);

  // Base architectural drafting rings (Safe Inner Ring & Unverified Outer Ring)
  const gridGroup = new THREE.Group();
  scene.add(gridGroup);

  const makeRing = (radius, colorHex, opacity = 0.42, thickness = 0.025) => {
    const geo = new THREE.TorusGeometry(radius, thickness, 16, 128);
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
  };

  const innerRing = makeRing(2.65, 0x157f56, 0.55, 0.022);
  const outerRing = makeRing(4.35, 0xb96b08, 0.45, 0.02);
  const plinthDisk = new THREE.Mesh(
    new THREE.CylinderGeometry(4.95, 5.05, 0.12, 72),
    new THREE.MeshPhysicalMaterial({ color: 0xe6e1d7, roughness: 0.78, metalness: 0.06, clearcoat: 0.12 })
  );
  plinthDisk.position.y = -0.08;
  gridGroup.add(plinthDisk, innerRing, outerRing);

  // Expanding radar sweep ring on plinth plane
  const sweepMat = new THREE.MeshBasicMaterial({ color: 0x1e4fd6, transparent: true, opacity: 0.25, side: THREE.DoubleSide });
  const sweepRing = new THREE.Mesh(new THREE.RingGeometry(0.45, 0.52, 64), sweepMat);
  sweepRing.rotation.x = -Math.PI / 2;
  sweepRing.position.y = 0.01;
  scene.add(sweepRing);

  // Central Router Monolith
  const routerGroup = new THREE.Group();
  const routerBody = new THREE.Mesh(
    new THREE.CylinderGeometry(0.46, 0.56, 1.05, 32),
    new THREE.MeshPhysicalMaterial({ color: 0x1e4fd6, metalness: 0.62, roughness: 0.28, clearcoat: 0.5 })
  );
  routerBody.position.y = 0.52;
  const routerCap = new THREE.Mesh(
    new THREE.TorusGeometry(0.48, 0.045, 16, 48),
    new THREE.MeshStandardMaterial({ color: 0xf4f1ea, metalness: 0.8, roughness: 0.2 })
  );
  routerCap.rotation.x = Math.PI / 2;
  routerCap.position.y = 1.02;
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
    while (dynamicGroup.children.length) dynamicGroup.remove(dynamicGroup.children[0]);
    interactables = [];
    packets = [];
    halos = [];

    const hasCrit = (snap.alerts || []).some((a) => !a.resolved && a.severity === "critical");
    routerBody.material.color.setHex(hasCrit ? 0xc53624 : (currentThemeDark ? 0x6394f2 : 0x1e4fd6));
    sweepMat.color.setHex(hasCrit ? 0xc53624 : (currentThemeDark ? 0x6394f2 : 0x1e4fd6));

    const mlMap = new Map((snap.ml?.device_scores || []).map((m) => [m.mac.toUpperCase(), m]));
    const online = (snap.devices || []).filter((d) => d.is_online);
    const gw = online.find((d) => d.is_gateway) || online[0];
    const others = online.filter((d) => d !== gw);

    if (gw) {
      routerBody.userData = { device: gw, ml: mlMap.get(gw.mac.toUpperCase()) };
      interactables.push(routerBody);
    }

    others.forEach((d, idx) => {
      const angle = (idx / Math.max(1, others.length)) * Math.PI * 2;
      const r = d.is_safe ? 2.65 : 4.35;
      const x = Math.cos(angle) * r;
      const z = Math.sin(angle) * r;

      const ml = mlMap.get(d.mac.toUpperCase());
      const isAlert =
        (snap.alerts || []).some((a) => !a.resolved && (a.related_mac === d.mac || a.related_ip === d.ip)) ||
        (ml && ml.risk_level === "critical");

      const colorHex = isAlert
        ? (currentThemeDark ? 0xe36050 : 0xc53624)
        : d.is_safe
        ? (currentThemeDark ? 0x3eb488 : 0x157f56)
        : (currentThemeDark ? 0xe2a343 : 0xb96b08);

      const nodeGroup = buildDeviceMesh(d.device_type, colorHex);
      nodeGroup.position.set(x, 0.02, z);
      nodeGroup.lookAt(0, 0.02, 0);
      nodeGroup.traverse((child) => {
        if (child.isMesh) {
          child.userData = { device: d, ml };
          interactables.push(child);
        }
      });
      dynamicGroup.add(nodeGroup);

      // ML Anomaly Risk Halo under device when elevated/critical
      if (ml && ml.anomaly_score >= 38) {
        const haloMat = new THREE.MeshBasicMaterial({
          color: ml.anomaly_score >= 70 ? 0xc53624 : 0xb96b08,
          transparent: true,
          opacity: 0.45,
          side: THREE.DoubleSide,
        });
        const halo = new THREE.Mesh(new THREE.RingGeometry(0.45, 0.62, 32), haloMat);
        halo.rotation.x = -Math.PI / 2;
        halo.position.set(x, 0.03, z);
        halo.userData = { baseScale: 1 + (ml.anomaly_score / 180) };
        dynamicGroup.add(halo);
        halos.push(halo);
      }

      // Parabolic Bezier data arc from router to device
      const start = new THREE.Vector3(0, 0.72, 0);
      const mid = new THREE.Vector3(x * 0.5, isAlert ? 2.25 : 1.55, z * 0.5);
      const end = new THREE.Vector3(x, 0.35, z);
      const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
      const arcGeo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(28));
      const arcLine = new THREE.Line(
        arcGeo,
        new THREE.LineBasicMaterial({ color: colorHex, transparent: true, opacity: isAlert ? 0.65 : 0.34 })
      );
      dynamicGroup.add(arcLine);

      // Traveling packet sphere
      const pkt = new THREE.Mesh(
        new THREE.SphereGeometry(isAlert ? 0.085 : 0.06, 12, 12),
        new THREE.MeshBasicMaterial({ color: colorHex })
      );
      dynamicGroup.add(pkt);
      packets.push({ mesh: pkt, curve, speed: isAlert ? 0.55 : 0.28, offset: idx * 0.21 });
    });
  }

  // Raycaster Hover & Click
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();

  function pickHit(clientX, clientY) {
    const rect = renderer.domElement.getBoundingClientRect();
    pointer.x = ((clientX - rect.left) / rect.width) * 2 - 1;
    pointer.y = -((clientY - rect.top) / rect.height) * 2 + 1;
    raycaster.setFromCamera(pointer, camera);
    const hits = raycaster.intersectObjects(interactables, false);
    return hits.length ? hits[0].object.userData : null;
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

    // Gentle sweep ring expansion
    const s = 1 + ((phase * 0.65) % 1) * 9.0;
    sweepRing.scale.set(s, s, 1);
    sweepMat.opacity = Math.max(0, 0.26 * (1 - ((phase * 0.65) % 1)));

    // Traveling data packets along Bezier arcs
    for (const p of packets) {
      const t = (phase * p.speed + p.offset) % 1;
      p.curve.getPoint(t, p.mesh.position);
    }

    // Pulsing ML anomaly halos
    for (const h of halos) {
      const pulse = h.userData.baseScale + Math.sin(phase * 4.5) * 0.14;
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
      camera.position.set(0, 7.6, 10.6);
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
