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

  // Central Router Procedural Gateway Model
  const routerGroup = new THREE.Group();
  const chassisMat = new THREE.MeshPhysicalMaterial({
    color: 0x1a233a,
    metalness: 0.65,
    roughness: 0.28,
    clearcoat: 0.6,
    clearcoatRoughness: 0.2
  });
  const routerBody = new THREE.Mesh(new THREE.BoxGeometry(1.22, 0.26, 0.82), chassisMat);
  routerBody.position.y = 0.16;
  routerGroup.add(routerBody);

  const topPlate = new THREE.Mesh(
    new THREE.BoxGeometry(1.14, 0.04, 0.74),
    new THREE.MeshStandardMaterial({ color: 0x0f172a, roughness: 0.45, metalness: 0.4 })
  );
  topPlate.position.set(0, 0.30, 0);
  routerGroup.add(topPlate);

  const antennaMat = new THREE.MeshStandardMaterial({ color: 0x0b0f19, metalness: 0.7, roughness: 0.3 });
  [-0.42, 0.42].forEach((xOff, i) => {
    const hinge = new THREE.Mesh(new THREE.CylinderGeometry(0.045, 0.045, 0.08, 16), antennaMat);
    hinge.rotation.z = Math.PI / 2;
    hinge.position.set(xOff, 0.26, -0.38);
    const stalk = new THREE.Mesh(new THREE.CylinderGeometry(0.022, 0.032, 0.95, 16), antennaMat);
    stalk.position.set(xOff + (i === 0 ? -0.06 : 0.06), 0.70, -0.42);
    stalk.rotation.z = i === 0 ? 0.12 : -0.12;
    stalk.rotation.x = -0.14;
    routerGroup.add(hinge, stalk);
  });

  const ledColors = [0x00e5ff, 0x3eb488, 0x00e5ff, 0x3eb488, 0x3eb488];
  ledColors.forEach((hex, idx) => {
    const led = new THREE.Mesh(
      new THREE.SphereGeometry(0.02, 12, 12),
      new THREE.MeshBasicMaterial({ color: hex })
    );
    led.position.set(-0.35 + idx * 0.175, 0.16, 0.42);
    routerGroup.add(led);
  });

  const routerHalo = new THREE.Mesh(
    new THREE.TorusGeometry(0.72, 0.025, 16, 64),
    new THREE.MeshBasicMaterial({ color: 0x1e4fd6, transparent: true, opacity: 0.55 })
  );
  routerHalo.rotation.x = Math.PI / 2;
  routerHalo.position.y = 0.02;
  routerGroup.add(routerHalo);
  scene.add(routerGroup);

  const dynamicGroup = new THREE.Group();
  scene.add(dynamicGroup);

  let interactables = [];
  let packets = [];
  let halos = [];
  let animatedFans = [];
  let currentThemeDark = false;
  let visible = true;
  let animId = 0;

  function resolve3DCategory(deviceType, d) {
    if (!d && !deviceType) return "iot";
    const text = `${d?.display_name || ""} ${d?.vendor || ""} ${d?.hostname || ""} ${d?.device_type || deviceType || ""}`.toLowerCase();
    if (/printer|canon|g4070|epson|brother|laserjet|deskjet|pixma/i.test(text)) return "printer";
    if (/alexa|echo|dot|show|amazon speaker/i.test(text)) return "alexa";
    if (/firetv|fire tv|firestick|fire stick|roku|chromecast|apple tv|xstream|iptv/i.test(text)) return "streaming_stick";
    if (text.includes("amazon technologies")) {
      return (d?.ip && d.ip.endsWith(".6")) ? "streaming_stick" : "alexa";
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

  function buildDeviceMesh(deviceType, colorHex, d) {
    const category = resolve3DCategory(deviceType, d);
    const mat = new THREE.MeshPhysicalMaterial({
      color: colorHex,
      metalness: 0.45,
      roughness: 0.32,
      clearcoat: 0.45,
      clearcoatRoughness: 0.25,
    });
    const accentMat = new THREE.MeshStandardMaterial({ color: 0xfaf8f4, metalness: 0.7, roughness: 0.25 });
    const g = new THREE.Group();

    if (category === "alexa") {
      // Amazon Echo cylindrical speaker with glowing cyan torus light ring
      const echoBody = new THREE.Mesh(
        new THREE.CylinderGeometry(0.28, 0.30, 0.52, 32),
        new THREE.MeshStandardMaterial({ color: 0x1c2128, roughness: 0.85, metalness: 0.1 })
      );
      echoBody.position.y = 0.26;
      const topRing = new THREE.Mesh(
        new THREE.CylinderGeometry(0.27, 0.28, 0.04, 32),
        new THREE.MeshStandardMaterial({ color: 0x12151b, roughness: 0.3, metalness: 0.5 })
      );
      topRing.position.y = 0.53;
      const cyanRing = new THREE.Mesh(
        new THREE.TorusGeometry(0.265, 0.02, 16, 48),
        new THREE.MeshBasicMaterial({ color: 0x00e5ff })
      );
      cyanRing.rotation.x = Math.PI / 2;
      cyanRing.position.y = 0.55;
      const centerBtn = new THREE.Mesh(
        new THREE.CylinderGeometry(0.04, 0.04, 0.015, 16),
        new THREE.MeshBasicMaterial({ color: 0x00e5ff })
      );
      centerBtn.position.y = 0.555;
      g.add(echoBody, topRing, cyanRing, centerBtn);
    } else if (category === "streaming_stick") {
      // Fire TV Dongle Stick + Companion Remote Control
      const stickBody = new THREE.Mesh(
        new THREE.BoxGeometry(0.34, 0.10, 0.72),
        new THREE.MeshStandardMaterial({ color: 0x12151b, roughness: 0.4, metalness: 0.2 })
      );
      stickBody.position.set(-0.16, 0.08, 0);
      const goldMat = new THREE.MeshStandardMaterial({ color: 0xd4af37, roughness: 0.2, metalness: 0.95 });
      const hdmiPlug = new THREE.Mesh(new THREE.BoxGeometry(0.18, 0.045, 0.16), goldMat);
      hdmiPlug.position.set(-0.16, 0.08, -0.42);
      const stickLed = new THREE.Mesh(
        new THREE.BoxGeometry(0.03, 0.02, 0.03),
        new THREE.MeshBasicMaterial({ color: 0x00e5ff })
      );
      stickLed.position.set(-0.16, 0.13, 0.28);
      const remoteBody = new THREE.Mesh(
        new THREE.BoxGeometry(0.22, 0.065, 0.64),
        new THREE.MeshStandardMaterial({ color: 0x1f242c, roughness: 0.5, metalness: 0.2 })
      );
      remoteBody.position.set(0.18, 0.05, 0.02);
      const dpad = new THREE.Mesh(
        new THREE.CylinderGeometry(0.065, 0.065, 0.02, 24),
        new THREE.MeshStandardMaterial({ color: 0x2e3540, roughness: 0.4, metalness: 0.4 })
      );
      dpad.position.set(0.18, 0.088, -0.12);
      const dpadCenter = new THREE.Mesh(
        new THREE.CylinderGeometry(0.03, 0.03, 0.025, 16),
        new THREE.MeshStandardMaterial({ color: 0x16181d, roughness: 0.2, metalness: 0.6 })
      );
      dpadCenter.position.set(0.18, 0.09, -0.12);
      g.add(stickBody, hdmiPlug, stickLed, remoteBody, dpad, dpadCenter);
    } else if (category === "printer") {
      // Multi-tier Printer Chassis + Scanner Bed + Rear Paper Feed + Front Tray
      const body = new THREE.Mesh(new THREE.BoxGeometry(0.72, 0.32, 0.56), mat);
      body.position.y = 0.16;
      const lid = new THREE.Mesh(
        new THREE.BoxGeometry(0.70, 0.05, 0.54),
        new THREE.MeshStandardMaterial({ color: 0x161920, roughness: 0.3, metalness: 0.5 })
      );
      lid.position.set(0, 0.34, 0);
      const rearTray = new THREE.Mesh(new THREE.BoxGeometry(0.48, 0.36, 0.02), accentMat);
      rearTray.rotation.x = -0.42;
      rearTray.position.set(0, 0.45, -0.22);
      const paperSheet = new THREE.Mesh(
        new THREE.BoxGeometry(0.42, 0.32, 0.008),
        new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.9 })
      );
      paperSheet.rotation.x = -0.42;
      paperSheet.position.set(0, 0.48, -0.21);
      const frontTray = new THREE.Mesh(new THREE.BoxGeometry(0.46, 0.03, 0.26), accentMat);
      frontTray.position.set(0, 0.12, 0.38);
      const printLed = new THREE.Mesh(new THREE.SphereGeometry(0.02, 12, 12), new THREE.MeshBasicMaterial({ color: 0x3eb488 }));
      printLed.position.set(0.28, 0.26, 0.28);
      g.add(body, lid, rearTray, paperSheet, frontTray, printLed);
    } else if (category === "tv") {
      // 16:9 Widescreen Smart TV + Stand Neck & Base
      const panel = new THREE.Mesh(new THREE.BoxGeometry(1.02, 0.60, 0.035), mat);
      panel.position.y = 0.44;
      const screen = new THREE.Mesh(
        new THREE.BoxGeometry(0.96, 0.54, 0.01),
        new THREE.MeshPhysicalMaterial({ color: 0x111622, roughness: 0.1, clearcoat: 0.9 })
      );
      screen.position.set(0, 0.44, 0.018);
      const neck = new THREE.Mesh(new THREE.CylinderGeometry(0.035, 0.045, 0.16, 12), accentMat);
      neck.position.y = 0.10;
      const base = new THREE.Mesh(new THREE.BoxGeometry(0.44, 0.025, 0.24), accentMat);
      base.position.y = 0.02;
      g.add(panel, screen, neck, base);
    } else if (category === "phone") {
      // Flagship Smartphone (Triple-Lens Studio Model on Display Stand)
      const phoneAssembly = new THREE.Group();
      phoneAssembly.position.y = 0.36;
      phoneAssembly.rotation.x = -0.22;

      // 1. Titanium / Aerospace Metal Chassis Frame
      const frameMat = new THREE.MeshStandardMaterial({
        color: 0x1e232d,
        metalness: 0.88,
        roughness: 0.22,
      });
      const frame = new THREE.Mesh(new THREE.BoxGeometry(0.33, 0.66, 0.036), frameMat);
      phoneAssembly.add(frame);

      [-0.166, 0.166].forEach((xSide) => {
        const band1 = new THREE.Mesh(new THREE.BoxGeometry(0.004, 0.015, 0.038), accentMat);
        band1.position.set(xSide, 0.18, 0);
        const band2 = new THREE.Mesh(new THREE.BoxGeometry(0.004, 0.015, 0.038), accentMat);
        band2.position.set(xSide, -0.18, 0);
        phoneAssembly.add(band1, band2);
      });

      const powerBtn = new THREE.Mesh(new THREE.BoxGeometry(0.008, 0.08, 0.012), accentMat);
      powerBtn.position.set(0.168, 0.08, 0);
      const volUp = new THREE.Mesh(new THREE.BoxGeometry(0.008, 0.05, 0.012), accentMat);
      volUp.position.set(-0.168, 0.12, 0);
      const volDown = new THREE.Mesh(new THREE.BoxGeometry(0.008, 0.05, 0.012), accentMat);
      volDown.position.set(-0.168, 0.04, 0);
      phoneAssembly.add(powerBtn, volUp, volDown);

      // 2. Front Screen Assembly: Jet-black bezel + Active AMOLED Face
      const screenBezel = new THREE.Mesh(
        new THREE.BoxGeometry(0.316, 0.646, 0.004),
        new THREE.MeshBasicMaterial({ color: 0x05070a })
      );
      screenBezel.position.set(0, 0, 0.019);

      const screenFace = new THREE.Mesh(
        new THREE.BoxGeometry(0.298, 0.626, 0.003),
        new THREE.MeshPhysicalMaterial({
          color: 0x0c121d,
          roughness: 0.04,
          clearcoat: 1.0,
          clearcoatRoughness: 0.06,
          emissive: 0x16263f,
          emissiveIntensity: 0.55,
        })
      );
      screenFace.position.set(0, 0, 0.021);

      const earSpeaker = new THREE.Mesh(
        new THREE.BoxGeometry(0.06, 0.006, 0.002),
        new THREE.MeshBasicMaterial({ color: 0x222730 })
      );
      earSpeaker.position.set(0, 0.302, 0.023);

      const dynamicIsland = new THREE.Mesh(
        new THREE.CylinderGeometry(0.015, 0.015, 0.004, 16),
        new THREE.MeshBasicMaterial({ color: 0x000000 })
      );
      dynamicIsland.rotation.x = Math.PI / 2;
      dynamicIsland.position.set(0, 0.278, 0.023);

      const homeBar = new THREE.Mesh(
        new THREE.BoxGeometry(0.11, 0.006, 0.002),
        new THREE.MeshBasicMaterial({ color: 0x8899aa })
      );
      homeBar.position.set(0, -0.292, 0.023);

      phoneAssembly.add(screenBezel, screenFace, earSpeaker, dynamicIsland, homeBar);

      // 3. Rear Multi-Lens Camera System & Backplate
      const backPlate = new THREE.Mesh(
        new THREE.BoxGeometry(0.318, 0.648, 0.004),
        new THREE.MeshStandardMaterial({ color: 0x161b24, roughness: 0.35, metalness: 0.65 })
      );
      backPlate.position.set(0, 0, -0.019);

      const camPlateau = new THREE.Mesh(
        new THREE.BoxGeometry(0.13, 0.16, 0.016),
        new THREE.MeshStandardMaterial({ color: 0x222936, roughness: 0.25, metalness: 0.75 })
      );
      camPlateau.position.set(-0.085, 0.22, -0.026);
      phoneAssembly.add(backPlate, camPlateau);

      const lensMat = new THREE.MeshPhysicalMaterial({ color: 0x080a0e, roughness: 0.02, clearcoat: 1.0 });
      const rimMat = new THREE.MeshStandardMaterial({ color: 0x8894a6, metalness: 0.95, roughness: 0.1 });
      const lensPositions = [
        [-0.108, 0.255],
        [-0.108, 0.185],
        [-0.055, 0.220],
      ];
      lensPositions.forEach(([lx, ly]) => {
        const rim = new THREE.Mesh(new THREE.CylinderGeometry(0.026, 0.026, 0.014, 16), rimMat);
        rim.rotation.x = Math.PI / 2;
        rim.position.set(lx, ly, -0.035);
        const pupil = new THREE.Mesh(new THREE.CylinderGeometry(0.020, 0.020, 0.015, 16), lensMat);
        pupil.rotation.x = Math.PI / 2;
        pupil.position.set(lx, ly, -0.036);
        phoneAssembly.add(rim, pupil);
      });

      const flash = new THREE.Mesh(
        new THREE.CylinderGeometry(0.009, 0.009, 0.012, 12),
        new THREE.MeshBasicMaterial({ color: 0xfff0c8 })
      );
      flash.rotation.x = Math.PI / 2;
      flash.position.set(-0.055, 0.265, -0.034);

      const lidar = new THREE.Mesh(
        new THREE.CylinderGeometry(0.007, 0.007, 0.012, 12),
        new THREE.MeshBasicMaterial({ color: 0x111111 })
      );
      lidar.rotation.x = Math.PI / 2;
      lidar.position.set(-0.055, 0.175, -0.034);
      phoneAssembly.add(flash, lidar);

      // 4. Subtle Clear Acrylic Presentation Stand
      const standDisc = new THREE.Mesh(
        new THREE.CylinderGeometry(0.18, 0.20, 0.025, 24),
        new THREE.MeshPhysicalMaterial({ color: 0xffffff, roughness: 0.12, transmission: 0.82, thickness: 0.3 })
      );
      standDisc.position.y = 0.013;
      const standSpine = new THREE.Mesh(
        new THREE.CylinderGeometry(0.016, 0.022, 0.22, 12),
        accentMat
      );
      standSpine.rotation.x = -0.22;
      standSpine.position.set(0, 0.12, -0.04);
      g.add(standDisc, standSpine, phoneAssembly);
    } else if (category === "computer") {
      // Clamshell Laptop with Keyboard Deck & Angled Screen Lid
      const laptopBase = new THREE.Mesh(new THREE.BoxGeometry(0.74, 0.045, 0.52), mat);
      laptopBase.position.y = 0.035;
      const kbd = new THREE.Mesh(new THREE.BoxGeometry(0.66, 0.01, 0.30), new THREE.MeshStandardMaterial({ color: 0x12151b, roughness: 0.7 }));
      kbd.position.set(0, 0.06, -0.06);
      const trackpad = new THREE.Mesh(new THREE.BoxGeometry(0.22, 0.01, 0.12), new THREE.MeshStandardMaterial({ color: 0x222730, roughness: 0.3 }));
      trackpad.position.set(0, 0.06, 0.16);
      const lidGroup = new THREE.Group();
      lidGroup.position.set(0, 0.05, -0.25);
      lidGroup.rotation.x = -0.25;
      const lidMesh = new THREE.Mesh(new THREE.BoxGeometry(0.72, 0.48, 0.03), mat);
      lidMesh.position.y = 0.24;
      const lidScreen = new THREE.Mesh(
        new THREE.BoxGeometry(0.68, 0.44, 0.01),
        new THREE.MeshPhysicalMaterial({ color: 0x182030, roughness: 0.1, clearcoat: 0.8 })
      );
      lidScreen.position.set(0, 0.24, 0.016);
      lidGroup.add(lidMesh, lidScreen);
      g.add(laptopBase, kbd, trackpad, lidGroup);
    } else if (category === "bulb") {
      // Smart Connected Bulb: Screw Base + Neck + Glass Dome + Glowing PointLight
      const baseCyl = new THREE.Mesh(
        new THREE.CylinderGeometry(0.12, 0.12, 0.18, 16),
        new THREE.MeshStandardMaterial({ color: 0xb0b5be, metalness: 0.9, roughness: 0.2 })
      );
      baseCyl.position.y = 0.10;
      const neckCyl = new THREE.Mesh(
        new THREE.CylinderGeometry(0.18, 0.13, 0.14, 20),
        new THREE.MeshStandardMaterial({ color: 0xf4f1ea, roughness: 0.6 })
      );
      neckCyl.position.y = 0.24;
      const bulbDome = new THREE.Mesh(
        new THREE.SphereGeometry(0.24, 28, 28),
        new THREE.MeshPhysicalMaterial({
          color: 0xfffaed,
          roughness: 0.1,
          transmission: 0.65,
          thickness: 0.2,
          emissive: 0xffd27d,
          emissiveIntensity: 0.75
        })
      );
      bulbDome.scale.set(1, 1.25, 1);
      bulbDome.position.y = 0.46;
      const bulbLight = new THREE.PointLight(0xffd27d, 0.7, 2.5);
      bulbLight.position.set(0, 0.46, 0);
      g.add(baseCyl, neckCyl, bulbDome, bulbLight);
    } else if (category === "fan") {
      // Smart Fan with 3 Aerodynamic ROTATING Blades
      const rod = new THREE.Mesh(new THREE.CylinderGeometry(0.035, 0.035, 0.24, 16), accentMat);
      rod.position.y = 0.50;
      const motor = new THREE.Mesh(new THREE.CylinderGeometry(0.19, 0.17, 0.10, 24), mat);
      motor.position.y = 0.36;
      const bladeGroup = new THREE.Group();
      bladeGroup.position.y = 0.36;
      for (let i = 0; i < 3; i++) {
        const blade = new THREE.Mesh(new THREE.BoxGeometry(0.12, 0.015, 0.52), mat);
        blade.position.set(0, 0, 0.28);
        blade.rotation.x = 0.12;
        const bladeArm = new THREE.Group();
        bladeArm.rotation.y = (i * Math.PI * 2) / 3;
        bladeArm.add(blade);
        bladeGroup.add(bladeArm);
      }
      g.add(rod, motor, bladeGroup);
      animatedFans.push(bladeGroup);
    } else if (category === "ac") {
      // Wall-mount Split AC with Louvers & Ice-Blue Temp Readout
      const acBody = new THREE.Mesh(
        new THREE.BoxGeometry(0.94, 0.28, 0.26),
        new THREE.MeshPhysicalMaterial({ color: 0xf4f1ea, roughness: 0.25, metalness: 0.1, clearcoat: 0.5 })
      );
      acBody.position.y = 0.32;
      const intake = new THREE.Mesh(new THREE.BoxGeometry(0.88, 0.02, 0.20), new THREE.MeshStandardMaterial({ color: 0xced2da, roughness: 0.6 }));
      intake.position.set(0, 0.465, -0.01);
      const louver = new THREE.Mesh(new THREE.BoxGeometry(0.88, 0.02, 0.08), new THREE.MeshStandardMaterial({ color: 0xa8b0bd, roughness: 0.4 }));
      louver.rotation.x = 0.35;
      louver.position.set(0, 0.19, 0.12);
      const tempLed = new THREE.Mesh(new THREE.BoxGeometry(0.12, 0.06, 0.01), new THREE.MeshBasicMaterial({ color: 0x56ccf2 }));
      tempLed.position.set(0.32, 0.32, 0.132);
      g.add(acBody, intake, louver, tempLed);
    } else if (category === "fridge") {
      // Double Door Smart Refrigerator with Handles & Freezer Seam
      const fridgeBody = new THREE.Mesh(
        new THREE.BoxGeometry(0.56, 1.12, 0.56),
        new THREE.MeshPhysicalMaterial({ color: 0xd8dce4, roughness: 0.28, metalness: 0.75, clearcoat: 0.3 })
      );
      fridgeBody.position.y = 0.56;
      const seam = new THREE.Mesh(new THREE.BoxGeometry(0.562, 0.015, 0.562), new THREE.MeshBasicMaterial({ color: 0x222730 }));
      seam.position.y = 0.78;
      const handleUpper = new THREE.Mesh(new THREE.CylinderGeometry(0.014, 0.014, 0.26, 16), new THREE.MeshStandardMaterial({ color: 0xfaf8f4, metalness: 0.95, roughness: 0.1 }));
      handleUpper.position.set(0.24, 0.90, 0.29);
      const handleLower = new THREE.Mesh(new THREE.CylinderGeometry(0.014, 0.014, 0.42, 16), new THREE.MeshStandardMaterial({ color: 0xfaf8f4, metalness: 0.95, roughness: 0.1 }));
      handleLower.position.set(0.24, 0.52, 0.29);
      g.add(fridgeBody, seam, handleUpper, handleLower);
    } else if (category === "camera") {
      // Articulated Security Camera + Glass Lens + Red Record LED
      const arm = new THREE.Mesh(new THREE.CylinderGeometry(0.035, 0.035, 0.22, 16), accentMat);
      arm.rotation.z = Math.PI / 4;
      arm.position.set(-0.16, 0.40, 0);
      const ball = new THREE.Mesh(new THREE.SphereGeometry(0.07, 16, 16), accentMat);
      ball.position.set(-0.06, 0.32, 0);
      const camBody = new THREE.Mesh(new THREE.CylinderGeometry(0.15, 0.17, 0.36, 24), mat);
      camBody.rotation.z = -Math.PI / 6;
      camBody.position.set(0.08, 0.25, 0);
      const lens = new THREE.Mesh(
        new THREE.CylinderGeometry(0.12, 0.12, 0.02, 24),
        new THREE.MeshPhysicalMaterial({ color: 0x0a0c10, roughness: 0.05, clearcoat: 1.0 })
      );
      lens.rotation.z = -Math.PI / 6;
      lens.position.set(0.18, 0.19, 0);
      const recLed = new THREE.Mesh(new THREE.SphereGeometry(0.015, 12, 12), new THREE.MeshBasicMaterial({ color: 0xe36050 }));
      recLed.position.set(0.20, 0.24, 0.06);
      g.add(arm, ball, camBody, lens, recLed);
    } else {
      // Microcontroller IoT Sensor PCB + IC Chip + Heartbeat LED
      const pcb = new THREE.Mesh(
        new THREE.BoxGeometry(0.46, 0.032, 0.46),
        new THREE.MeshStandardMaterial({ color: 0x162c1e, roughness: 0.5, metalness: 0.3 })
      );
      pcb.position.y = 0.02;
      const icChip = new THREE.Mesh(
        new THREE.BoxGeometry(0.22, 0.04, 0.22),
        new THREE.MeshStandardMaterial({ color: 0x181a1f, roughness: 0.2, metalness: 0.8 })
      );
      icChip.position.y = 0.045;
      const chipLed = new THREE.Mesh(new THREE.SphereGeometry(0.018, 12, 12), new THREE.MeshBasicMaterial({ color: colorHex }));
      chipLed.position.set(0.14, 0.05, 0.14);
      g.add(pcb, icChip, chipLed);
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
    animatedFans = [];

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

    const layout3d = window.GarudaLayout
      ? window.GarudaLayout.compute3DPlinthLayout(others)
      : {
          nodes: others.map((d, idx) => {
            const angle = (idx / Math.max(1, others.length)) * Math.PI * 2;
            const r = d.is_safe ? 2.65 : 4.35;
            return { device: d, x: Math.cos(angle) * r, z: Math.sin(angle) * r, r };
          }),
          plinthRadius: 4.95,
        };

    // Dynamic plinth, trust-ring & camera scaling for large networks (12 -> 1,000+ devices)
    const scaleFactor = Math.max(1, layout3d.plinthRadius / 4.95);
    plinthDisk.scale.set(scaleFactor, 1, scaleFactor);
    const inScale = Math.max(1, (layout3d.innerRadius || 2.65) / 2.65);
    const outScale = Math.max(1, (layout3d.outerRadius || 4.35) / 4.35);
    innerRing.scale.set(inScale, inScale, 1);
    outerRing.scale.set(outScale, outScale, 1);
    controls.maxDistance = Math.max(18, layout3d.plinthRadius * 3.4);

    layout3d.nodes.forEach((entry, idx) => {
      const d = entry.device;
      const x = entry.x;
      const z = entry.z;

      const ml = mlMap.get(d.mac.toUpperCase());
      const isAlert =
        (snap.alerts || []).some((a) => !a.resolved && (a.related_mac === d.mac || a.related_ip === d.ip)) ||
        (ml && ml.risk_level === "critical");

      const colorHex = isAlert
        ? (currentThemeDark ? 0xe36050 : 0xc53624)
        : d.is_safe
        ? (currentThemeDark ? 0x3eb488 : 0x157f56)
        : (currentThemeDark ? 0xe2a343 : 0xb96b08);

      const nodeGroup = buildDeviceMesh(d.device_type, colorHex, d);
      nodeGroup.position.set(x, 0.02, z);
      nodeGroup.lookAt(0, 0.02, 0);
      nodeGroup.userData = { baseY: 0.02, targetScale: 1.0 };
      nodeGroup.traverse((child) => {
        if (child.isMesh) {
          child.userData = { device: d, ml, parentGroup: nodeGroup };
          interactables.push(child);
        }
      });
      // Soft contact-shadow plinth disc beneath each 3D silhouette
      const shadowDisc = new THREE.Mesh(
        new THREE.CircleGeometry(0.42, 24),
        new THREE.MeshBasicMaterial({ color: 0x000000, transparent: true, opacity: currentThemeDark ? 0.34 : 0.14 })
      );
      shadowDisc.rotation.x = -Math.PI / 2;
      shadowDisc.position.set(x, 0.005, z);
      dynamicGroup.add(shadowDisc, nodeGroup);

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

  let hoveredGroup = null;
  renderer.domElement.addEventListener("pointermove", (e) => {
    const hit = pickHit(e.clientX, e.clientY);
    const nextGroup = hit?.parentGroup || null;
    if (hoveredGroup && hoveredGroup !== nextGroup) hoveredGroup.scale.set(1, 1, 1);
    if (nextGroup) nextGroup.scale.set(1.14, 1.14, 1.14);
    hoveredGroup = nextGroup;
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

    // Rotating smart fan blades
    for (const fan of animatedFans) {
      fan.rotation.y += reducedMotion ? 0.02 : 0.08;
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
