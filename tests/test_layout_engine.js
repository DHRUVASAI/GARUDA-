const layoutEngine = require("../frontend/layoutEngine.js");

console.log("================================================================================");
console.log("GARUDA v4 — RIGOROUS LAYOUT ENGINE MATHEMATICAL VERIFICATION");
console.log("================================================================================");

const testCounts = [12, 150, 1000];
let allPassed = true;

for (const n of testCounts) {
  console.log(`\n--- TESTING N = ${n} DEVICES ---`);
  const synth = layoutEngine.generateSyntheticDevices(n, 0.08, 0.22);

  // 1. Test 2D Layout
  const t0_2d = performance.now();
  const layout2d = layoutEngine.computePolarLayout(synth.devices, synth.alerts, synth.mlScores, {
    mode: "2d",
    width: 1200,
    height: 900,
  });
  const t1_2d = performance.now();

  const labelResult = layoutEngine.compute2DLabelPlacement(layout2d.nodes, {
    width: 1200,
    height: 900,
    zoom: 1.0,
    panX: 0,
    panY: 0,
    nodeRadius: n > 300 ? 3 : n > 80 ? 4.5 : n > 18 ? 7 : 10,
    routerRadius: 30,
    measureTextFn: (txt) => ({ width: txt.length * 6.8 }),
  });
  const t2_2d = performance.now();

  const verify2d = layoutEngine.verifyLayoutInvariants(layout2d, labelResult);
  console.log(`[2D Verification N=${n}]:`);
  console.log(`  - Layout Compute Time: ${(t1_2d - t0_2d).toFixed(2)}ms`);
  console.log(`  - Labeler Compute Time: ${(t2_2d - t1_2d).toFixed(2)}ms`);
  console.log(`  - Placed Nodes: ${verify2d.nodeCount}`);
  console.log(`  - Placed Non-Overlapping Labels: ${verify2d.placedLabelsCount}`);
  console.log(`  - Target Min Spacing: ${verify2d.minSpacingTarget.toFixed(2)}px`);
  console.log(`  - Actual Min Euclidean Dist: ${verify2d.actualMinDistance.toFixed(2)}px`);
  console.log(`  - Pairwise Distance Violations: ${verify2d.distanceViolations}`);
  console.log(`  - Pairwise Label Overlaps: ${verify2d.aabbOverlaps}`);
  console.log(`  - Label-on-Dot Overlaps: ${verify2d.labelDotOverlaps}`);
  console.log(`  - VERDICT: ${verify2d.passed ? "PASSED (100% COLLISION FREE)" : "FAILED"}`);

  if (!verify2d.passed) {
    allPassed = false;
    console.error("  Details:", verify2d.violationDetails, verify2d.overlapDetails);
  }

  // 2. Test 3D Layout
  const t0_3d = performance.now();
  const layout3d = layoutEngine.computePolarLayout(synth.devices, synth.alerts, synth.mlScores, {
    mode: "3d",
    minNodeSpacing: 1.35,
  });
  const t1_3d = performance.now();

  const verify3d = layoutEngine.verifyLayoutInvariants(layout3d, { placedLabels: [], occupiedBoxes: [] });
  console.log(`[3D Verification N=${n}]:`);
  console.log(`  - Layout Compute Time: ${(t1_3d - t0_3d).toFixed(2)}ms`);
  console.log(`  - Placed 3D Nodes: ${verify3d.nodeCount}`);
  console.log(`  - Target Min Spacing: ${verify3d.minSpacingTarget.toFixed(2)} world units`);
  console.log(`  - Actual Min 3D Dist: ${verify3d.actualMinDistance.toFixed(2)} world units`);
  console.log(`  - Mesh Penetration Violations: ${verify3d.distanceViolations}`);
  console.log(`  - Outer Plinth Radius: ${layout3d.outerRadius.toFixed(2)} world units`);
  console.log(`  - VERDICT: ${verify3d.passed ? "PASSED (100% CLIPPING FREE)" : "FAILED"}`);

  if (!verify3d.passed) {
    allPassed = false;
    console.error("  3D Details:", verify3d.violationDetails);
  }
}

console.log("\n================================================================================");
console.log(`FINAL SUITE RESULT: ${allPassed ? "ALL 6 TEST BENCHMARKS PASSED PERFECTLY" : "SOME FAILED"}`);
console.log("================================================================================");
process.exit(allPassed ? 0 : 1);
