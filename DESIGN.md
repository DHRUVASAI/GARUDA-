# GARUDA v6 — System Architecture & Design Document

## 1. Layered Defense-in-Depth Architecture
- **Edge Discovery & Guardrail Layer:** `capability_probe.py` classifies the active network (`home_lan`, `campus_safe`, `vpn_protected`) before launching fault-isolated plugins (`plugin_engine.py`) with independent timeout budgets.
- **Detection & Behavioral Layer:** `ids_engine.py` inspects L2/L3/L4/L7 events (ARP, DHCP, TCP SYN, UDP/53 DNS, outbound flow cadence) while `ml_engine.py` scores every host across 8 behavioral dimensions with CUSUM slow-drift tracking and anti-poisoning gates.
- **Correlation & Cloud Layer:** `campaign_correlator.py` links multi-stage alerts into Purple-Team kill chains (`PT-01`..`PT-08`), and `aws_bridge.py` translates findings into AWS Security Hub ASFF (`2018-10-08`) alongside VPC Flow Log ingestion.
- **Containment & Forensics Layer:** `firewall_manager.py` enforces OS-native IP blocks and lockdown recovery, while `attestation_ledger.py` seals critical evidence in a thread-safe Ed25519 + SHA-256 Merkle chain.

## 2. Frontend Spatial Engine
- **Daylight Editorial UI:** Warm archival paper (`#F3F0EA`) + ivory surfaces (`#FAF8F4`) with Night Ops toggle and 4-layer tactile hardware buttons.
- **Scale-Invariant Layout (`layoutEngine.js`):** Circumference ring-packing + AABB label culling ensures zero collisions from 12 to 1,000+ devices in both 2D Pan/Zoom Radar (`0.5x`–`5.0x`) and Three.js PBR 3D Topology (`topology3d.js`).
