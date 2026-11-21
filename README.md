# GARUDA v6 — Adversarial-Hardened Network Guardian, AI Engine, AWS Bridge & Forensic Ledger

> **Off Campus Verification Code:** `FXYKCA`
>
> <a href="https://github.com/DHRUVASAI/GARUDA-"><img src="https://img.shields.io/badge/Off_Campus_Code-FXYKCA-blueviolet?style=flat-square" alt="Off Campus Code: FXYKCA" /></a>

GARUDA v6 is a cross-platform personal & enterprise-ready network defense platform combining **5-layer real device naming**, **live packet IDS**, **IsolationForest + CUSUM ML anomaly detection**, **Ed25519 + SHA-256 Merkle forensic attestation**, **Purple-Team campaign correlation**, **AWS Security Hub ASFF & VPC Flow Log telemetry**, and a **collision-free 2D/3D spatial topology** scaling to 1,000+ devices.

---

## Core Architecture & v6 Capabilities

| Subsystem | Module(s) | Key Capabilities |
| :--- | :--- | :--- |
| **Auto-Adapting Environment Probe** | `capability_probe.py`, `plugin_engine.py` | Auto-detects Home LAN, Campus Wi-Fi (clamps `/16`–`/22` to `/24`), and Active VPN tunnels; isolates mDNS/SSDP plugins with strict timeout budgets. |
| **Live Adversarial Packet IDS** | `ids_engine.py` | Detects ARP spoofing, ARP reply storms, Proxy-ARP false-positive suppression, Rogue/competing DHCP servers, Fast/Slow/Distributed SYN port scans, live UDP/53 DNS tunneling & DGA, C2 periodic beaconing, cleartext FTP/Telnet, and MAC spoofing. |
| **Explainable ML Behavioral Engine** | `ml_engine.py` | 8-dimensional `IsolationForest` + online Welford Z-score + **CUSUM slow behavioral drift** + strict **baseline poisoning resistance** + single-feature evasion defense (`<2%` benign FP rate). |
| **Purple-Team Campaign Correlator** | `campaign_correlator.py` | Correlates multi-stage kill chains (`PT-01`..`PT-08`: ARP+DNS MITM, Recon→C2, Rogue DHCP+DNS, Trusted Compromise, Multi-Device Attacks, Intermittent Attackers) into chronological incident timelines (`GET /api/v6/campaigns`). |
| **AWS Edge-to-Cloud Bridge** | `aws_bridge.py` | Exports local LAN alerts in official **AWS Security Finding Format (ASFF `2018-10-08`)** and analyzes **AWS VPC Flow Logs** (`/api/v5/aws/asff-preview`, `/api/v5/aws/vpc-flow-analyze`). |
| **Cryptographic & Web3 Ledger** | `attestation_ledger.py`, `GarudaAttestation.sol` | Thread-safe Ed25519 + SHA-256 hash-chained SQLite ledger with binary Merkle inclusion proofs, tamper/deletion detection, restart recovery, and EVM smart contract anchoring. |
| **OS Firewall & Malware Shield** | `firewall_manager.py`, `malware_scanner.py` | Real Windows Defender (`netsh`) / Linux (`ufw`/`iptables`/`nft`) IP blocking, Public Wi-Fi Lockdown with clean policy recovery, ClamAV/YARA/psutil process HIDS, and Abuse.ch C2 feeds. |
| **Resilient IEEE OUI & Smart Device Engine** | `oui_db.py`, `device_scanner.py` | Multi-source failover (Linux `hwdata` + `arp-scan` + IEEE CSV + local cache) with 40,400+ vendor prefixes. Dedicated model recognition for **Amazon Echo/Alexa** (Dot, Show, Studio), **Amazon Fire TV Stick** (4K Max, 4K, Lite, Cube), **Google Nest/Chromecast**, **Apple TV/HomePod**, and **Roku**. |
| **Collision-Free 2D/3D Frontend** | `layoutEngine.js`, `topology3d.js`, `app.js` | Golden-ratio / circumference ring-packing up to 1,000+ devices, 2D radar Pan & Zoom (`0.5x`–`5.0x`), dynamic 3D WebGL plinth/camera scaling, and skippable MIL-STD tactical bootloader. |

---

## Verified Adversarial Benchmark (`81 / 81` Automated Tests)

| Suite | Tests | Coverage |
| :--- | :---: | :--- |
| `tests/test_garuda_v6_adversarial_50.py` | **50 / 50** | Red Team (`RT-01`..`RT-12`), ML (`ML-01`..`ML-08`), Blue Team (`BT-01`..`BT-07`), Forensics (`FR-01`..`FR-08`), Purple Team (`PT-01`..`PT-08`), Resilience (`PR-01`..`PR-07`). |
| `tests/test_garuda_v6_1_adaptive_adversary.py` | **5 / 5** | Adaptive MAC Hopping, Low-and-Slow Distributed Evasion, Encrypted C2 Behavioral Cadence, Anti-Baseline Poisoning Guardrail, Crash & Recovery Under Pressure. |
| `tests/test_garuda_ieee_sync_and_smart_devices.py` | **8 / 8** | Multi-source IEEE OUI sync resilience, offline bundled cache fallback, vendor normalization, Amazon Alexa & Fire TV Stick detection, smart IoT classification. |
| `tests/test_garuda_v5_resilience.py` | **7 / 7** | Campus `/24` clamp, Proxy-ARP shield, VPN skip, TTL/Port OS fusion, plugin isolation, hot-reload rules, AWS ASFF + VPC Flow Logs. |
| `tests/test_garuda_v4.py` | **11 / 11** | Core OUI, SSDP XML, IDS, EICAR/reverse-shell, firewall builders, advisor, DGA entropy, IsolationForest, Merkle, Ed25519, Solidity contract. |

---

## Quick Start

```bash
# Windows (1-click non-blocking launcher — opens http://localhost:8000 automatically)
garuda.bat

# Linux / macOS
chmod +x run.sh
sudo ./run.sh

# Run all 81 automated tests
pytest -v tests/
```
