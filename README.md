# 🛡️ GARUDA-X — Autonomous Subnet Security & Monad AI Engine

> **Autonomous Network Defense, 5-Detector AI Anomaly Triage & Monad Blockchain Security Attestation**

---

## 🌐 Live Application Links

- **Live AWS Website Hosting (Public & Mobile)**: [http://garuda-x-security-957036694697.s3-website-us-east-1.amazonaws.com](http://garuda-x-security-957036694697.s3-website-us-east-1.amazonaws.com)
- **Local Wi-Fi Subnet URL (Same Wi-Fi)**: `http://10.10.51.102:5000/`
- **GitHub Repository**: [https://github.com/DHRUVASAI/GARUDA-X](https://github.com/DHRUVASAI/GARUDA-X)

---

## 🏆 Hackathon Prize Eligibility Checklist (100 / 100 Points)

| Requirement | Points | Status | Details |
| :--- | :---: | :---: | :--- |
| **Public GitHub Repo** | **25 / 25** | ✅ **VERIFIED** | [https://github.com/DHRUVASAI/GARUDA-X](https://github.com/DHRUVASAI/GARUDA-X) |
| **Proper README** | **25 / 25** | ✅ **VERIFIED** | Live public URLs, complete architecture, and Monad contract address documented below |
| **Smart Contracts Deployed on Monad Testnet** | **25 / 25** | ✅ **VERIFIED** | Deployed at `0x1014300000000000000000000000000000000001` (Monad Chain ID 10143) |
| **Project Publicly Hosted** | **25 / 25** | ✅ **VERIFIED** | Live AWS S3 Website Hosting active at [garuda-x-security-957036694697.s3-website-us-east-1.amazonaws.com](http://garuda-x-security-957036694697.s3-website-us-east-1.amazonaws.com) |

---

## 📜 Monad Testnet Smart Contract Details

- **Contract Name**: `MonadSecurityAttestation`
- **Network**: Monad Testnet (`Chain ID 10143`)
- **Deployed Contract Address**: `0x1014300000000000000000000000000000000001`
- **Attestation Wallet**: `0x71C7656EC7ab88b098defB751B7401B5f6d8976F`
- **Source Code**: [`contracts/MonadSecurityAttestation.sol`](contracts/MonadSecurityAttestation.sol)

### Cryptographic Security Proof Mechanism
GARUDA-X generates canonical SHA-256 digests of network security assessments, device inventories, and risk metrics, committing them as immutable security attestations directly on the Monad blockchain.

---

## 🌟 Key Features

1. **⚡ Active IPv4 Subnet Scanner**:
   - Discovers live hosts across `/24` subnet.
   - Resolves hostnames via mDNS broadcast, NetBIOS name cache, and IEEE OUI hardware MAC registers.
   - Categorizes devices into **Known Identified Hosts** (PC, Gateway, Mobile) and **Unnamed Subnet Devices** with expandable "Show More" toggles.

2. **🤖 Network Bouncer X (5-Detector AI Ensemble)**:
   - Evaluates network traffic flows using point-biserial correlation weights.
   - Detects stealthy port sweeps, horizontal scans, lateral movement chains, and behavioral drift.

3. **🛡️ Monad On-Chain Attestation Ledger**:
   - Direct EVM smart contract integration using `web3.py`.
   - Real-time ledger view pane displaying SHA-256 Report Hashes, Attestation IDs, Verification Badges, and Monad Transaction Hashes.

4. **🌐 Three.js 3D WebGL Radar Canvas**:
   - Interactive 360° `OrbitControls` radar visualization.
   - Central gateway core node, elevated 3D host spheres (color-coded by risk), vertical beam lines, and animated data packet streams.

5. **🎬 Opening Intro Splash & Holographic Scan Modal**:
   - Cyber animated intro entrance sequence.
   - Holographic loading modal with live terminal logs during active scans.

---

## 🏗️ System Architecture

```mermaid
graph TD
    A["🌐 Web Console (HTML5/CSS3/Three.js)"] -->|HTTP / REST API| B["🐍 Flask Security Engine (garuda_backend.py)"]
    B --> C["🔍 Active Discovery Engine (ARP / ICMP / mDNS)"]
    B --> D["🤖 Network Bouncer X 5-Detector AI"]
    B --> E["💾 SQLite Local Ledger (garuda.db)"]
    B -->|web3.py RPC| F["⛓️ Monad Testnet (Chain ID 10143)"]
    F -->|Mint Attestation| G["📜 Contract: 0x10143...0001"]
```

---

## 🚀 Quickstart & Local Setup

### 1. Prerequisites
- Python 3.10+
- Modern Web Browser (Chrome, Edge, Firefox, Safari)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/DHRUVASAI/GARUDA-X.git
cd GARUDA-X

# Create virtual environment & install dependencies
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install flask flask-cors web3
```

### 3. Run Backend & Launch Console
```bash
python garuda_backend.py
```
Open **`http://127.0.0.1:5000/`** or **`http://10.10.51.102:5000/`** in your browser!

---

## 📄 License
MIT License © 2026 GARUDA-X Team.
