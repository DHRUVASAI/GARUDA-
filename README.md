# GARUDA v4 — Full-Stack Network Guardian, AI Behavioral Engine & Cryptographic Web3 Ledger

GARUDA v4 keeps every active defense & engineering pillar from v3 while introducing three major upgrades built from first principles:

1. **AI / Machine Learning Behavioral Anomaly Engine (`backend/app/services/ml_engine.py`)**:
   - 8-dimensional behavioral feature vector per host (Welford online latency Z-score, ARP reply rate, SYN port fanout, DNS Shannon entropy, C2 beacon inter-arrival CV, hardware novelty, off-hours drift, alert pressure).
   - Dual-model ensemble: `scikit-learn` **IsolationForest** (with pure-Python Isolation Forest fallback) + weighted statistical drift detector.
   - Real **Shannon Entropy + Linguistic DGA / DNS Tunneling Classifier** (`POST /api/ml/analyze-domain`).
   - **Explainable AI top-factor attribution** in plain English + **Human-in-the-Loop baseline reinforcement** whenever you mark a device Safe (`POST /api/devices/{mac}/trust` or `POST /api/ml/retrain`).

2. **Cryptographic Forensic & Web3 Attestation Ledger (`backend/app/services/attestation_ledger.py` + `contracts/GarudaAttestation.sol`)**:
   - Persistent **Ed25519 asymmetric signing keypair** (`data/garuda_node_ed25519.pem`).
   - Append-only **SHA-256 hash-chained SQLite ledger** automatically sealing critical IDS alerts, MITM pins, malware findings, and firewall blocks.
   - Real **Binary SHA-256 Merkle Tree & Inclusion Proofs** (`GET /api/ledger/proof/{block_index}`) + full chain tamper auditor (`GET /api/ledger/verify`) + JSON proof export (`GET /api/ledger/export`).
   - Audited **Solidity `^0.8.24` smart contract (`contracts/GarudaAttestation.sol`)** with `anchorRoot(...)` and on-chain `verifyIncident(...)`, plus optional live EVM RPC anchoring (`POST /api/ledger/anchor` via `GARUDA_WEB3_RPC_URL`, `GARUDA_WEB3_CONTRACT`, `GARUDA_WEB3_PRIVATE_KEY`).

3. **Studio 3D PBR Spatial Topology + Tactile Optical UI (`frontend/topology3d.js`)**:
   - Fault-isolated **Three.js v0.170.0** studio scene (`AgXToneMapping`, `PMREMGenerator` + `RoomEnvironment` softboxes, `60mm` telephoto optics, sculpted per-device 3D silhouettes, concentric trust rings, animated Bezier packet arcs, pulsing ML anomaly halos, `OrbitControls`, and Raycaster hover/click drawer inspection) paired with an instant **2D Precision Radar** toggle and automatic zero-error fallback.

## Quick Start
```bash
# Windows (Administrator Command Prompt + Npcap recommended)
run.bat

# Linux / macOS
chmod +x run.sh
sudo ./run.sh
```
Open **http://localhost:8000** (Dashboard) or **http://localhost:8000/docs** (Swagger API).

## Run All Automated Unit Tests
```bash
pytest -v tests/test_garuda_v4.py
```
