# GARUDA v7 — Research-Grade Architecture, Threat Model & Evaluation Protocol

## 1. System Architecture
```
[LAN / Host Traffic]
       │
       ├──► Scapy Live Packet IDS + Device Scanner (5-Layer Naming)
       ├──► Behavioral ML Engine (IsolationForest + Welford + Adaptive Thresholds)
       ├──► Network Doctor (DNS, TLS, ARP Spoof, Risky Ports, System Vitals)
       │
       ▼
[FastAPI Control Plane + JWT RBAC (Admin / Analyst / Viewer)]
       │
       ├──► OS Firewall Enforcer (UFW / iptables / Windows Netsh) + Safe Mode
       ├──► PostgreSQL / SQLite Persistence + Immutable AdminAuditLog
       └──► Ed25519 + SHA-256 Merkle Attestation Ledger
```

## 2. Threat Model & Attack Assumptions
- **In-Scope Threats:** Layer-2 ARP spoofing/MITM, unauthorized LAN reconnaissance (SYN/distributed scans), periodic encrypted C2 beaconing, DGA/high-entropy domains, baseline/model poisoning attempts, and unauthorized administrative tampering.
- **Out-of-Scope / Known Limitations:** Kernel-level rootkits on the host OS, full TLS payload decryption (GARUDA inspects metadata/periodicity without breaking end-to-end encryption), and multi-10Gbps carrier-grade line rates (where Suricata/DPDK is preferred).

## 3. Experimental Setup & Reproducible Validation
1. **Real-World Attack Validation:** Run `python validation/attack_suite.py --target 127.0.0.1 --api http://127.0.0.1:8000` to execute controlled SYN scans, distributed probes, periodic C2 beacons, and poisoning probes.
2. **Performance & Ablation Benchmarking:** Run `python benchmarks/run_benchmarks.py` to record real hardware Detection Rate, Precision, FPR, Mean/P95 Latency, Throughput, CPU %, and RAM MB.
3. **Competitor Positioning (Suricata, Zeek, Wazuh):** GARUDA's measurable advantage is its **single-host footprint (<250 MB RAM)** combining active OS firewalling, real-time Network Doctor diagnostics, and cryptographic Ed25519 Merkle audit trails without requiring a multi-node SIEM cluster.
4. **Reliability & Hardening:** Verified via `pytest tests/` including `test_garuda_v7_auth_doctor_admin.py` and `test_garuda_v7_reliability_hardening.py`.
