#!/usr/bin/env bash
set -e
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
echo ""
echo "================================================================"
echo "  GARUDA v4 Full-Stack Network, AI & Forensic Guardian"
echo "  Web Dashboard : http://localhost:8000"
echo "  Swagger API   : http://localhost:8000/docs"
echo "  Tip: Run with 'sudo ./run.sh' for live Scapy IDS & UFW control"
echo "================================================================"
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
