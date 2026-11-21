@echo off
title GARUDA v6 — Tactical Network Guardian
echo ================================================================
echo   GARUDA v6 — Auto-Adapting Network, AI, AWS & Forensic Guardian
echo ================================================================
if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating Python virtual environment...
    python -m venv .venv
)
call .venv\Scripts\activate.bat
echo [2/3] Ensuring dependencies are installed...
pip install -q -r requirements.txt
echo [3/3] Launching GARUDA v6 Engine (non-blocking) and opening dashboard...
start "GARUDA v6 Server" /min cmd /c "python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"
timeout /t 2 /nobreak >nul
start "" http://localhost:8000
echo Dashboard opened at http://localhost:8000 (Swagger API: http://localhost:8000/docs)
