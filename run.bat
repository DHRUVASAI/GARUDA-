@echo off
python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
echo.
echo ================================================================
echo   GARUDA v4 Full-Stack Network, AI & Forensic Guardian
echo   Web Dashboard : http://localhost:8000
echo   Swagger API   : http://localhost:8000/docs
echo   Tip: Run Command Prompt as Administrator + install Npcap for
echo        live packet sniffing and 1-click Windows Firewall control.
echo ================================================================
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
