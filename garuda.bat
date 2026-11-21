@echo off
setlocal
set "GARUDA_DIR=%~dp0"

cd /d "%GARUDA_DIR%"

echo.
echo =================================================================
echo   GARUDA -- Personal Network Guardian, AI Anomaly ^& Forensic Ledger
echo =================================================================
echo   [*] Web Dashboard : http://localhost:8000
echo   [*] Swagger API   : http://localhost:8000/docs
echo   [*] Press Ctrl+C in this window to stop the server
echo =================================================================
echo.

start "" "http://localhost:8000"

python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 %*

endlocal
