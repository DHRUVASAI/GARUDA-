@echo off
setlocal
title GARUDA v6 -- Tactical Network Guardian

set "LAUNCH_DIR=%~dp0"
cd /d "%LAUNCH_DIR%"

if exist "%LAUNCH_DIR%GARUDA--main\backend\app\main.py" (
    cd /d "%LAUNCH_DIR%GARUDA--main"
)

echo.
echo ================================================================
echo   GARUDA v6 -- Adversarial Network Guardian and Forensic Ledger
echo ================================================================
echo   [*] Starting Sentinel Core on http://localhost:8000 ...
echo   [*] Launching Tactical Web Dashboard in default browser...
start "" http://localhost:8000

echo   [*] Engine is LIVE. Interactive logs streaming below.
echo   [*] Press Ctrl+C in this terminal to safely stop the server.
echo ================================================================
echo.

python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 %*

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Server stopped with exit code %ERRORLEVEL%.
    pause
)

endlocal
