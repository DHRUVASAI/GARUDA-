@echo off
setlocal
set "GARUDA_DIR=%~dp0"

cd /d "%GARUDA_DIR%"

echo.
echo =================================================================
echo   GARUDA -- Personal Network Guardian, AI Anomaly ^& Forensic Ledger
echo =================================================================
echo   [*] Starting Sentinel Core on http://localhost:8000 ...
echo   [*] The browser dashboard will open automatically when ready.
echo   [*] Press Ctrl+C in this window to stop the server.
echo =================================================================
echo.

python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 %*

if %ERRORLEVEL% NEQ 0 (
  echo.
  echo [!] Server stopped or encountered an issue (Exit Code: %ERRORLEVEL%).
  echo     If port 8000 was busy, ensure no other GARUDA instance is running.
  pause
)

endlocal
