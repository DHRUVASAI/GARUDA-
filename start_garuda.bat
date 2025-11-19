@echo off
echo ========================================
echo   GARUDA Network Scanner - Quick Setup
echo ========================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.7+
    pause
    exit /b 1
)

echo [1/4] Installing dependencies...
pip install flask flask-cors --quiet
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)
echo [OK] Dependencies installed

echo.
echo [2/4] Getting your local IP address...
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address"') do (
    set LOCAL_IP=%%a
    goto :found_ip
)
:found_ip
set LOCAL_IP=%LOCAL_IP:~1%
echo [OK] Your local IP: %LOCAL_IP%

echo.
echo [3/4] Checking firewall...
netsh advfirewall firewall show rule name="GARUDA Backend" >nul 2>&1
if errorlevel 1 (
    echo Adding firewall rule...
    netsh advfirewall firewall add rule name="GARUDA Backend" dir=in action=allow protocol=TCP localport=5000 >nul 2>&1
    if errorlevel 1 (
        echo [WARN] Could not add firewall rule. You may need to run as Administrator.
    ) else (
        echo [OK] Firewall rule added
    )
) else (
    echo [OK] Firewall rule exists
)

echo.
echo [4/4] Setup complete!
echo.
echo ========================================
echo   DEPLOYMENT OPTIONS
echo ========================================
echo.
echo Option 1: LOCAL DEPLOYMENT (Recommended for testing)
echo   - Backend:  http://localhost:5000
echo   - Frontend: http://localhost:8000
echo   - Press [1] to start
echo.
echo Option 2: NETWORK DEPLOYMENT (Access from other devices)
echo   - Backend:  http://%LOCAL_IP%:5000
echo   - Frontend: http://%LOCAL_IP%:8000
echo   - Press [2] to start
echo.
echo Option 3: BACKEND ONLY (Use with GitHub Pages)
echo   - Backend:  http://%LOCAL_IP%:5000
echo   - Frontend: GitHub Pages
echo   - Press [3] to start
echo.
echo Press [Q] to quit
echo.

choice /c 123Q /n /m "Select option: "

if errorlevel 4 goto :end
if errorlevel 3 goto :backend_only
if errorlevel 2 goto :network_deploy
if errorlevel 1 goto :local_deploy

:local_deploy
echo.
echo ========================================
echo   Starting LOCAL deployment...
echo ========================================
echo.
echo [Backend] Starting on http://localhost:5000
echo [Frontend] Starting on http://localhost:8000
echo.
echo Open your browser to: http://localhost:8000/garuda-visualization.html
echo.
echo Press Ctrl+C to stop both servers
echo.
start /b python garudaa\garuda_backend.py
timeout /t 2 /nobreak >nul
cd garudaa
start /b python -m http.server 8000
timeout /t 2 /nobreak >nul
echo [OK] Servers started!
echo.
start http://localhost:8000/garuda-visualization.html
pause
goto :end

:network_deploy
echo.
echo ========================================
echo   Starting NETWORK deployment...
echo ========================================
echo.
echo [Backend] Starting on http://%LOCAL_IP%:5000
echo [Frontend] Starting on http://%LOCAL_IP%:8000
echo.
echo Access from any device on your WiFi:
echo   http://%LOCAL_IP%:8000/garuda-visualization.html
echo.
echo Press Ctrl+C to stop both servers
echo.
start /b python garudaa\garuda_backend.py
timeout /t 2 /nobreak >nul
cd garudaa
start /b python -m http.server 8000
timeout /t 2 /nobreak >nul
echo [OK] Servers started!
echo.
echo Open this URL on any device (same WiFi):
echo http://%LOCAL_IP%:8000/garuda-visualization.html
echo.
pause
goto :end

:backend_only
echo.
echo ========================================
echo   Starting BACKEND ONLY...
echo ========================================
echo.
echo [Backend] Starting on http://%LOCAL_IP%:5000
echo.
echo Update your GitHub Pages frontend with:
echo   const API_BASE = 'http://%LOCAL_IP%:5000';
echo.
echo Health check: http://%LOCAL_IP%:5000/api/health
echo.
echo Press Ctrl+C to stop
echo.
python garudaa\garuda_backend.py
pause
goto :end

:end
echo.
echo Shutting down...
taskkill /f /im python.exe >nul 2>&1
echo Done!
pause
