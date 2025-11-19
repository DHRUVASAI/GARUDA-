# GARUDA Network Scanner - PowerShell Launcher
# Run with: .\start_garuda.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  GARUDA Network Scanner - Quick Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[OK] Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python not found! Please install Python 3.7+" -ForegroundColor Red
    pause
    exit 1
}

# Install dependencies
Write-Host ""
Write-Host "[1/4] Installing dependencies..." -ForegroundColor Yellow
pip install flask flask-cors --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Failed to install dependencies" -ForegroundColor Red
    pause
    exit 1
}

# Get local IP
Write-Host ""
Write-Host "[2/4] Getting your local IP address..." -ForegroundColor Yellow
$localIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi*" | Select-Object -First 1).IPAddress
if (-not $localIP) {
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*"} | Select-Object -First 1).IPAddress
}
Write-Host "[OK] Your local IP: $localIP" -ForegroundColor Green

# Check/Add firewall rule
Write-Host ""
Write-Host "[3/4] Checking firewall..." -ForegroundColor Yellow
$firewallRule = Get-NetFirewallRule -DisplayName "GARUDA Backend" -ErrorAction SilentlyContinue
if (-not $firewallRule) {
    try {
        New-NetFirewallRule -DisplayName "GARUDA Backend" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow | Out-Null
        Write-Host "[OK] Firewall rule added" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Could not add firewall rule. You may need to run as Administrator." -ForegroundColor Yellow
    }
} else {
    Write-Host "[OK] Firewall rule exists" -ForegroundColor Green
}

Write-Host ""
Write-Host "[4/4] Setup complete!" -ForegroundColor Green
Write-Host ""

# Menu
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   DEPLOYMENT OPTIONS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. LOCAL DEPLOYMENT (Recommended for testing)" -ForegroundColor White
Write-Host "   - Backend:  http://localhost:5000" -ForegroundColor Gray
Write-Host "   - Frontend: http://localhost:8000" -ForegroundColor Gray
Write-Host ""
Write-Host "2. NETWORK DEPLOYMENT (Access from other devices)" -ForegroundColor White
Write-Host "   - Backend:  http://${localIP}:5000" -ForegroundColor Gray
Write-Host "   - Frontend: http://${localIP}:8000" -ForegroundColor Gray
Write-Host ""
Write-Host "3. BACKEND ONLY (Use with GitHub Pages)" -ForegroundColor White
Write-Host "   - Backend:  http://${localIP}:5000" -ForegroundColor Gray
Write-Host "   - Frontend: GitHub Pages" -ForegroundColor Gray
Write-Host ""
Write-Host "Q. Quit" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Select option [1-3, Q]"

switch ($choice.ToUpper()) {
    "1" {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "   Starting LOCAL deployment..." -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[Backend] Starting on http://localhost:5000" -ForegroundColor Yellow
        Write-Host "[Frontend] Starting on http://localhost:8000" -ForegroundColor Yellow
        Write-Host ""
        
        # Start backend
        $backendJob = Start-Job -ScriptBlock { 
            Set-Location $using:PWD
            python garudaa\garuda_backend.py 
        }
        Start-Sleep -Seconds 2
        
        # Start frontend
        $frontendJob = Start-Job -ScriptBlock { 
            Set-Location "$using:PWD\garudaa"
            python -m http.server 8000 
        }
        Start-Sleep -Seconds 2
        
        Write-Host "[OK] Servers started!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Opening browser..." -ForegroundColor Yellow
        Start-Process "http://localhost:8000/garuda-visualization.html"
        
        Write-Host ""
        Write-Host "Press any key to stop servers..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        
        Stop-Job $backendJob
        Stop-Job $frontendJob
        Remove-Job $backendJob
        Remove-Job $frontendJob
    }
    
    "2" {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "   Starting NETWORK deployment..." -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[Backend] Starting on http://${localIP}:5000" -ForegroundColor Yellow
        Write-Host "[Frontend] Starting on http://${localIP}:8000" -ForegroundColor Yellow
        Write-Host ""
        
        # Start backend
        $backendJob = Start-Job -ScriptBlock { 
            Set-Location $using:PWD
            python garudaa\garuda_backend.py 
        }
        Start-Sleep -Seconds 2
        
        # Start frontend
        $frontendJob = Start-Job -ScriptBlock { 
            Set-Location "$using:PWD\garudaa"
            python -m http.server 8000 
        }
        Start-Sleep -Seconds 2
        
        Write-Host "[OK] Servers started!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Access from any device on your WiFi:" -ForegroundColor Cyan
        Write-Host "http://${localIP}:8000/garuda-visualization.html" -ForegroundColor White
        Write-Host ""
        Write-Host "Press any key to stop servers..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        
        Stop-Job $backendJob
        Stop-Job $frontendJob
        Remove-Job $backendJob
        Remove-Job $frontendJob
    }
    
    "3" {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "   Starting BACKEND ONLY..." -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[Backend] Starting on http://${localIP}:5000" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Update your GitHub Pages frontend with:" -ForegroundColor Cyan
        Write-Host "  const API_BASE = 'http://${localIP}:5000';" -ForegroundColor White
        Write-Host ""
        Write-Host "Health check: http://${localIP}:5000/api/health" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
        Write-Host ""
        
        python garudaa\garuda_backend.py
    }
    
    default {
        Write-Host "Exiting..." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host ""
Write-Host "Shutting down..." -ForegroundColor Yellow
Write-Host "Done!" -ForegroundColor Green
