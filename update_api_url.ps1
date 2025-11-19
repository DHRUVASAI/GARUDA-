# Update API_BASE URL in garuda-visualization.html
# Usage: .\update_api_url.ps1 -URL "http://192.168.1.100:5000"

param(
    [Parameter(Mandatory=$false)]
    [string]$URL = ""
)

$htmlFile = "garudaa\garuda-visualization.html"

if (-not (Test-Path $htmlFile)) {
    Write-Host "[ERROR] File not found: $htmlFile" -ForegroundColor Red
    exit 1
}

# Get local IP if URL not provided
if ($URL -eq "") {
    Write-Host "Detecting local IP address..." -ForegroundColor Yellow
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi*" | Select-Object -First 1).IPAddress
    if (-not $localIP) {
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*"} | Select-Object -First 1).IPAddress
    }
    
    Write-Host ""
    Write-Host "Available options:" -ForegroundColor Cyan
    Write-Host "1. localhost (http://localhost:5000)" -ForegroundColor White
    Write-Host "2. Local network (http://$localIP:5000)" -ForegroundColor White
    Write-Host "3. Railway production (https://garuda-production-71a8.up.railway.app)" -ForegroundColor White
    Write-Host "4. Custom URL" -ForegroundColor White
    Write-Host ""
    
    $choice = Read-Host "Select option [1-4]"
    
    switch ($choice) {
        "1" { $URL = "http://localhost:5000" }
        "2" { $URL = "http://${localIP}:5000" }
        "3" { $URL = "https://garuda-production-71a8.up.railway.app" }
        "4" { 
            $URL = Read-Host "Enter custom URL (e.g., http://192.168.1.50:5000)"
        }
        default {
            Write-Host "[ERROR] Invalid choice" -ForegroundColor Red
            exit 1
        }
    }
}

# Validate URL
if ($URL -notmatch "^https?://") {
    Write-Host "[ERROR] Invalid URL format. Must start with http:// or https://" -ForegroundColor Red
    exit 1
}

# Remove trailing slash
$URL = $URL.TrimEnd('/')

Write-Host ""
Write-Host "Updating API_BASE to: $URL" -ForegroundColor Yellow

# Read file content
$content = Get-Content $htmlFile -Raw

# Find and replace API_BASE
$pattern = "const API_BASE = '[^']*';"
$replacement = "const API_BASE = '$URL';"

if ($content -match $pattern) {
    $newContent = $content -replace $pattern, $replacement
    
    # Write back to file
    Set-Content -Path $htmlFile -Value $newContent -NoNewline
    
    Write-Host "[OK] API_BASE updated successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Current configuration:" -ForegroundColor Cyan
    Write-Host "  API_BASE = '$URL'" -ForegroundColor White
    Write-Host ""
    
    # Test connection if localhost
    if ($URL -like "*localhost*" -or $URL -like "*127.0.0.1*") {
        Write-Host "Testing connection..." -ForegroundColor Yellow
        try {
            $response = Invoke-WebRequest -Uri "$URL/api/health" -TimeoutSec 2 -ErrorAction Stop
            Write-Host "[OK] Backend is responding!" -ForegroundColor Green
            Write-Host "Response: $($response.Content)" -ForegroundColor Gray
        } catch {
            Write-Host "[WARN] Backend not responding. Make sure it's running!" -ForegroundColor Yellow
            Write-Host "Start it with: python garudaa\garuda_backend.py" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Start backend: python garudaa\garuda_backend.py" -ForegroundColor White
    Write-Host "2. Open: http://localhost:8000/garuda-visualization.html" -ForegroundColor White
    Write-Host "   OR push to GitHub for GitHub Pages deployment" -ForegroundColor White
    
} else {
    Write-Host "[ERROR] Could not find API_BASE in file" -ForegroundColor Red
    Write-Host "Please update manually at line ~578" -ForegroundColor Yellow
    exit 1
}
