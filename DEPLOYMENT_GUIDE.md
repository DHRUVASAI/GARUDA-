# 🚀 GARUDA Network Scanner - Complete Deployment Guide

## ⚠️ Critical Understanding

**Network scanning requires LOCAL network access** - your backend MUST run on the same network as the devices you want to scan. Cloud services like Railway, Heroku, AWS, etc. **CANNOT** scan your home/office WiFi network because they're in different locations.

---

## 🎯 Recommended Deployment Architecture

### **Option 1: Hybrid Deployment (BEST)** ⭐
**Backend:** Local network (your computer/Raspberry Pi)  
**Frontend:** GitHub Pages (public access)

#### Why This Works:
- ✅ Backend can scan local network devices
- ✅ Frontend accessible from anywhere
- ✅ Free hosting for frontend
- ✅ Full functionality

---

## 📋 Deployment Methods

## Method 1: Local Backend + GitHub Pages Frontend (RECOMMENDED) ⭐

### Step 1: Setup Backend Locally

#### A. Install Python Dependencies
```powershell
cd "c:\Users\Dhruva Sai\Desktop\SEM 3\garuda"
pip install flask flask-cors
```

#### B. Get Your Local IP Address
```powershell
ipconfig
# Look for "IPv4 Address" under your WiFi adapter
# Example: 192.168.1.100
```

#### C. Update Backend for External Access
```powershell
# Edit garudaa/garuda_backend.py - change last line to:
app.run(debug=False, host='0.0.0.0', port=5000)
```

#### D. Start Backend Server
```powershell
cd "c:\Users\Dhruva Sai\Desktop\SEM 3\garuda"
python garudaa/garuda_backend.py
```

**Backend will be available at:** `http://YOUR_LOCAL_IP:5000`

### Step 2: Deploy Frontend to GitHub Pages

#### A. Update API URL in Frontend
Edit `garuda-visualization.html` line 578:
```javascript
// Replace with your local IP
const API_BASE = 'http://192.168.1.100:5000';  // YOUR LOCAL IP
```

#### B. Push to GitHub
```powershell
git add .
git commit -m "Update for local backend deployment"
git push origin master
```

#### C. Enable GitHub Pages
1. Go to: `https://github.com/DHRUVASAI/FEDF_30009/settings/pages`
2. Source: **Deploy from branch**
3. Branch: **master** → Folder: **/ (root)**
4. Click **Save**
5. Wait 2-3 minutes for deployment

#### D. Access Your App
- URL: `https://dhruvasai.github.io/FEDF_30009/garudaa/garuda-visualization.html`
- **Important:** Both devices must be on the same WiFi network

### Step 3: Allow Browser Access (CORS)

Modern browsers block `http` requests from `https` sites. You have 2 options:

#### Option A: Use Browser Extension (Easiest)
1. Install "Allow CORS" extension for Chrome/Edge
2. Enable it when using the scanner
3. Scan will work

#### Option B: Serve Frontend Locally Too
```powershell
cd "c:\Users\Dhruva Sai\Desktop\SEM 3\garuda\garudaa"
python -m http.server 8000
```
Access: `http://localhost:8000/garuda-visualization.html`

---

## Method 2: Fully Local Deployment (SIMPLEST) 🏠

### Everything runs on your computer

```powershell
# Terminal 1: Start Backend
cd "c:\Users\Dhruva Sai\Desktop\SEM 3\garuda"
python garudaa/garuda_backend.py

# Terminal 2: Start Frontend
cd "c:\Users\Dhruva Sai\Desktop\SEM 3\garuda\garudaa"
python -m http.server 8000
```

**Update frontend API URL:**
```javascript
const API_BASE = 'http://localhost:5000';
```

**Access:** `http://localhost:8000/garuda-visualization.html`

### ✅ Pros:
- Complete control
- No CORS issues
- Full network scanning capability

### ❌ Cons:
- Only accessible from your computer
- Backend stops when computer sleeps

---

## Method 3: Raspberry Pi Deployment (24/7 Server) 🍓

### Perfect for always-on network monitoring

### Hardware Needed:
- Raspberry Pi 3/4/5
- MicroSD card (16GB+)
- Power supply
- WiFi or Ethernet connection

### Setup:

#### 1. Install Raspberry Pi OS
```bash
# On Raspberry Pi
sudo apt update
sudo apt install python3-pip git -y
```

#### 2. Clone Your Project
```bash
git clone https://github.com/DHRUVASAI/FEDF_30009.git
cd FEDF_30009
```

#### 3. Install Dependencies
```bash
pip3 install flask flask-cors
```

#### 4. Create Startup Service
```bash
sudo nano /etc/systemd/system/garuda.service
```

Add this content:
```ini
[Unit]
Description=GARUDA Network Scanner Backend
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/FEDF_30009
ExecStart=/usr/bin/python3 garudaa/garuda_backend.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### 5. Enable Auto-Start
```bash
sudo systemctl daemon-reload
sudo systemctl enable garuda.service
sudo systemctl start garuda.service
sudo systemctl status garuda.service
```

#### 6. Get Raspberry Pi IP
```bash
hostname -I
# Example: 192.168.1.50
```

#### 7. Update Frontend
Edit `garuda-visualization.html`:
```javascript
const API_BASE = 'http://192.168.1.50:5000';  // Pi IP
```

#### 8. Access from Any Device
- Deploy frontend to GitHub Pages
- Access from phone/laptop/desktop on same network
- Backend runs 24/7 on Raspberry Pi

---

## Method 4: Desktop Application (STANDALONE) 💻

### Create a standalone desktop app

```powershell
# Install PyWebView
pip install pywebview flask flask-cors
```

Create `garuda_app.py`:
```python
import webview
import threading
from garudaa.garuda_backend import app

def start_backend():
    app.run(debug=False, host='127.0.0.1', port=5000)

if __name__ == '__main__':
    # Start backend in thread
    backend_thread = threading.Thread(target=start_backend, daemon=True)
    backend_thread.start()
    
    # Start GUI
    webview.create_window(
        'GARUDA Network Scanner',
        'http://localhost:5000/static/garuda-visualization.html',
        width=1400,
        height=900
    )
    webview.start()
```

**Package as EXE:**
```powershell
pip install pyinstaller
pyinstaller --onefile --windowed garuda_app.py
```

---

## Method 5: Docker Container (ADVANCED) 🐳

### For easy deployment on any system

Create `Dockerfile`:
```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for network tools
RUN apt-get update && apt-get install -y \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy application
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port
EXPOSE 5000

# Run backend
CMD ["python", "garudaa/garuda_backend.py"]
```

Create `requirements.txt`:
```txt
flask==3.0.0
flask-cors==4.0.0
```

Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  garuda-backend:
    build: .
    ports:
      - "5000:5000"
    network_mode: "host"  # Access local network
    restart: unless-stopped
```

**Deploy:**
```powershell
docker-compose up -d
```

---

## 🌐 Network Configurations

### For LAN Access (Access from other devices on WiFi)

#### Windows Firewall Rule:
```powershell
# Allow port 5000
New-NetFirewallRule -DisplayName "GARUDA Backend" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
```

#### Find Your IP:
```powershell
ipconfig | Select-String "IPv4"
```

#### Access from other devices:
- Backend: `http://YOUR_IP:5000`
- If using local frontend: `http://YOUR_IP:8000`

---

## 🔒 Security Considerations

### If Exposing to Internet (NOT RECOMMENDED):

1. **Add Authentication:**
```python
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

users = {
    "admin": "your_secure_password"
}

@auth.verify_password
def verify_password(username, password):
    if username in users and users[username] == password:
        return username

@app.route('/api/scan/full', methods=['POST'])
@auth.login_required
def full_scan():
    # ... existing code
```

2. **Use HTTPS with SSL Certificate**

3. **Rate Limiting:**
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/api/scan/full')
@limiter.limit("5 per minute")
def full_scan():
    # ... existing code
```

---

## 📱 Mobile Access

### Access from Phone/Tablet on Same WiFi:

1. Start backend on your computer
2. Get your computer's IP: `ipconfig`
3. On phone, open browser: `http://YOUR_IP:5000`
4. For GitHub Pages frontend: Update `API_BASE` to your computer IP

---

## 🎯 Recommended Setup by Use Case

### Home Network Monitoring:
→ **Method 3: Raspberry Pi** (always-on, low power)

### Personal Use / Demo:
→ **Method 2: Fully Local** (simple, works offline)

### Team Project / Presentation:
→ **Method 1: Hybrid** (professional, accessible)

### Distributable Application:
→ **Method 4: Desktop App** (single file, no setup)

### Enterprise / Advanced:
→ **Method 5: Docker** (scalable, reproducible)

---

## 🚀 Quick Start (5 Minutes)

```powershell
# 1. Start Backend
cd "c:\Users\Dhruva Sai\Desktop\SEM 3\garuda"
python garudaa/garuda_backend.py

# 2. In another terminal, start Frontend
cd "c:\Users\Dhruva Sai\Desktop\SEM 3\garuda\garudaa"
python -m http.server 8000

# 3. Open browser
# http://localhost:8000/garuda-visualization.html

# 4. Click "Scanner" tab → "START DEEP SCAN"
```

---

## 🐛 Troubleshooting

### Backend won't start:
```powershell
# Check if port is in use
netstat -ano | findstr :5000

# Kill process if needed
taskkill /PID <PID> /F
```

### CORS errors:
- Use same protocol (both http or both https)
- Or add CORS extension to browser
- Or use local deployment (Method 2)

### No devices found:
- Run as Administrator (Windows requires elevation for network scanning)
- Check Windows Firewall
- Ensure WiFi adapter is active

### Can't access from other devices:
- Check firewall rules
- Verify same WiFi network
- Use IP address, not localhost

---

## 📞 Need Help?

Check browser console (F12) for detailed error messages!

**Files to configure:**
- `garuda-visualization.html` → Line 578: `API_BASE` URL
- `garuda_backend.py` → Last line: `host` and `port`

**Essential Commands:**
- Start backend: `python garudaa/garuda_backend.py`
- Start frontend: `python -m http.server 8000`
- Check IP: `ipconfig`
- Test backend: `http://localhost:5000/api/health`
