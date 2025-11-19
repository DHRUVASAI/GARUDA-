# 🚀 GARUDA - QUICK START GUIDE

## Choose Your Deployment Method

### ⚡ FASTEST: Automated Local Setup (1 minute)

**For testing and demos:**

1. **Double-click** `start_garuda.bat` (or run `.\start_garuda.ps1`)
2. **Select option 1** (Local Deployment)
3. **Browser opens automatically** → Start scanning!

---

### 🌐 RECOMMENDED: Hybrid Deployment (5 minutes)

**For professional use - backend on your network, frontend on GitHub Pages:**

#### Step 1: Configure Backend URL
```powershell
.\update_api_url.ps1
# Select option 2 (Local network)
# Note the IP address shown
```

#### Step 2: Start Backend
```powershell
.\start_garuda.ps1
# Select option 3 (Backend only)
# Keep this running
```

#### Step 3: Deploy Frontend to GitHub
```powershell
git add .
git commit -m "Configure for local backend"
git push origin master
```

#### Step 4: Enable GitHub Pages
1. Go to: `https://github.com/DHRUVASAI/FEDF_30009/settings/pages`
2. Source: **master** → Folder: **/ (root)**
3. Click **Save**
4. Wait 2-3 minutes

#### Step 5: Access Your App
- URL: `https://dhruvasai.github.io/FEDF_30009/garudaa/garuda-visualization.html`
- **Important:** Your device must be on the same WiFi network as the backend

---

### 🏠 SIMPLEST: Fully Local (2 minutes)

**Everything on your computer:**

```powershell
# Terminal 1
python garudaa\garuda_backend.py

# Terminal 2
cd garudaa
python -m http.server 8000

# Open browser
http://localhost:8000/garuda-visualization.html
```

---

## 📱 Access from Other Devices

**On same WiFi network:**

1. **Find your IP:**
   ```powershell
   ipconfig
   # Look for IPv4 Address: e.g., 192.168.1.100
   ```

2. **Start backend:**
   ```powershell
   .\start_garuda.ps1
   # Select option 2 (Network Deployment)
   ```

3. **On phone/tablet, open:**
   ```
   http://192.168.1.100:8000/garuda-visualization.html
   ```

---

## 🔧 Quick Troubleshooting

### Problem: Backend won't start
```powershell
# Check if port is in use
netstat -ano | findstr :5000

# Kill the process
taskkill /PID <PID> /F

# Try again
python garudaa\garuda_backend.py
```

### Problem: Can't access from phone
- ✅ Both devices on same WiFi?
- ✅ Windows Firewall allows port 5000?
  ```powershell
  # Add firewall rule
  New-NetFirewallRule -DisplayName "GARUDA" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
  ```
- ✅ Using IP address (not localhost)?

### Problem: CORS errors
- ✅ Use `http://` for both frontend and backend
- ✅ OR install "Allow CORS" browser extension
- ✅ OR use local deployment (both localhost)

### Problem: No devices detected
- ✅ Run as Administrator
- ✅ Windows Defender Firewall → Allow app
- ✅ Connected to WiFi?

---

## 📦 What Each File Does

| File | Purpose |
|------|---------|
| `start_garuda.bat` | Automated Windows launcher |
| `start_garuda.ps1` | PowerShell launcher with menu |
| `update_api_url.ps1` | Change backend URL easily |
| `app.py` | Railway/cloud deployment entry |
| `garudaa/garuda_backend.py` | Flask backend server |
| `garudaa/garuda-visualization.html` | Main dashboard UI |
| `DEPLOYMENT_GUIDE.md` | Complete deployment options |

---

## 🎯 Common Use Cases

### Use Case 1: Class Demo
```powershell
.\start_garuda.bat
# Select option 1
# Show on projector
```

### Use Case 2: Home Network Monitoring
```powershell
# Setup once:
.\start_garuda.ps1  # Select option 2
# Bookmark: http://YOUR_IP:8000/garuda-visualization.html
# Access from any device at home
```

### Use Case 3: Project Presentation
```powershell
# Deploy to GitHub Pages (frontend)
# Run backend locally during presentation
.\start_garuda.ps1  # Select option 3
# Share GitHub Pages link with audience
```

### Use Case 4: Raspberry Pi Server
```bash
# On Raspberry Pi - runs 24/7
git clone https://github.com/DHRUVASAI/FEDF_30009.git
cd FEDF_30009
pip3 install flask flask-cors
python3 garudaa/garuda_backend.py
# Access from anywhere on your network
```

---

## ⚙️ Advanced Configuration

### Change Backend Port
Edit `garudaa/garuda_backend.py` (last line):
```python
app.run(debug=False, host='0.0.0.0', port=8080)  # Change 5000 to 8080
```

### Add Authentication
```python
# In garuda_backend.py
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    return username == "admin" and password == "secret"

@app.route('/api/scan/full')
@auth.login_required
def full_scan():
    # ...
```

### Enable HTTPS
```powershell
# Generate certificate
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

# In garuda_backend.py
app.run(ssl_context=('cert.pem', 'key.pem'))
```

---

## 📊 Understanding Scan Results

### Dashboard Tab
- **Connected Devices:** Total devices detected
- **Threat Level:** Based on WiFi encryption
- **Network Status:** Backend connection status
- **Scan Status:** Current operation status

### Topology Tab
- **Green node:** Your router/gateway
- **Yellow node:** Your device
- **Cyan nodes:** Other network devices
- **Lines:** Network connections

### Analytics Tab
- **Device Types:** Router, computer, phone, IoT
- **Security Vulnerabilities:** Detected issues
- **Signal Strength:** WiFi signal distribution
- **Network Performance:** Latency and bandwidth

---

## 🔐 Security Notes

- ⚠️ **Only scan networks you own or have permission to scan**
- ⚠️ **Don't expose backend to internet without authentication**
- ⚠️ **Use HTTPS for production deployments**
- ⚠️ **Keep logs private - contain network information**

---

## 📚 Full Documentation

- **Detailed Deployment:** `DEPLOYMENT_GUIDE.md`
- **Deployment Checklist:** `DEPLOYMENT_CHECKLIST.md`
- **Project README:** `garudaa/README.md`

---

## 🆘 Still Need Help?

1. **Check browser console** (Press F12)
2. **Check backend terminal** for error messages
3. **Test health endpoint:** `http://localhost:5000/api/health`
4. **Review logs** in terminal where backend is running

---

**Last Updated:** November 19, 2025  
**Project:** GARUDA - Gateway Analysis & Response Unit for Device Audit
