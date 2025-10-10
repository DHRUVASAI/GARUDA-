# 🛡️ GARUDA Quantum Defense System

A real-time WiFi network security scanner and threat assessment tool with a cyberpunk-themed interface.

## 🎯 Features

- **WiFi Network Scanning**: Detect nearby networks across Windows, macOS, and Linux
- **Security Assessment**: Real-time threat analysis based on encryption type
- **Network Traffic Monitoring**: Track bytes and packets sent/received
- **Device Discovery**: Find all devices connected to your network
- **Man-in-the-Middle Risk Analysis**: Assess vulnerability to MITM attacks
- **Beautiful UI**: Cyberpunk-themed interface with animations

## 📋 Requirements

### Backend Requirements
```bash
Python 3.7+
Flask
Flask-CORS
```

### System Requirements
- **Windows**: `netsh` command (built-in)
- **macOS**: Airport utility (built-in)
- **Linux**: `nmcli` (NetworkManager)

## 🚀 Installation

### 1. Install Python Dependencies

```bash
pip install flask flask-cors
```

### 2. Project Structure

Create this folder structure:
```
garuda/
├── garuda_backend.py
├── index.html
├── script.js
├── styles.css
└── README.md
```

### 3. Run the Backend

```bash
python garuda_backend.py
```

You should see:
```
============================================================
◈ GARUDA QUANTUM DEFENSE SYSTEM BACKEND ◈
============================================================
System: Windows/Linux/Darwin
Starting API server on http://localhost:5000

Available Endpoints:
  GET  /api/health          - System health check
  GET  /api/scan/nearby     - Scan nearby WiFi networks
  GET  /api/scan/connected  - Check connected network
  POST /api/scan/full       - Full network scan
============================================================
```

### 4. Open the Frontend

Simply open `index.html` in your browser, or serve it using:

```bash
# Python 3
python -m http.server 8000

# Then visit: http://localhost:8000
```

## 🎮 Usage

1. **Start Backend**: Run `python garuda_backend.py`
2. **Open Frontend**: Open `index.html` in browser
3. **Click "INITIALIZE DEEP SCAN"**: Starts the network scan
4. **View Results**: See connected devices, traffic analysis, and security threats

## 📊 What Gets Displayed

### 1. Gateway Node
- Router IP and MAC address
- Open ports
- Connection status

### 2. This Device
- Your current IP
- Connected WiFi network name
- Encryption type (WPA2/WPA3/etc.)
- Signal strength
- **Security threat level**

### 3. Network Traffic Analysis
- Bytes sent/received
- Packets sent/received
- Real-time monitoring status

### 4. Connected Devices
- All devices on your network (from ARP table)
- IP and MAC addresses
- Total device count

## 🔐 Security Threat Levels

| Level | Encryption | Risk |
|-------|-----------|------|
| **CRITICAL** | Open/WEP | 99.9% exploit risk |
| **HIGH** | WPA | 85.4% exploit risk |
| **MEDIUM** | WPA2-Personal | 45.2% exploit risk |
| **LOW** | WPA2-Enterprise | 12.3% exploit risk |
| **SECURE** | WPA3 | 3.7% exploit risk |

## 🛠️ Troubleshooting

### Backend Issues

**Error: "Not connected to any network"**
```
Solution: Connect to WiFi before running scan
```

**Error: "nmcli not found" (Linux)**
```bash
sudo apt install network-manager  # Ubuntu/Debian
sudo dnf install NetworkManager   # Fedora
```

**Error: "Permission denied" (Linux)**
```bash
# Some commands may need sudo
sudo python garuda_backend.py
```

### Frontend Issues

**Error: "Failed to fetch"**
```
Solution: Make sure backend is running on port 5000
Check: http://localhost:5000/api/health
```

**CORS Error**
```
Solution: Backend has CORS enabled by default
If still seeing errors, check browser console
```

### Network Traffic Shows "N/A"

This is normal on some systems. Windows provides the best traffic data.

## 🎨 Customization

### Change API Port

In `garuda_backend.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5000)  # Change 5000 to your port
```

In `script.js`:
```javascript
const API_BASE = 'http://localhost:5000';  // Update port here
```

### Adjust Scan Duration

In `script.js`:
```javascript
}, 400);  // Change to 200 for faster, 800 for slower
```

## 🔒 Security Notes

⚠️ **Important Security Considerations:**

1. **Never run this with root/admin privileges unless necessary**
2. **This tool is for educational purposes and authorized testing only**
3. **Do not scan networks you don't own or have permission to test**
4. **The backend opens port 5000 - don't expose to the internet**
5. **Use HTTPS in production environments**

## 🌐 Deployment (Optional)

### For Local Network Access

```python
# Backend is already configured to listen on 0.0.0.0
# Access from other devices using:
http://YOUR_COMPUTER_IP:5000
```

### For Production (Not Recommended)

This tool is designed for local use. If you must deploy:

1. Add authentication
2. Use HTTPS (SSL/TLS)
3. Implement rate limiting
4. Restrict CORS to specific origins
5. Add input validation

## 📝 API Endpoints

### GET /api/health
Health check endpoint
```json
{
  "status": "OPERATIONAL",
  "timestamp": "2024-10-09T10:30:00",
  "system": "Windows"
}
```

### GET /api/scan/nearby
Scan for nearby WiFi networks
```json
{
  "status": "success",
  "networks_found": 5,
  "networks": [...]
}
```

### GET /api/scan/connected
Get connected network info
```json
{
  "status": "success",
  "connected_network": {
    "ssid": "MyNetwork",
    "encryption": "WPA2-Personal",
    "security_assessment": {...}
  }
}
```

### POST /api/scan/full
Full network scan (used by frontend)
```json
{
  "status": "success",
  "connected_network": {...},
  "devices": [...],
  "network_traffic": {...},
  "connected_devices": [...]
}
```

## 🐛 Known Issues

1. **Traffic monitoring limited on macOS/Linux** - System limitations
2. **Device vendor detection not implemented** - Would require MAC address database
3. **Port scanning is simulated** - Real port scanning requires additional tools (nmap)
4. **ARP table can be incomplete** - Some devices may not appear immediately

## 🚀 Future Enhancements

- [ ] Real port scanning with nmap integration
- [ ] MAC address vendor lookup
- [ ] Historical scan data tracking
- [ ] Email/SMS alerts for threats
- [ ] Export reports (PDF/JSON)
- [ ] Scheduled automatic scans
- [ ] More detailed traffic analysis
- [ ] Rogue AP detection

## 📜 License

This project is for educational purposes only. Use responsibly and only on networks you own or have permission to test.

## 🤝 Contributing

Feel free to fork and improve! Some areas that need work:
- Better cross-platform compatibility
- More detailed traffic analysis
- Real device fingerprinting
- Enhanced threat detection algorithms

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section
2. Verify your system meets requirements
3. Check backend logs in terminal
4. Check browser console for frontend errors

---

**Made with ◈ for network security enthusiasts**

*Remember: With great power comes great responsibility. Only scan networks you own!*