// Enhanced GARUDA Frontend with Error Handling

// Check if running from file:// protocol
const isFileProtocol = window.location.protocol === 'file:';
const API_BASE = isFileProtocol || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://127.0.0.1:5000' 
    : '/api';

console.log('API Base URL:', API_BASE);
console.log('Protocol:', window.location.protocol);

// Initialize particles
function initParticles() {
    const container = document.getElementById('particles');
    for (let i = 0; i < 50; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 10 + 's';
        particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
        container.appendChild(particle);
    }
}

// Flash screen effect
function flashScreen() {
    const flash = document.createElement('div');
    flash.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 255, 255, 0.3);
        z-index: 9999;
        pointer-events: none;
        animation: flashFade 0.5s ease-out;
    `;
    document.body.appendChild(flash);
    setTimeout(() => flash.remove(), 500);
}

function initiateScan() {
    const scanBtn = document.getElementById('scanBtn');
    const btnText = document.getElementById('btnText');
    const progressSection = document.getElementById('progressSection');
    const resultsSection = document.getElementById('resultsSection');
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const statusDisplay = document.getElementById('statusDisplay');

    scanBtn.disabled = true;
    btnText.textContent = '◈ SCANNING IN PROGRESS ◈';

    progressSection.classList.add('active');
    resultsSection.classList.remove('active');

    let progress = 0;
    const statusMessages = [
        '◈ INITIALIZING QUANTUM PROTOCOLS...',
        '◈ ESTABLISHING SECURE HANDSHAKE...',
        '◈ DEPLOYING NETWORK PROBES...',
        '◈ ANALYZING PACKET SIGNATURES...',
        '◈ SCANNING NETWORK TRAFFIC...',
        '◈ DETECTING CONNECTED DEVICES...',
        '◈ COMPILING SECURITY REPORT...',
        '◈ FINALIZING THREAT ASSESSMENT...'
    ];

    const scanInterval = setInterval(() => {
        progress += 12.5;
        if (progress > 100) progress = 100;

        progressBar.style.width = progress + '%';
        progressText.textContent = Math.round(progress) + '%';

        const statusIndex = Math.floor((progress / 100) * statusMessages.length);
        if (statusIndex < statusMessages.length) {
            statusDisplay.textContent = statusMessages[statusIndex];
        }

        if (progress >= 100) {
            clearInterval(scanInterval);
            fetchNetworkData();
        }
    }, 400);
}

function fetchNetworkData() {
    console.log('Fetching from:', `${API_BASE}/api/scan/full`);
    
    fetch(`${API_BASE}/api/scan/full`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        mode: 'cors'
    })
    .then(response => {
        console.log('Response status:', response.status);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('=== FULL SCAN DATA RECEIVED ===');
        console.log('Full data:', data);
        console.log('Connected network:', data.connected_network);
        console.log('Network traffic:', data.network_traffic);
        console.log('Connected devices:', data.connected_devices);
        console.log('================================');
        
        updateUI(data);
        showResults();
    })
    .catch(error => {
        console.error('Backend Error:', error);
        showError(`Cannot connect to backend server. Make sure Python backend is running on port 5000.\n\nError: ${error.message}`);
        
        // Show dummy data so UI still displays
        showDummyData();
        showResults();
    });
}

function showDummyData() {
    console.log('Showing dummy data due to backend connection failure');
    const dummyData = {
        status: 'success',
        timestamp: new Date().toISOString(),
        scan_duration: '3.2s',
        connected_network: {
            ssid: '[Backend Offline]',
            encryption: 'Unknown',
            signal: 'N/A',
            bssid: 'N/A',
            security_assessment: {
                threat_level: 'UNKNOWN',
                mitm_risk: 'UNKNOWN',
                exploit_risk: 'N/A',
                vulnerability: 'Backend connection failed',
                description: 'Cannot connect to Python backend server.',
                recommendation: 'Start backend: python garuda_backend.py'
            }
        },
        local_ip: 'Unknown',
        gateway: 'Unknown',
        nodes_detected: 0,
        addresses_scanned: 256,
        devices: [
            {
                ip: 'Backend',
                mac: 'Offline',
                type: 'GATEWAY NODE',
                vendor: 'N/A',
                status: 'OFFLINE',
                ports: [],
                threat_level: 'N/A'
            }
        ],
        network_traffic: {
            bytes_sent: 'N/A',
            bytes_received: 'N/A',
            packets_sent: 'N/A',
            packets_received: 'N/A'
        },
        connected_devices: [],
        security_summary: {
            threat_level: 'UNKNOWN',
            mitm_risk: 'UNKNOWN',
            recommendation: 'Start the Python backend server'
        }
    };
    
    updateUI(dummyData);
}

function updateUI(data) {
    console.log('Updating UI with data:', data);
    
    // Update stats
    updateStats(data);
    
    // Update devices - this is the key fix
    if (data && data.connected_network) {
        updateDeviceDisplay(data);
    } else {
        console.warn('No connected_network data received');
    }
    
    // Update threat alerts
    if (data.connected_network?.security_assessment) {
        updateThreatAlerts(data.connected_network.security_assessment);
    }
}

function updateStats(data) {
    const stats = document.querySelectorAll('.stat-number');
    if (stats[0]) stats[0].textContent = data.nodes_detected || '4';
    if (stats[2]) stats[2].textContent = data.addresses_scanned || '256';
    if (stats[3]) stats[3].textContent = data.scan_duration || '3.2s';
    
    // Update threat count based on security assessment
    const threatLevel = data.security_summary?.threat_level || 'UNKNOWN';
    if (stats[1]) {
        stats[1].textContent = ['CRITICAL', 'HIGH'].includes(threatLevel) ? '2' : '0';
        stats[1].style.color = threatLevel === 'CRITICAL' ? '#f00' : '#0f0';
    }
}

function updateDeviceDisplay(data) {
    const deviceGrid = document.querySelector('.device-grid');
    if (!deviceGrid) return;
    
    console.log('Device display data:', data);
    
    let deviceHTML = '';
    
    // 1. Gateway Node
    const gateway = data.devices?.find(d => d.type === 'GATEWAY NODE');
    if (gateway) {
        deviceHTML += createGatewayCard(gateway);
    } else {
        // Fallback gateway card
        deviceHTML += createGatewayCard({
            ip: data.gateway || '192.168.1.1',
            mac: data.connected_network?.bssid || 'Unknown',
            type: 'GATEWAY NODE',
            vendor: 'Router',
            status: 'ONLINE',
            ports: [22, 53, 80, 443],
            threat_level: 'SECURE'
        });
    }
    
    // 2. Current Device (This Device)
    const currentDevice = {
        ip: data.local_ip || '192.168.1.X',
        type: 'THIS DEVICE',
        status: 'ONLINE',
        network: data.connected_network?.ssid || 'Unknown Network',
        encryption: data.connected_network?.encryption || 'Unknown',
        signal: data.connected_network?.signal || 'N/A',
        bssid: data.connected_network?.bssid || 'N/A',
        threat_level: data.connected_network?.security_assessment?.threat_level || 'UNKNOWN'
    };
    
    console.log('Current device:', currentDevice);
    
    deviceHTML += createCurrentDeviceCard(currentDevice);
    
    // 3. Network Traffic Analysis
    const trafficData = data.network_traffic || {
        bytes_sent: 'N/A',
        bytes_received: 'N/A',
        packets_sent: 'N/A',
        packets_received: 'N/A'
    };
    deviceHTML += createTrafficAnalysisCard(trafficData);
    
    // 4. Connected Devices
    const connectedDevices = data.connected_devices || [];
    deviceHTML += createConnectedDevicesCard(connectedDevices);
    
    deviceGrid.innerHTML = deviceHTML;
    console.log('Device display updated successfully');
}

function createGatewayCard(device) {
    return `
        <div class="device-card">
            <div class="device-header">
                <span class="device-icon">◢</span>
                <span>${device.ip} - GATEWAY NODE</span>
            </div>
            <div class="device-info">
                <strong>STATUS:</strong> <span class="status-online">${device.status || 'ONLINE'}</span><br>
                <strong>MAC ID:</strong> ${device.mac || 'Unknown'}<br>
                <strong>VENDOR:</strong> ${device.vendor || 'Router'}<br>
                <strong>OPEN PORTS:</strong> ${device.ports?.join(', ') || '22, 53, 80, 443'}<br>
                <strong>THREAT LEVEL:</strong> <span style="color: #0f0;">${device.threat_level || 'SECURE'}</span>
            </div>
        </div>
    `;
}

function createCurrentDeviceCard(device) {
    const isCritical = device.threat_level === 'CRITICAL';
    const isHigh = device.threat_level === 'HIGH';
    const threatColor = isCritical ? '#f00' : (isHigh ? '#ff6600' : '#0ff');
    const cardClass = isCritical ? 'threat-high' : '';
    
    // Handle cases where data might be missing
    const networkName = device.network || 'Unknown Network';
    const encryption = device.encryption || 'Unknown';
    const signal = device.signal || 'N/A';
    const bssid = device.bssid || 'N/A';
    const threatLevel = device.threat_level || 'UNKNOWN';
    
    console.log('Creating current device card:', {
        networkName, encryption, signal, bssid, threatLevel
    });
    
    return `
        <div class="device-card ${cardClass}">
            <div class="device-header">
                <span class="device-icon" style="color: ${threatColor};">◢</span>
                <span>${device.ip} - ${device.type}</span>
            </div>
            <div class="device-info">
                <strong>STATUS:</strong> <span class="status-online">${device.status}</span><br>
                <strong>CONNECTED TO:</strong> <span style="color: #0ff; font-weight: 700;">${networkName}</span><br>
                <strong>ENCRYPTION:</strong> ${encryption}<br>
                <strong>SIGNAL:</strong> ${signal}<br>
                <strong>MAC ADDRESS:</strong> ${bssid}<br>
                <strong>THREAT LEVEL:</strong> <span style="color: ${threatColor};">${threatLevel}</span>
            </div>
        </div>
    `;
}

function createTrafficAnalysisCard(traffic) {
    const formatBytes = (bytes) => {
        if (bytes === 'N/A' || !bytes) return 'N/A';
        const num = parseInt(bytes);
        if (isNaN(num)) return bytes;
        if (num > 1073741824) return (num / 1073741824).toFixed(2) + ' GB';
        if (num > 1048576) return (num / 1048576).toFixed(2) + ' MB';
        if (num > 1024) return (num / 1024).toFixed(2) + ' KB';
        return num + ' B';
    };
    
    return `
        <div class="device-card threat-medium">
            <div class="device-header">
                <span class="device-icon" style="color: #0ff;">◢</span>
                <span>NETWORK TRAFFIC ANALYSIS</span>
            </div>
            <div class="device-info">
                <strong>STATUS:</strong> <span class="status-online">MONITORING</span><br>
                <strong>BYTES SENT:</strong> ${formatBytes(traffic.bytes_sent)}<br>
                <strong>BYTES RECEIVED:</strong> ${formatBytes(traffic.bytes_received)}<br>
                <strong>PACKETS SENT:</strong> ${traffic.packets_sent}<br>
                <strong>PACKETS RECEIVED:</strong> ${traffic.packets_received}<br>
                <strong>ANALYSIS:</strong> <span style="color: #0ff;">ACTIVE</span>
            </div>
        </div>
    `;
}

function createConnectedDevicesCard(devices) {
    const deviceCount = devices.length;
    
    // Create a more detailed list
    let deviceList = '';
    if (deviceCount === 0) {
        deviceList = '<span style="color: #888;">No additional devices detected</span>';
    } else if (deviceCount <= 5) {
        // Show all devices if 5 or fewer
        deviceList = devices.map(d => 
            `<div style="margin: 5px 0; padding: 5px; background: rgba(0,255,255,0.1); border-left: 2px solid #0ff;">
                <strong>${d.ip}</strong><br>
                MAC: ${d.mac}<br>
                Status: <span style="color: #0f0;">${d.status}</span>
            </div>`
        ).join('');
    } else {
        // Show first 3 and indicate more
        deviceList = devices.slice(0, 3).map(d => 
            `<div style="margin: 5px 0; padding: 5px; background: rgba(0,255,255,0.1); border-left: 2px solid #0ff;">
                <strong>${d.ip}</strong><br>
                MAC: ${d.mac}<br>
                Status: <span style="color: #0f0;">${d.status}</span>
            </div>`
        ).join('') + `<div style="margin: 10px 0; color: #0ff; font-style: italic;">+ ${deviceCount - 3} more devices...</div>`;
    }
    
    return `
        <div class="device-card">
            <div class="device-header">
                <span class="device-icon">◢</span>
                <span>CONNECTED DEVICES (${deviceCount})</span>
            </div>
            <div class="device-info">
                <strong>STATUS:</strong> <span class="status-online">DETECTED</span><br>
                <strong>TOTAL DEVICES:</strong> ${deviceCount}<br>
                <strong>DEVICE LIST:</strong><br>
                <div style="margin-top: 10px;">
                    ${deviceList}
                </div>
                <strong>SCAN STATUS:</strong> <span style="color: #0f0;">COMPLETE</span>
            </div>
        </div>
    `;
}

function updateThreatAlerts(assessment) {
    const threatAlert = document.querySelector('.threat-alert');
    if (!threatAlert) return;
    
    const isCritical = assessment.threat_level === 'CRITICAL';
    
    threatAlert.innerHTML = `
        <span class="threat-badge ${isCritical ? '' : 'medium'}">
            ⚠ ${assessment.threat_level} THREAT
        </span>
        <div class="threat-title">${assessment.vulnerability}</div>
        <div class="threat-details">
            <strong>DESCRIPTION:</strong> ${assessment.description}<br>
            <strong>MITM RISK:</strong> ${assessment.mitm_risk}<br>
            <strong>EXPLOITATION PROBABILITY:</strong> ${assessment.exploit_risk}<br>
            <strong>RECOMMENDED ACTION:</strong> ${assessment.recommendation}
        </div>
    `;
}

function showError(message) {
    const statusDisplay = document.getElementById('statusDisplay');
    if (statusDisplay) {
        statusDisplay.textContent = `⚠ ERROR: ${message}`;
        statusDisplay.style.color = '#f00';
    }
    
    // Also show in console
    console.error('GARUDA Error:', message);
    
    // Show alert with instructions
    const alertDiv = document.createElement('div');
    alertDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: linear-gradient(135deg, rgba(255, 0, 0, 0.9), rgba(139, 0, 0, 0.9));
        border: 3px solid #f00;
        border-radius: 5px;
        padding: 20px;
        color: #fff;
        font-family: 'Rajdhani', sans-serif;
        max-width: 400px;
        z-index: 10000;
        box-shadow: 0 0 30px rgba(255, 0, 0, 0.5);
        animation: slideInRight 0.5s ease;
    `;
    
    alertDiv.innerHTML = `
        <div style="font-size: 18px; font-weight: 700; margin-bottom: 10px;">
            ⚠ BACKEND CONNECTION FAILED
        </div>
        <div style="font-size: 14px; line-height: 1.6;">
            ${message.replace('\n\n', '<br><br>')}
        </div>
        <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.3); font-size: 12px;">
            <strong>To fix this:</strong><br>
            1. Open terminal/command prompt<br>
            2. Run: <code style="background: rgba(0,0,0,0.3); padding: 2px 5px; border-radius: 3px;">python garuda_backend.py</code><br>
            3. Wait for "Running on http://127.0.0.1:5000"<br>
            4. Click RESCAN NETWORK
        </div>
        <button onclick="this.parentElement.remove()" style="
            margin-top: 15px;
            background: rgba(255,255,255,0.2);
            border: 2px solid #fff;
            color: #fff;
            padding: 8px 15px;
            cursor: pointer;
            border-radius: 3px;
            font-family: 'Orbitron', sans-serif;
            font-size: 12px;
        ">CLOSE</button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 15 seconds
    setTimeout(() => {
        if (alertDiv.parentElement) {
            alertDiv.remove();
        }
    }, 15000);
}

function showResults() {
    const scanBtn = document.getElementById('scanBtn');
    const btnText = document.getElementById('btnText');
    const progressSection = document.getElementById('progressSection');
    const resultsSection = document.getElementById('resultsSection');
    
    setTimeout(() => {
        progressSection.classList.remove('active');
        resultsSection.classList.add('active');
        
        scanBtn.disabled = false;
        btnText.textContent = '◈ RESCAN NETWORK ◈';
        
        flashScreen();
    }, 800);
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
    initParticles();
    console.log('GARUDA System Initialized');
    console.log('Checking backend connection...');
    
    // Test backend connection
    fetch(`${API_BASE}/api/health`, {
        method: 'GET',
        mode: 'cors'
    })
    .then(response => response.json())
    .then(data => {
        console.log('✓ Backend connected:', data);
        console.log('✓ System:', data.system);
        console.log('✓ Status:', data.status);
    })
    .catch(error => {
        console.error('✗ Backend connection failed:', error);
        console.error('✗ Make sure to run: python garuda_backend.py');
        console.error('✗ Expected backend at:', API_BASE);
    });
});