import os
import sys
import math
import struct
import wave
import subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

WORK_DIR = Path(r"C:\Users\dhruv\Downloads\GARUDA--main\GARUDA--main\brag-output\work")
OUT_DIR = Path(r"C:\Users\dhruv\Downloads\GARUDA--main\GARUDA--main\brag-output")
WORK_DIR.mkdir(parents=True, exist_ok=True)
OUT_DIR.mkdir(parents=True, exist_ok=True)

FFMPEG_EXE = r"C:\Users\dhruv\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-9.0.2-full_build\bin\ffmpeg.exe"
if not os.path.exists(FFMPEG_EXE):
    FFMPEG_EXE = "ffmpeg"

WIDTH = 1920
HEIGHT = 1080
FPS = 30
TOTAL_FRAMES = 1800  # Exactly 60.0 seconds
SAMPLE_RATE = 44100

print(f"[+] 1. Synthesizing 60-Second Cyber-Electronic Soundtrack (120 BPM, {TOTAL_FRAMES} frames)...")

audio_path = WORK_DIR / "audio_60s.wav"
num_samples = int(SAMPLE_RATE * (TOTAL_FRAMES / FPS))
audio_left = [0.0] * num_samples
audio_right = [0.0] * num_samples

bpm = 120.0
spb = (60.0 / bpm) * SAMPLE_RATE  # 22050 samples per beat
beats = int(num_samples / spb)    # 120 beats total

# Chord progression root frequencies: D minor (D1, F1, G1, A1, Bb1, C2)
bass_progression = [36.71, 36.71, 43.65, 48.99, 36.71, 36.71, 58.27, 55.00]
arp_notes_pool = [
    [293.66, 349.23, 440.00, 523.25, 587.33, 440.00, 349.23, 293.66],  # Dm
    [349.23, 440.00, 523.25, 698.46, 523.25, 440.00, 349.23, 261.63],  # F
    [392.00, 466.16, 587.33, 783.99, 587.33, 466.16, 392.00, 293.66],  # Gm
    [440.00, 554.37, 659.25, 880.00, 659.25, 554.37, 440.00, 329.63],  # A
]

for b in range(beats):
    beat_start = int(b * spb)
    bar = b // 4
    
    # 1. Kick Drum (Starts soft in bar 0-1, drives continuously from bar 2 onwards)
    if b >= 4 and b < 116:
        kick_len = int(SAMPLE_RATE * 0.24)
        for i in range(min(kick_len, num_samples - beat_start)):
            t = i / SAMPLE_RATE
            env = math.exp(-t * 20.0)
            freq = 160.0 * math.exp(-t * 32.0) + 40.0
            val = math.sin(2.0 * math.pi * freq * t) * env * 0.85
            idx = beat_start + i
            audio_left[idx] += val
            audio_right[idx] += val

    # 2. Snare / Clap on beats 2 and 4 of each 4-beat bar (from bar 4 onwards)
    if b >= 14 and b < 114 and (b % 2 == 1):
        snare_len = int(SAMPLE_RATE * 0.22)
        for i in range(min(snare_len, num_samples - beat_start)):
            t = i / SAMPLE_RATE
            env = math.exp(-t * 16.0)
            noise = ((math.sin(i * 1234.567) * 43758.5453) % 2.0) - 1.0
            tone = math.sin(2.0 * math.pi * 195.0 * t) * 0.45
            val = (noise * 0.65 + tone) * env * 0.50
            idx = beat_start + i
            audio_left[idx] += val * 0.95
            audio_right[idx] += val * 0.95

    # 3. Hi-hats on 8th and 16th notes
    if b >= 8 and b < 116:
        sub_steps = 4 if b >= 30 else 2
        for s in range(sub_steps):
            hh_start = beat_start + int(s * (spb / sub_steps))
            hh_len = int(SAMPLE_RATE * 0.04)
            for i in range(min(hh_len, num_samples - hh_start)):
                t = i / SAMPLE_RATE
                env = math.exp(-t * 70.0)
                noise = ((math.sin((hh_start + i) * 876.54) * 31415.9) % 2.0) - 1.0
                vol = 0.22 if s % 2 == 0 else 0.14
                val = noise * env * vol
                idx = hh_start + i
                if idx < num_samples:
                    audio_left[idx] += val * 0.75
                    audio_right[idx] += val * 1.0

    # 4. Bassline
    prog_idx = (b // 2) % len(bass_progression)
    b_note = bass_progression[prog_idx]
    bass_len = int(spb * 0.88)
    for i in range(min(bass_len, num_samples - beat_start)):
        t = i / SAMPLE_RATE
        env = math.sin(math.pi * (i / bass_len)) ** 0.6
        val = (math.sin(2 * math.pi * b_note * t) + 0.35 * math.sin(4 * math.pi * b_note * t)) * env * 0.38
        idx = beat_start + i
        if idx < num_samples:
            audio_left[idx] += val
            audio_right[idx] += val

    # 5. Cyber Arpeggio (16th notes, 4 per beat)
    if b >= 4 and b < 116:
        active_arp = arp_notes_pool[bar % len(arp_notes_pool)]
        for sub in range(4):
            arp_start = beat_start + int(sub * (spb / 4))
            a_note = active_arp[(b * 4 + sub) % len(active_arp)]
            note_len = int(spb * 0.20)
            pan = 0.5 + 0.35 * math.sin((b * 4 + sub) * 0.6)
            for i in range(min(note_len, num_samples - arp_start)):
                t = i / SAMPLE_RATE
                env = math.exp(-t * 22.0)
                val = math.sin(2 * math.pi * a_note * t) * env * 0.18
                idx = arp_start + i
                if idx < num_samples:
                    audio_left[idx] += val * (1.0 - pan)
                    audio_right[idx] += val * pan

# 6. Scene Transition Impacts & Sub-Drops
transitions = [0, 210, 450, 690, 930, 1200, 1530]
for frame_idx in transitions:
    trans_sample = int((frame_idx / FPS) * SAMPLE_RATE)
    drop_len = int(SAMPLE_RATE * 0.65)
    for i in range(min(drop_len, num_samples - trans_sample)):
        t = i / SAMPLE_RATE
        env = math.exp(-t * 6.5)
        freq = 190.0 * math.exp(-t * 10.0) + 28.0
        val = math.sin(2 * math.pi * freq * t) * env * 0.70
        idx = trans_sample + i
        if idx < num_samples:
            audio_left[idx] += val
            audio_right[idx] += val

# Limiter & Write WAV
with wave.open(str(audio_path), "w") as wav_file:
    wav_file.setnchannels(2)
    wav_file.setsampwidth(2)
    wav_file.setframerate(SAMPLE_RATE)
    
    frames_data = bytearray()
    for l, r in zip(audio_left, audio_right):
        l_sat = math.tanh(l * 1.1) * 30000.0
        r_sat = math.tanh(r * 1.1) * 30000.0
        frames_data.extend(struct.pack("<hh", int(l_sat), int(r_sat)))
    wav_file.writeframes(frames_data)

print(f"[+] Audio track synthesized: {audio_path} (60.0s, 44.1kHz)")

# ==============================================================================
# 2. Rendering 1800 Frames & Piping directly to FFmpeg
# ==============================================================================
print(f"[+] 2. Setting up fonts and screenshots...")

font_huge = None
font_title = None
font_sub = None
font_body = None
font_mono = None
font_tiny = None

for font_path in [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"]:
    if os.path.exists(font_path):
        font_huge = ImageFont.truetype(font_path, 74)
        font_title = ImageFont.truetype(font_path, 48)
        font_sub = ImageFont.truetype(font_path, 30)
        font_body = ImageFont.truetype(font_path, 24)
        font_mono = ImageFont.truetype(font_path, 20)
        font_tiny = ImageFont.truetype(font_path, 16)
        break

if not font_huge:
    font_huge = font_title = font_sub = font_body = font_mono = font_tiny = ImageFont.load_default()

# Load Screenshots
shot_radar = None
shot_devices = None
radar_path = Path(r"C:\Users\dhruv\.gemini\antigravity\brain\a32c7978-dfc6-41fc-ad3d-1de47a97dc5a\browser_evidence\e4b8ba72-e179-4d93-8132-c4d859c9fa1c\final_step_18.png")
devices_path = Path(r"C:\Users\dhruv\.gemini\antigravity\brain\a32c7978-dfc6-41fc-ad3d-1de47a97dc5a\browser_evidence\f6ddc925-80fd-4b35-9a4e-669054fabef0\final_step_79.png")

if radar_path.exists():
    try:
        shot_radar = Image.open(radar_path).convert("RGBA")
    except Exception:
        pass

if devices_path.exists():
    try:
        shot_devices = Image.open(devices_path).convert("RGBA")
    except Exception:
        pass

def draw_cyber_grid(draw, frame_idx):
    offset = (frame_idx * 3) % 80
    grid_color = (18, 28, 48, 110)
    for x in range(0, WIDTH + 80, 80):
        draw.line([(x - offset, 0), (x - offset, HEIGHT)], fill=grid_color, width=1)
    for y in range(0, HEIGHT + 80, 80):
        draw.line([(0, y), (WIDTH, y)], fill=grid_color, width=1)
    
    # Top status bar
    draw.line([(0, 64), (WIDTH, 64)], fill=(14, 165, 233, 90), width=1)
    draw.text((60, 22), "GARUDA // AUTONOMOUS NETWORK GUARDIAN", fill=(14, 165, 233), font=font_mono)
    draw.text((WIDTH - 640, 22), "OFF CAMPUS BY AWS · GROWTHX · REAL PACKET IDS", fill=(16, 185, 129), font=font_mono)

def draw_card(draw, x, y, w, h, bg_color, border_color, radius=12):
    draw.rounded_rectangle([x, y, x + w, y + h], radius=radius, fill=bg_color, outline=border_color, width=2)

def draw_badge(draw, x, y, text, bg=(14, 165, 233, 50), fg=(56, 189, 248)):
    bbox = font_mono.getbbox(text)
    bw = (bbox[2] - bbox[0]) + 18
    bh = 30
    draw.rounded_rectangle([x, y, x + bw, y + bh], radius=6, fill=bg, outline=fg, width=1)
    draw.text((x + 9, y + 4), text, fill=fg, font=font_mono)
    return bw

OUT_MP4 = OUT_DIR / "brag.mp4"
POSTER_JPG = OUT_DIR / "brag.jpg"

print(f"[+] 3. Launching FFmpeg encoder pipeline -> {OUT_MP4} ...")

ffmpeg_cmd = [
    FFMPEG_EXE,
    "-y",
    "-f", "rawvideo",
    "-vcodec", "rawvideo",
    "-s", f"{WIDTH}x{HEIGHT}",
    "-pix_fmt", "rgb24",
    "-r", str(FPS),
    "-i", "-",
    "-i", str(audio_path),
    "-c:v", "libx264",
    "-preset", "fast",
    "-crf", "18",
    "-pix_fmt", "yuv420p",
    "-c:a", "aac",
    "-b:a", "192k",
    "-shortest",
    str(OUT_MP4)
]

ffmpeg_proc = subprocess.Popen(ffmpeg_cmd, stdin=subprocess.PIPE)

poster_frame_image = None
best_poster_frame_idx = 1620  # Scene 7 with the big shield and AWS Off Campus banner

print(f"[+] 4. Rendering {TOTAL_FRAMES} frames...")

for frame in range(TOTAL_FRAMES):
    im = Image.new("RGBA", (WIDTH, HEIGHT), (8, 12, 20, 255))
    draw = ImageDraw.Draw(im)
    draw_cyber_grid(draw, frame)

    # -------------------------------------------------------------
    # SCENE 1: THE HOOK & INTRODUCTION (Frames 0 - 209 / 0.0s - 7.0s)
    # -------------------------------------------------------------
    if frame < 210:
        cx, cy = WIDTH // 2, HEIGHT // 2 - 20
        angle = frame * 0.12
        for r in (140, 260, 380):
            draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(14, 165, 233, 70), width=2)
        
        # Rotating Radar Beam
        bx = cx + 380 * math.cos(angle)
        by = cy + 380 * math.sin(angle)
        draw.line([(cx, cy), (bx, by)], fill=(56, 189, 248, 220), width=3)
        
        # Pulsing Red Threat Blips
        t_pulse = 0.5 + 0.5 * math.sin(frame * 0.3)
        rad = int(8 + t_pulse * 6)
        draw.ellipse([cx + 180 - rad, cy - 120 - rad, cx + 180 + rad, cy - 120 + rad], fill=(239, 68, 68), outline=(255, 255, 255))
        draw.ellipse([cx - 240 - rad, cy + 140 - rad, cx - 240 + rad, cy + 140 + rad], fill=(239, 68, 68), outline=(255, 255, 255))
        draw.ellipse([cx + 260 - rad, cy + 180 - rad, cx + 260 + rad, cy + 180 + rad], fill=(239, 68, 68), outline=(255, 255, 255))

        # Typography
        draw.text((cx - 560, cy - 80), "YOUR WI-FI ROUTER IS COMPLETELY BLIND.", fill=(255, 255, 255), font=font_huge)
        draw.text((cx - 430, cy + 20), "Enterprise SIEMs cost $100,000 / year.", fill=(244, 63, 94), font=font_sub)
        draw.text((cx - 490, cy + 90), "Meet GARUDA — Autonomous Personal Network Defense.", fill=(14, 165, 233), font=font_title)
        
        # Bottom Badges
        draw_badge(draw, cx - 380, cy + 200, "OFF CAMPUS BY AWS", bg=(245, 158, 11, 40), fg=(251, 191, 36))
        draw_badge(draw, cx - 110, cy + 200, "GROWTHX", bg=(168, 85, 247, 40), fg=(192, 132, 252))
        draw_badge(draw, cx + 80, cy + 200, "REAL-TIME SCAPY IDS", bg=(16, 185, 129, 40), fg=(52, 211, 153))

    # -------------------------------------------------------------
    # SCENE 2: 5-LAYER HARDWARE DISCOVERY (Frames 210 - 449 / 7.0s - 15.0s)
    # -------------------------------------------------------------
    elif frame < 450:
        rel = frame - 210
        draw.text((100, 100), "100% REAL HARDWARE RECOGNITION", fill=(255, 255, 255), font=font_huge)
        draw.text((105, 195), "5-Layer Pipeline: mDNS · SSDP UPnP XML · DHCP Opt 12 · NetBIOS · 35k OUI Cache", fill=(56, 189, 248), font=font_sub)
        draw.text((105, 245), "Zero 'Unknown Device' labels. Real names, real vendors, live latency & security trust bands.", fill=(148, 163, 184), font=font_body)

        devices = [
            ("omen (This Computer)", "AzureWave / HP Wi-Fi · 192.168.1.13", "Windows 11 Laptop · 1.2ms", (14, 165, 233), "SAFE"),
            ("Zyxel / Airtel Fiber Router", "Main Wi-Fi Gateway · 192.168.1.1", "Wi-Fi 6 Gateway · 0.8ms", (234, 179, 8), "ROUTER"),
            ("[LG] webOS TV UK6360PTE", "LG Electronics · 192.168.1.2", "4K Smart TV · 4.5ms", (168, 85, 247), "SAFE"),
            ("Canon G4070 series Printer", "Canon Inc. · 192.168.1.17", "IPP Office Printer · 12ms", (16, 185, 129), "SAFE"),
            ("realme-13-Pro-5G", "Realme Mobile · 192.168.1.5", "Android 14 Phone · 18ms", (59, 130, 246), "UNVERIFIED"),
        ]

        for i, (name, meta, dtype, col, trust) in enumerate(devices):
            slide = min(1.0, max(0.0, (rel - i * 10) / 14.0))
            if slide > 0.0:
                card_x = int(100 + (1.0 - slide) * 80)
                card_y = 310 + i * 135
                card_w = WIDTH - 200
                card_h = 115

                bg_col = (15, 23, 42, int(230 * slide))
                border_col = (col[0], col[1], col[2], int(255 * slide))
                draw_card(draw, card_x, card_y, card_w, card_h, bg_col, border_col)

                # Color accent bar
                draw.rectangle([card_x, card_y, card_x + 8, card_y + card_h], fill=col)

                # Texts
                draw.text((card_x + 35, card_y + 20), name, fill=(255, 255, 255), font=font_title)
                draw.text((card_x + 35, card_y + 70), meta, fill=(148, 163, 184), font=font_body)
                draw.text((card_x + card_w - 460, card_y + 40), dtype, fill=(203, 213, 225), font=font_body)
                
                # Trust badge
                t_col = (16, 185, 129) if trust == "SAFE" else ((234, 179, 8) if trust == "UNVERIFIED" else (14, 165, 233))
                draw_badge(draw, card_x + card_w - 180, card_y + 35, trust, bg=(t_col[0], t_col[1], t_col[2], 40), fg=t_col)

    # -------------------------------------------------------------
    # SCENE 3: REAL-TIME SCAPY PACKET IDS (Frames 450 - 689 / 15.0s - 23.0s)
    # -------------------------------------------------------------
    elif frame < 690:
        rel = frame - 450
        draw.text((100, 100), "LIVE SCAPY L2-L7 PACKET IDS", fill=(255, 255, 255), font=font_huge)
        draw.text((105, 195), "Raw socket promisc filter sniffing live Ethernet, IP, TCP, UDP & DNS layers", fill=(239, 68, 68), font=font_sub)
        draw.text((105, 245), "Deterministic stateful detection against modern LAN exploitation vectors.", fill=(148, 163, 184), font=font_body)

        attacks = [
            ("ARP Cache Poisoning (MITM)", "Rogue gateway ARP spoofing detected in real-time.", "Static Gateway ARP Pinning", (239, 68, 68)),
            ("SYN Flood DoS Attack", "Unacknowledged SYN backlog burst exceeding 80 pkts/s.", "Automated Rate-Limit Barrier", (245, 158, 11)),
            ("Stealth Port Scan (Nmap)", "Xmas/Null probe sweep across closed ports.", "Immediate Host Blacklist", (168, 85, 247)),
            ("DNS Poisoning / Rogue DoH", "Local gateway DNS mismatch vs Quad9 cryptographic DoH.", "Integrity Attestation Flag", (59, 130, 246)),
        ]

        grid_y = 310
        for i, (title, desc, mitig, col) in enumerate(attacks):
            gx = 100 + (i % 2) * (WIDTH // 2 - 80)
            gy = grid_y + (i // 2) * 230
            gw = WIDTH // 2 - 120
            gh = 195

            draw_card(draw, gx, gy, gw, gh, (18, 25, 42, 240), col)
            draw.text((gx + 25, gy + 20), title, fill=(255, 255, 255), font=font_sub)
            draw.text((gx + 25, gy + 75), desc, fill=(148, 163, 184), font=font_body)
            draw.text((gx + 25, gy + 125), "Defense: " + mitig, fill=col, font=font_body)

        # Bottom Critical Alert simulation banner
        if rel > 30:
            banner_pulse = 0.5 + 0.5 * math.sin(rel * 0.4)
            b_alpha = int(200 + 55 * banner_pulse)
            b_y = HEIGHT - 180
            draw_card(draw, 100, b_y, WIDTH - 200, 110, (40, 10, 15, 240), (239, 68, 68, b_alpha))
            draw.text((130, b_y + 20), "ALERT #402: ARP Spoofing Detected! Rogue MAC 02:42:AC:11:00:03 masquerading as Gateway 192.168.1.1", fill=(239, 68, 68), font=font_sub)
            draw.text((130, b_y + 65), "Automated Action: Dynamic ARP rule flushed & packet dropped at Windows Kernel Firewall.", fill=(255, 255, 255), font=font_body)

    # -------------------------------------------------------------
    # SCENE 4: MACHINE LEARNING BEHAVIORAL ANOMALY (Frames 690 - 929 / 23.0s - 31.0s)
    # -------------------------------------------------------------
    elif frame < 930:
        rel = frame - 690
        draw.text((100, 100), "8D TENSOR ML ANOMALY DETECTION", fill=(255, 255, 255), font=font_huge)
        draw.text((105, 195), "Continuous Isolation Forest + Streaming Robust Random Cut Forest (RRCF)", fill=(16, 185, 129), font=font_sub)
        draw.text((105, 245), "Unsupervised behavioral profiling catches zero-day C2 channels and covert tunnels.", fill=(148, 163, 184), font=font_body)

        # Anomaly Score Gauge Card
        gw, gh = 520, 520
        gx, gy = 100, 310
        draw_card(draw, gx, gy, gw, gh, (15, 23, 42, 240), (16, 185, 129))

        draw.text((gx + 40, gy + 35), "AI ANOMALY METER", fill=(255, 255, 255), font=font_sub)
        
        # Dynamic meter spike animation
        progress = min(1.0, rel / 60.0)
        curr_score = 0.12 + (0.94 - 0.12) * (1.0 - math.exp(-progress * 4.0))
        
        meter_col = (16, 185, 129) if curr_score < 0.4 else ((245, 158, 11) if curr_score < 0.7 else (239, 68, 68))
        draw.text((gx + 40, gy + 110), f"{curr_score:.2f}", fill=meter_col, font=font_huge)
        draw.text((gx + 220, gy + 140), "/ 1.00 PEAK", fill=(148, 163, 184), font=font_sub)
        
        status_txt = "STATUS: SAFE BASELINE" if curr_score < 0.4 else ("STATUS: ELEVATED RISK" if curr_score < 0.7 else "STATUS: CRITICAL C2 BEACON!")
        draw.text((gx + 40, gy + 220), status_txt, fill=meter_col, font=font_sub)

        # Meter Bar
        bar_w = 440
        fill_w = int(bar_w * curr_score)
        draw.rectangle([gx + 40, gy + 280, gx + 40 + bar_w, gy + 305], fill=(30, 41, 59))
        draw.rectangle([gx + 40, gy + 280, gx + 40 + fill_w, gy + 305], fill=meter_col)

        draw.text((gx + 40, gy + 350), "Engine: IsolationForest (8-Feature Tensor)", fill=(203, 213, 225), font=font_body)
        draw.text((gx + 40, gy + 400), "Trained On: 10,000 Welford Baseline Vectors", fill=(148, 163, 184), font=font_mono)
        draw.text((gx + 40, gy + 440), "Confidence: 99.4% · False Positive: < 0.05%", fill=(16, 185, 129), font=font_mono)

        # 4 Factor Breakdown Cards on Right
        factors = [
            ("Byte Ratio Entropy", "Asymmetric outbound burst ratio: 18.4x standard", "0.88", (239, 68, 68)),
            ("Inter-Arrival Periodicity", "Deterministic 4.98s heartbeat signature (C2 beacon)", "0.91", (239, 68, 68)),
            ("Port Volatility", "High-frequency ephemeral port hopping over TLS", "0.79", (245, 158, 11)),
            ("Connection Churn", "Persistent keep-alives to unindexed foreign ASN", "0.84", (245, 158, 11)),
        ]

        fx = gx + gw + 40
        for i, (fname, fdesc, fscore, fcol) in enumerate(factors):
            fy = gy + i * 135
            fw = WIDTH - fx - 100
            fh = 115
            draw_card(draw, fx, fy, fw, fh, (15, 23, 42, 240), fcol)
            draw.text((fx + 30, fy + 20), fname, fill=(255, 255, 255), font=font_sub)
            draw.text((fx + 30, fy + 68), fdesc, fill=(148, 163, 184), font=font_body)
            draw.text((fx + fw - 120, fy + 35), fscore, fill=fcol, font=font_title)

    # -------------------------------------------------------------
    # SCENE 5: WEB3 MERKLE FORENSIC LEDGER & OS FIREWALL (Frames 930 - 1199 / 31.0s - 40.0s)
    # -------------------------------------------------------------
    elif frame < 1200:
        rel = frame - 930
        draw.text((100, 100), "IMMUTABLE FORENSIC ATTRIBUTION & CONTAINMENT", fill=(255, 255, 255), font=font_huge)
        draw.text((105, 195), "RFC 6962 SHA-256 Merkle Tree + Ed25519 Cryptographic Posture Seals", fill=(168, 85, 247), font=font_sub)
        draw.text((105, 245), "Tamper-proof audit trails for legal forensic integrity + instant kernel firewall drops.", fill=(148, 163, 184), font=font_body)

        # Left Card: Merkle Forensic Ledger
        lw = (WIDTH - 240) // 2
        lh = 600
        lx, ly = 100, 310
        draw_card(draw, lx, ly, lw, lh, (15, 23, 42, 240), (168, 85, 247))

        draw.text((lx + 35, ly + 30), "RFC 6962 CRYPTOGRAPHIC LEDGER", fill=(255, 255, 255), font=font_sub)
        draw.text((lx + 35, ly + 80), "Block Index: #18 · Ed25519 Signature Verified", fill=(52, 211, 153), font=font_body)

        blocks = [
            ("Root Hash", "0x7a3f81e9d02c4b5a8891f3c7e41b9d20", (168, 85, 247)),
            ("Attestation Leaf 0", "Device Census · 14 MACs Verified", (56, 189, 248)),
            ("Attestation Leaf 1", "IDS Alert #402 · ARP Poisoning Sealed", (239, 68, 68)),
            ("Attestation Leaf 2", "Firewall Lockdown Rule Enforced", (245, 158, 11)),
        ]

        for i, (bname, bhash, bcol) in enumerate(blocks):
            by = ly + 140 + i * 105
            draw_card(draw, lx + 30, by, lw - 60, 85, (20, 29, 50, 240), bcol, radius=8)
            draw.text((lx + 50, by + 12), bname, fill=bcol, font=font_body)
            draw.text((lx + 50, by + 45), bhash, fill=(203, 213, 225), font=font_mono)

        # Right Card: Zero-Trust OS Firewall Containment
        rx = lx + lw + 40
        draw_card(draw, rx, ly, lw, lh, (15, 23, 42, 240), (239, 68, 68))

        draw.text((rx + 35, ly + 30), "ACTIVE OS FIREWALL CONTAINMENT", fill=(255, 255, 255), font=font_sub)
        draw.text((rx + 35, ly + 80), "Native Windows Defender / netsh advfirewall API", fill=(245, 158, 11), font=font_body)

        # Counter animation
        blocked_count = int(1200 + (rel * 28.5))
        draw_card(draw, rx + 30, ly + 140, lw - 60, 160, (30, 15, 20, 240), (239, 68, 68))
        draw.text((rx + 60, ly + 165), "PACKETS QUARANTINED & BLOCKED", fill=(239, 68, 68), font=font_body)
        draw.text((rx + 60, ly + 210), f"{blocked_count:,}", fill=(255, 255, 255), font=font_huge)

        # Actions
        draw_card(draw, rx + 30, ly + 330, lw - 60, 95, (16, 185, 129, 30), (16, 185, 129))
        draw.text((rx + 50, ly + 345), "1-Click IP Isolation Active", fill=(16, 185, 129), font=font_sub)
        draw.text((rx + 50, ly + 385), "Rogue attacker blocked from LAN & WAN interfaces.", fill=(148, 163, 184), font=font_tiny)

        draw_card(draw, rx + 30, ly + 450, lw - 60, 95, (239, 68, 68, 30), (239, 68, 68))
        draw.text((rx + 50, ly + 465), "Emergency Lockdown Mode Armed", fill=(239, 68, 68), font=font_sub)
        draw.text((rx + 50, ly + 505), "Drops all inbound/outbound traffic except gateway tunnel.", fill=(148, 163, 184), font=font_tiny)

    # -------------------------------------------------------------
    # SCENE 6: UI WALKTHROUGH & 3D WEBGL TOPOLOGY (Frames 1200 - 1529 / 40.0s - 51.0s)
    # -------------------------------------------------------------
    elif frame < 1530:
        rel = frame - 1200
        draw.text((100, 85), "ELITE TACTICAL 2D & 3D DASHBOARD", fill=(255, 255, 255), font=font_huge)
        draw.text((105, 180), "Multi-ring collision-free packing engine with guaranteed zero overlapping labels at any scale", fill=(56, 189, 248), font=font_sub)

        # Mockup Browser Frame
        mw = 1100
        mh = 680
        mx = 100
        my = 260
        draw_card(draw, mx, my, mw, mh, (15, 23, 42, 255), (14, 165, 233))
        
        # Browser chrome header
        draw.rectangle([mx, my, mx + mw, my + 38], fill=(30, 41, 59))
        draw.ellipse([mx + 15, my + 13, mx + 27, my + 25], fill=(239, 68, 68))
        draw.ellipse([mx + 35, my + 13, mx + 47, my + 25], fill=(245, 158, 11))
        draw.ellipse([mx + 55, my + 13, mx + 67, my + 25], fill=(16, 185, 129))
        draw.text((mx + 90, my + 10), "http://localhost:8000 — GARUDA Network Guardian Dashboard", fill=(148, 163, 184), font=font_tiny)

        # Paste Screenshot into Frame
        active_shot = shot_radar if rel < 165 else shot_devices
        if active_shot:
            inner_w = mw - 4
            inner_h = mh - 42
            resized_shot = active_shot.resize((inner_w, inner_h), Image.Resampling.LANCZOS)
            im.paste(resized_shot, (mx + 2, my + 40))

        # Right-side floating highlight badges
        fx = mx + mw + 40
        highlights = [
            ("Guaranteed Zero Collisions", "AABB priority label solver eliminates overlapping nodes at 10, 100, or 1,000+ scale.", (56, 189, 248)),
            ("3D PBR WebGL Topology", "GPU-accelerated InstancedMesh rendering running at 60 FPS under full device load.", (168, 85, 247)),
            ("Safe Simulation Lab", "1-click safe attack simulation testing ARP, SYN floods, ML beacons, and rogue IoT devices.", (245, 158, 11)),
            ("Daylight / Night Ops", "Spec-verified adaptive UI auto-synchronizing with your OS system color settings.", (16, 185, 129)),
        ]

        for i, (htitle, hdesc, hcol) in enumerate(highlights):
            hy = my + i * 165
            hw = WIDTH - fx - 100
            hh = 145
            draw_card(draw, fx, hy, hw, hh, (15, 23, 42, 240), hcol)
            draw.text((fx + 25, hy + 20), htitle, fill=(255, 255, 255), font=font_sub)
            draw.text((fx + 25, hy + 70), hdesc, fill=(148, 163, 184), font=font_body)

    # -------------------------------------------------------------
    # SCENE 7: OUTRO & AWS OFF CAMPUS CTA (Frames 1530 - 1799 / 51.0s - 60.0s)
    # -------------------------------------------------------------
    else:
        rel = frame - 1530
        cx, cy = WIDTH // 2, HEIGHT // 2 - 40

        # Central Shield Glyph Animation
        pulse = 0.5 + 0.5 * math.sin(rel * 0.25)
        shield_glow = int(20 + 15 * pulse)
        
        # Outer expanding rings
        for r in range(120, 420, 90):
            glow_r = r + int(pulse * 20)
            draw.ellipse([cx - glow_r, cy - glow_r, cx + glow_r, cy + glow_r], outline=(14, 165, 233, 40), width=2)

        # Huge Brand Title
        draw.text((cx - 240, cy - 200), "GARUDA", fill=(255, 255, 255), font=font_huge)
        draw.text((cx - 380, cy - 100), "Autonomous Personal Network Guardian", fill=(14, 165, 233), font=font_title)
        draw.text((cx - 480, cy - 30), "Live Packet IDS · ML Behavioral Anomaly · Merkle Forensic Ledger", fill=(148, 163, 184), font=font_sub)

        # Big AWS Hackathon Box
        box_w = 980
        box_h = 240
        box_x = cx - box_w // 2
        box_y = cy + 60
        draw_card(draw, box_x, box_y, box_w, box_h, (15, 23, 42, 250), (245, 158, 11), radius=16)

        draw.text((box_x + 50, box_y + 30), "BUILT FOR OFF CAMPUS BY AWS", fill=(251, 191, 36), font=font_title)
        draw.text((box_x + 50, box_y + 95), "Tagging: @GrowthX  &  @AWSDevelopers", fill=(255, 255, 255), font=font_sub)

        # 1-Command badge
        draw_badge(draw, box_x + 50, box_y + 160, "OPEN CMD & TYPE: garuda", bg=(16, 185, 129, 50), fg=(52, 211, 153))
        draw_badge(draw, box_x + 480, box_y + 160, "100% LOCAL-FIRST · ZERO CLOUD LEAK", bg=(56, 189, 248, 40), fg=(56, 189, 248))

        # Footer
        draw.text((cx - 280, cy + 340), "GitHub: github.com/DHRUVASAI/GARUDA-", fill=(203, 213, 225), font=font_mono)

    # Capture poster frame
    if frame == best_poster_frame_idx:
        poster_frame_image = im.copy()

    # Write raw frame to FFmpeg pipe
    ffmpeg_proc.stdin.write(im.convert("RGB").tobytes())

    if (frame + 1) % 150 == 0 or frame == TOTAL_FRAMES - 1:
        print(f"    --> Rendered {frame + 1}/{TOTAL_FRAMES} frames ({((frame + 1) / TOTAL_FRAMES) * 100:.1f}%)...")

ffmpeg_proc.stdin.close()
ffmpeg_proc.wait()

print(f"[+] 5. Video render complete: {OUT_MP4}")

# Save Poster Frame
if poster_frame_image:
    poster_frame_image.convert("RGB").save(str(POSTER_JPG), quality=95)
    print(f"[+] 6. Poster frame saved: {POSTER_JPG}")

print("[+] ALL DONE!")
