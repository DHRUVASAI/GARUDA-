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

# ==============================================================================
# 1. Reuse / Synthesize 60s High-Energy Soundtrack
# ==============================================================================
audio_path = WORK_DIR / "audio_60s.wav"
if not audio_path.exists():
    print(f"[+] Synthesizing 60-Second Soundtrack...")
    num_samples = int(SAMPLE_RATE * (TOTAL_FRAMES / FPS))
    audio_left = [0.0] * num_samples
    audio_right = [0.0] * num_samples

    bpm = 120.0
    spb = (60.0 / bpm) * SAMPLE_RATE
    beats = int(num_samples / spb)

    bass_progression = [36.71, 36.71, 43.65, 48.99, 36.71, 36.71, 58.27, 55.00]
    arp_notes_pool = [
        [293.66, 349.23, 440.00, 523.25, 587.33, 440.00, 349.23, 293.66],
        [349.23, 440.00, 523.25, 698.46, 523.25, 440.00, 349.23, 261.63],
        [392.00, 466.16, 587.33, 783.99, 587.33, 466.16, 392.00, 293.66],
        [440.00, 554.37, 659.25, 880.00, 659.25, 554.37, 440.00, 329.63],
    ]

    for b in range(beats):
        beat_start = int(b * spb)
        bar = b // 4
        
        # Kick
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

        # Snare
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

        # Hi-hats
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

        # Bass
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

        # Arp
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

    # Transition drops
    for frame_idx in [0, 210, 450, 690, 930, 1200, 1530]:
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

print(f"[+] Audio track confirmed: {audio_path}")

# ==============================================================================
# 2. Daylight (Light Theme) Palette & Fonts
# ==============================================================================
# Exact GARUDA Daylight Tokens
COLOR_BG = (243, 240, 234)         # #F3F0EA Warm parchment
COLOR_SURFACE = (250, 248, 244)    # #FAF8F4 Crisp ivory surface
COLOR_SURFACE_2 = (232, 227, 218)  # #E8E3DA Secondary surface
COLOR_INK = (22, 24, 29)           # #16181D Deep APCA ink
COLOR_INK_MUTED = (87, 92, 102)    # #575C66 Slate muted ink
COLOR_ACCENT = (30, 79, 214)       # #1E4FD6 Sapphire Blue
COLOR_SAFE = (21, 127, 86)         # #157F56 Emerald Green
COLOR_WARN = (185, 107, 8)         # #B96B08 Amber Orange
COLOR_DANGER = (197, 54, 36)       # #C53624 Crimson Red

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

# Load Daylight Screenshots
shot_radar = None
shot_devices = None
shot_ledger = None

p_radar = WORK_DIR / "light_radar_1080.png"
p_dev = WORK_DIR / "light_devices_1080.png"
p_led = WORK_DIR / "light_ledger_1080.png"

if p_radar.exists(): shot_radar = Image.open(p_radar).convert("RGBA")
if p_dev.exists(): shot_devices = Image.open(p_dev).convert("RGBA")
if p_led.exists(): shot_ledger = Image.open(p_led).convert("RGBA")

def draw_light_grid(draw, frame_idx):
    offset = (frame_idx * 3) % 80
    grid_color = (22, 24, 29, 22)
    for x in range(0, WIDTH + 80, 80):
        draw.line([(x - offset, 0), (x - offset, HEIGHT)], fill=grid_color, width=1)
    for y in range(0, HEIGHT + 80, 80):
        draw.line([(0, y), (WIDTH, y)], fill=grid_color, width=1)
    
    # Top status bar
    draw.line([(0, 64), (WIDTH, 64)], fill=(30, 79, 214, 60), width=1)
    draw.text((60, 22), "GARUDA // AUTONOMOUS NETWORK GUARDIAN · DAYLIGHT OPS", fill=COLOR_ACCENT, font=font_mono)
    draw.text((WIDTH - 680, 22), "OFF CAMPUS BY AWS · GROWTHX · REAL PACKET IDS", fill=COLOR_SAFE, font=font_mono)

def draw_light_card(draw, x, y, w, h, bg_color=COLOR_SURFACE, border_color=(22, 24, 29, 35), radius=12):
    # Simulated shadow
    draw.rounded_rectangle([x + 2, y + 4, x + w + 2, y + h + 4], radius=radius, fill=(22, 24, 29, 15))
    draw.rounded_rectangle([x, y, x + w, y + h], radius=radius, fill=bg_color, outline=border_color, width=2)

def draw_light_badge(draw, x, y, text, bg=(30, 79, 214, 25), fg=COLOR_ACCENT):
    bbox = font_mono.getbbox(text)
    bw = (bbox[2] - bbox[0]) + 18
    bh = 30
    draw.rounded_rectangle([x, y, x + bw, y + bh], radius=6, fill=bg, outline=fg, width=1)
    draw.text((x + 9, y + 4), text, fill=fg, font=font_mono)
    return bw

OUT_MP4 = OUT_DIR / "brag.mp4"
POSTER_JPG = OUT_DIR / "brag.jpg"

print(f"[+] 3. Launching FFmpeg encoder pipeline (Light Mode) -> {OUT_MP4} ...")

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

print(f"[+] 4. Rendering {TOTAL_FRAMES} Daylight frames...")

for frame in range(TOTAL_FRAMES):
    im = Image.new("RGBA", (WIDTH, HEIGHT), (243, 240, 234, 255))
    draw = ImageDraw.Draw(im)
    draw_light_grid(draw, frame)

    # -------------------------------------------------------------
    # SCENE 1: THE HOOK & INTRODUCTION (Frames 0 - 209 / 0.0s - 7.0s)
    # -------------------------------------------------------------
    if frame < 210:
        cx, cy = WIDTH // 2, HEIGHT // 2 - 20
        angle = frame * 0.12
        for r in (140, 260, 380):
            draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(30, 79, 214, 45), width=2)
        
        # Rotating Radar Beam
        bx = cx + 380 * math.cos(angle)
        by = cy + 380 * math.sin(angle)
        draw.line([(cx, cy), (bx, by)], fill=(30, 79, 214, 180), width=3)
        
        # Pulsing Red Threat Blips
        t_pulse = 0.5 + 0.5 * math.sin(frame * 0.3)
        rad = int(8 + t_pulse * 6)
        draw.ellipse([cx + 180 - rad, cy - 120 - rad, cx + 180 + rad, cy - 120 + rad], fill=COLOR_DANGER, outline=(255, 255, 255))
        draw.ellipse([cx - 240 - rad, cy + 140 - rad, cx - 240 + rad, cy + 140 + rad], fill=COLOR_DANGER, outline=(255, 255, 255))
        draw.ellipse([cx + 260 - rad, cy + 180 - rad, cx + 260 + rad, cy + 180 + rad], fill=COLOR_DANGER, outline=(255, 255, 255))

        # Typography (Light Mode: High APCA contrast)
        draw.text((cx - 560, cy - 80), "YOUR WI-FI ROUTER IS COMPLETELY BLIND.", fill=COLOR_INK, font=font_huge)
        draw.text((cx - 430, cy + 20), "Enterprise SIEMs cost $100,000 / year.", fill=COLOR_DANGER, font=font_sub)
        draw.text((cx - 490, cy + 90), "Meet GARUDA — Autonomous Personal Network Defense.", fill=COLOR_ACCENT, font=font_title)
        
        # Badges
        draw_light_badge(draw, cx - 380, cy + 200, "OFF CAMPUS BY AWS", bg=(245, 158, 11, 30), fg=COLOR_WARN)
        draw_light_badge(draw, cx - 110, cy + 200, "GROWTHX", bg=(147, 51, 234, 30), fg=(147, 51, 234))
        draw_light_badge(draw, cx + 80, cy + 200, "REAL-TIME SCAPY IDS", bg=(21, 127, 86, 30), fg=COLOR_SAFE)

    # -------------------------------------------------------------
    # SCENE 2: 5-LAYER HARDWARE DISCOVERY (Frames 210 - 449 / 7.0s - 15.0s)
    # -------------------------------------------------------------
    elif frame < 450:
        rel = frame - 210
        draw.text((100, 100), "100% REAL HARDWARE RECOGNITION", fill=COLOR_INK, font=font_huge)
        draw.text((105, 195), "5-Layer Pipeline: mDNS · SSDP UPnP XML · DHCP Opt 12 · NetBIOS · 35k OUI Cache", fill=COLOR_ACCENT, font=font_sub)
        draw.text((105, 245), "Zero 'Unknown Device' labels. Real names, real vendors, live latency & security trust bands.", fill=COLOR_INK_MUTED, font=font_body)

        devices = [
            ("omen (This Computer)", "AzureWave / HP Wi-Fi · 192.168.1.13", "Windows 11 Laptop · 1.2ms", COLOR_ACCENT, "SAFE"),
            ("Zyxel / Airtel Fiber Router", "Main Wi-Fi Gateway · 192.168.1.1", "Wi-Fi 6 Gateway · 0.8ms", COLOR_WARN, "ROUTER"),
            ("[LG] webOS TV UK6360PTE", "LG Electronics · 192.168.1.2", "4K Smart TV · 4.5ms", (147, 51, 234), "SAFE"),
            ("Canon G4070 series Printer", "Canon Inc. · 192.168.1.17", "IPP Office Printer · 12ms", COLOR_SAFE, "SAFE"),
            ("realme-13-Pro-5G", "Realme Mobile · 192.168.1.5", "Android 14 Phone · 18ms", (37, 99, 235), "UNVERIFIED"),
        ]

        for i, (name, meta, dtype, col, trust) in enumerate(devices):
            slide = min(1.0, max(0.0, (rel - i * 10) / 14.0))
            if slide > 0.0:
                card_x = int(100 + (1.0 - slide) * 80)
                card_y = 310 + i * 135
                card_w = WIDTH - 200
                card_h = 115

                draw_light_card(draw, card_x, card_y, card_w, card_h, bg_color=COLOR_SURFACE, border_color=(col[0], col[1], col[2], 120))
                draw.rectangle([card_x, card_y, card_x + 8, card_y + card_h], fill=col)

                draw.text((card_x + 35, card_y + 20), name, fill=COLOR_INK, font=font_title)
                draw.text((card_x + 35, card_y + 70), meta, fill=COLOR_INK_MUTED, font=font_body)
                draw.text((card_x + card_w - 460, card_y + 40), dtype, fill=COLOR_INK, font=font_body)
                
                t_col = COLOR_SAFE if trust == "SAFE" else (COLOR_WARN if trust == "UNVERIFIED" else COLOR_ACCENT)
                draw_light_badge(draw, card_x + card_w - 180, card_y + 35, trust, bg=(t_col[0], t_col[1], t_col[2], 25), fg=t_col)

    # -------------------------------------------------------------
    # SCENE 3: REAL-TIME SCAPY PACKET IDS (Frames 450 - 689 / 15.0s - 23.0s)
    # -------------------------------------------------------------
    elif frame < 690:
        rel = frame - 450
        draw.text((100, 100), "LIVE SCAPY L2-L7 PACKET IDS", fill=COLOR_INK, font=font_huge)
        draw.text((105, 195), "Raw socket promisc filter sniffing live Ethernet, IP, TCP, UDP & DNS layers", fill=COLOR_DANGER, font=font_sub)
        draw.text((105, 245), "Deterministic stateful detection against modern LAN exploitation vectors.", fill=COLOR_INK_MUTED, font=font_body)

        attacks = [
            ("ARP Cache Poisoning (MITM)", "Rogue gateway ARP spoofing detected in real-time.", "Static Gateway ARP Pinning", COLOR_DANGER),
            ("SYN Flood DoS Attack", "Unacknowledged SYN backlog burst exceeding 80 pkts/s.", "Automated Rate-Limit Barrier", COLOR_WARN),
            ("Stealth Port Scan (Nmap)", "Xmas/Null probe sweep across closed ports.", "Immediate Host Blacklist", (147, 51, 234)),
            ("DNS Poisoning / Rogue DoH", "Local gateway DNS mismatch vs Quad9 cryptographic DoH.", "Integrity Attestation Flag", COLOR_ACCENT),
        ]

        grid_y = 310
        for i, (title, desc, mitig, col) in enumerate(attacks):
            gx = 100 + (i % 2) * (WIDTH // 2 - 80)
            gy = grid_y + (i // 2) * 230
            gw = WIDTH // 2 - 120
            gh = 195

            draw_light_card(draw, gx, gy, gw, gh, bg_color=COLOR_SURFACE, border_color=(col[0], col[1], col[2], 120))
            draw.text((gx + 25, gy + 20), title, fill=COLOR_INK, font=font_sub)
            draw.text((gx + 25, gy + 75), desc, fill=COLOR_INK_MUTED, font=font_body)
            draw.text((gx + 25, gy + 125), "Defense: " + mitig, fill=col, font=font_body)

        if rel > 30:
            b_y = HEIGHT - 180
            draw_light_card(draw, 100, b_y, WIDTH - 200, 110, bg_color=(254, 242, 242), border_color=COLOR_DANGER)
            draw.text((130, b_y + 20), "ALERT #402: ARP Spoofing Detected! Rogue MAC 02:42:AC:11:00:03 masquerading as Gateway 192.168.1.1", fill=COLOR_DANGER, font=font_sub)
            draw.text((130, b_y + 65), "Automated Action: Dynamic ARP rule flushed & packet dropped at Windows Kernel Firewall.", fill=COLOR_INK, font=font_body)

    # -------------------------------------------------------------
    # SCENE 4: MACHINE LEARNING BEHAVIORAL ANOMALY (Frames 690 - 929 / 23.0s - 31.0s)
    # -------------------------------------------------------------
    elif frame < 930:
        rel = frame - 690
        draw.text((100, 100), "8D TENSOR ML ANOMALY DETECTION", fill=COLOR_INK, font=font_huge)
        draw.text((105, 195), "Continuous Isolation Forest + Streaming Robust Random Cut Forest (RRCF)", fill=COLOR_SAFE, font=font_sub)
        draw.text((105, 245), "Unsupervised behavioral profiling catches zero-day C2 channels and covert tunnels.", fill=COLOR_INK_MUTED, font=font_body)

        gw, gh = 520, 520
        gx, gy = 100, 310
        draw_light_card(draw, gx, gy, gw, gh, bg_color=COLOR_SURFACE, border_color=(COLOR_SAFE[0], COLOR_SAFE[1], COLOR_SAFE[2], 120))

        draw.text((gx + 40, gy + 35), "AI ANOMALY METER", fill=COLOR_INK, font=font_sub)
        
        progress = min(1.0, rel / 60.0)
        curr_score = 0.12 + (0.94 - 0.12) * (1.0 - math.exp(-progress * 4.0))
        
        meter_col = COLOR_SAFE if curr_score < 0.4 else (COLOR_WARN if curr_score < 0.7 else COLOR_DANGER)
        draw.text((gx + 40, gy + 110), f"{curr_score:.2f}", fill=meter_col, font=font_huge)
        draw.text((gx + 220, gy + 140), "/ 1.00 PEAK", fill=COLOR_INK_MUTED, font=font_sub)
        
        status_txt = "STATUS: SAFE BASELINE" if curr_score < 0.4 else ("STATUS: ELEVATED RISK" if curr_score < 0.7 else "STATUS: CRITICAL C2 BEACON!")
        draw.text((gx + 40, gy + 220), status_txt, fill=meter_col, font=font_sub)

        # Bar
        bar_w = 440
        fill_w = int(bar_w * curr_score)
        draw.rectangle([gx + 40, gy + 280, gx + 40 + bar_w, gy + 305], fill=(226, 232, 240))
        draw.rectangle([gx + 40, gy + 280, gx + 40 + fill_w, gy + 305], fill=meter_col)

        draw.text((gx + 40, gy + 350), "Engine: IsolationForest (8-Feature Tensor)", fill=COLOR_INK, font=font_body)
        draw.text((gx + 40, gy + 400), "Trained On: 10,000 Welford Baseline Vectors", fill=COLOR_INK_MUTED, font=font_mono)
        draw.text((gx + 40, gy + 440), "Confidence: 99.4% · False Positive: < 0.05%", fill=COLOR_SAFE, font=font_mono)

        factors = [
            ("Byte Ratio Entropy", "Asymmetric outbound burst ratio: 18.4x standard", "0.88", COLOR_DANGER),
            ("Inter-Arrival Periodicity", "Deterministic 4.98s heartbeat signature (C2 beacon)", "0.91", COLOR_DANGER),
            ("Port Volatility", "High-frequency ephemeral port hopping over TLS", "0.79", COLOR_WARN),
            ("Connection Churn", "Persistent keep-alives to unindexed foreign ASN", "0.84", COLOR_WARN),
        ]

        fx = gx + gw + 40
        for i, (fname, fdesc, fscore, fcol) in enumerate(factors):
            fy = gy + i * 135
            fw = WIDTH - fx - 100
            fh = 115
            draw_light_card(draw, fx, fy, fw, fh, bg_color=COLOR_SURFACE, border_color=(fcol[0], fcol[1], fcol[2], 120))
            draw.text((fx + 30, fy + 20), fname, fill=COLOR_INK, font=font_sub)
            draw.text((fx + 30, fy + 68), fdesc, fill=COLOR_INK_MUTED, font=font_body)
            draw.text((fx + fw - 120, fy + 35), fscore, fill=fcol, font=font_title)

    # -------------------------------------------------------------
    # SCENE 5: WEB3 MERKLE FORENSIC LEDGER & OS FIREWALL (Frames 930 - 1199 / 31.0s - 40.0s)
    # -------------------------------------------------------------
    elif frame < 1200:
        rel = frame - 930
        draw.text((100, 100), "IMMUTABLE FORENSIC ATTRIBUTION & CONTAINMENT", fill=COLOR_INK, font=font_huge)
        draw.text((105, 195), "RFC 6962 SHA-256 Merkle Tree + Ed25519 Cryptographic Posture Seals", fill=(147, 51, 234), font=font_sub)
        draw.text((105, 245), "Tamper-proof audit trails for legal forensic integrity + instant kernel firewall drops.", fill=COLOR_INK_MUTED, font=font_body)

        lw = (WIDTH - 240) // 2
        lh = 600
        lx, ly = 100, 310
        draw_light_card(draw, lx, ly, lw, lh, bg_color=COLOR_SURFACE, border_color=(147, 51, 234, 120))

        draw.text((lx + 35, ly + 30), "RFC 6962 CRYPTOGRAPHIC LEDGER", fill=COLOR_INK, font=font_sub)
        draw.text((lx + 35, ly + 80), "Block Index: #18 · Ed25519 Signature Verified", fill=COLOR_SAFE, font=font_body)

        blocks = [
            ("Root Hash", "0x7a3f81e9d02c4b5a8891f3c7e41b9d20", (147, 51, 234)),
            ("Attestation Leaf 0", "Device Census · 14 MACs Verified", COLOR_ACCENT),
            ("Attestation Leaf 1", "IDS Alert #402 · ARP Poisoning Sealed", COLOR_DANGER),
            ("Attestation Leaf 2", "Firewall Lockdown Rule Enforced", COLOR_WARN),
        ]

        for i, (bname, bhash, bcol) in enumerate(blocks):
            by = ly + 140 + i * 105
            draw_light_card(draw, lx + 30, by, lw - 60, 85, bg_color=COLOR_SURFACE_2, border_color=bcol, radius=8)
            draw.text((lx + 50, by + 12), bname, fill=bcol, font=font_body)
            draw.text((lx + 50, by + 45), bhash, fill=COLOR_INK, font=font_mono)

        rx = lx + lw + 40
        draw_light_card(draw, rx, ly, lw, lh, bg_color=COLOR_SURFACE, border_color=(COLOR_DANGER[0], COLOR_DANGER[1], COLOR_DANGER[2], 120))

        draw.text((rx + 35, ly + 30), "ACTIVE OS FIREWALL CONTAINMENT", fill=COLOR_INK, font=font_sub)
        draw.text((rx + 35, ly + 80), "Native Windows Defender / netsh advfirewall API", fill=COLOR_WARN, font=font_body)

        blocked_count = int(1200 + (rel * 28.5))
        draw_light_card(draw, rx + 30, ly + 140, lw - 60, 160, bg_color=(254, 242, 242), border_color=COLOR_DANGER)
        draw.text((rx + 60, ly + 165), "PACKETS QUARANTINED & BLOCKED", fill=COLOR_DANGER, font=font_body)
        draw.text((rx + 60, ly + 210), f"{blocked_count:,}", fill=COLOR_INK, font=font_huge)

        draw_light_card(draw, rx + 30, ly + 330, lw - 60, 95, bg_color=(240, 253, 244), border_color=COLOR_SAFE)
        draw.text((rx + 50, ly + 345), "1-Click IP Isolation Active", fill=COLOR_SAFE, font=font_sub)
        draw.text((rx + 50, ly + 385), "Rogue attacker blocked from LAN & WAN interfaces.", fill=COLOR_INK_MUTED, font=font_tiny)

        draw_light_card(draw, rx + 30, ly + 450, lw - 60, 95, bg_color=(254, 242, 242), border_color=COLOR_DANGER)
        draw.text((rx + 50, ly + 465), "Emergency Lockdown Mode Armed", fill=COLOR_DANGER, font=font_sub)
        draw.text((rx + 50, ly + 505), "Drops all inbound/outbound traffic except gateway tunnel.", fill=COLOR_INK_MUTED, font=font_tiny)

    # -------------------------------------------------------------
    # SCENE 6: UI WALKTHROUGH & 3D WEBGL TOPOLOGY (Frames 1200 - 1529 / 40.0s - 51.0s)
    # -------------------------------------------------------------
    elif frame < 1530:
        rel = frame - 1200
        draw.text((100, 85), "ELITE TACTICAL 2D & 3D DASHBOARD (DAYLIGHT OPS)", fill=COLOR_INK, font=font_huge)
        draw.text((105, 180), "Multi-ring collision-free packing engine with guaranteed zero overlapping labels at any scale", fill=COLOR_ACCENT, font=font_sub)

        mw = 1100
        mh = 680
        mx = 100
        my = 260
        draw_light_card(draw, mx, my, mw, mh, bg_color=COLOR_SURFACE, border_color=COLOR_ACCENT)
        
        # Chrome Header on Light
        draw.rectangle([mx, my, mx + mw, my + 38], fill=COLOR_SURFACE_2)
        draw.ellipse([mx + 15, my + 13, mx + 27, my + 25], fill=COLOR_DANGER)
        draw.ellipse([mx + 35, my + 13, mx + 47, my + 25], fill=COLOR_WARN)
        draw.ellipse([mx + 55, my + 13, mx + 67, my + 25], fill=COLOR_SAFE)
        draw.text((mx + 90, my + 10), "http://localhost:8000 — GARUDA Network Guardian (Daylight Ops)", fill=COLOR_INK_MUTED, font=font_tiny)

        # Real Daylight Screenshot in Frame
        if rel < 110:
            active_shot = shot_radar
        elif rel < 220:
            active_shot = shot_devices
        else:
            active_shot = shot_ledger

        if active_shot:
            inner_w = mw - 4
            inner_h = mh - 42
            resized_shot = active_shot.resize((inner_w, inner_h), Image.Resampling.LANCZOS)
            im.paste(resized_shot, (mx + 2, my + 40))

        # Right Highlights in Light Mode
        fx = mx + mw + 40
        highlights = [
            ("Guaranteed Zero Collisions", "AABB priority label solver eliminates overlapping nodes at 10, 100, or 1,000+ scale.", COLOR_ACCENT),
            ("3D PBR WebGL Topology", "GPU-accelerated InstancedMesh rendering running at 60 FPS under full device load.", (147, 51, 234)),
            ("Safe Simulation Lab", "1-click safe attack simulation testing ARP, SYN floods, ML beacons, and rogue IoT devices.", COLOR_WARN),
            ("Daylight / Night Ops", "Spec-verified adaptive UI auto-synchronizing with your OS system color settings.", COLOR_SAFE),
        ]

        for i, (htitle, hdesc, hcol) in enumerate(highlights):
            hy = my + i * 165
            hw = WIDTH - fx - 100
            hh = 145
            draw_light_card(draw, fx, hy, hw, hh, bg_color=COLOR_SURFACE, border_color=(hcol[0], hcol[1], hcol[2], 120))
            draw.text((fx + 25, hy + 20), htitle, fill=COLOR_INK, font=font_sub)
            draw.text((fx + 25, hy + 70), hdesc, fill=COLOR_INK_MUTED, font=font_body)

    # -------------------------------------------------------------
    # SCENE 7: OUTRO & AWS OFF CAMPUS CTA (Frames 1530 - 1799 / 51.0s - 60.0s)
    # -------------------------------------------------------------
    else:
        rel = frame - 1530
        cx, cy = WIDTH // 2, HEIGHT // 2 - 40

        pulse = 0.5 + 0.5 * math.sin(rel * 0.25)
        for r in range(120, 420, 90):
            glow_r = r + int(pulse * 20)
            draw.ellipse([cx - glow_r, cy - glow_r, cx + glow_r, cy + glow_r], outline=(30, 79, 214, 30), width=2)

        # Huge Brand Title in Daylight Ink
        draw.text((cx - 240, cy - 200), "GARUDA", fill=COLOR_INK, font=font_huge)
        draw.text((cx - 380, cy - 100), "Autonomous Personal Network Guardian", fill=COLOR_ACCENT, font=font_title)
        draw.text((cx - 480, cy - 30), "Live Packet IDS · ML Behavioral Anomaly · Merkle Forensic Ledger", fill=COLOR_INK_MUTED, font=font_sub)

        # Big AWS Hackathon Box in Light Mode
        box_w = 980
        box_h = 240
        box_x = cx - box_w // 2
        box_y = cy + 60
        draw_light_card(draw, box_x, box_y, box_w, box_h, bg_color=COLOR_SURFACE, border_color=COLOR_WARN, radius=16)

        draw.text((box_x + 50, box_y + 30), "BUILT FOR OFF CAMPUS BY AWS", fill=COLOR_WARN, font=font_title)
        draw.text((box_x + 50, box_y + 95), "Tagging: @GrowthX  &  @AWSDevelopers", fill=COLOR_INK, font=font_sub)

        draw_light_badge(draw, box_x + 50, box_y + 160, "OPEN CMD & TYPE: garuda", bg=(21, 127, 86, 25), fg=COLOR_SAFE)
        draw_light_badge(draw, box_x + 480, box_y + 160, "100% LOCAL-FIRST · ZERO CLOUD LEAK", bg=(30, 79, 214, 25), fg=COLOR_ACCENT)

        draw.text((cx - 280, cy + 340), "GitHub: github.com/DHRUVASAI/GARUDA-", fill=COLOR_INK_MUTED, font=font_mono)

    if frame == best_poster_frame_idx:
        poster_frame_image = im.copy()

    ffmpeg_proc.stdin.write(im.convert("RGB").tobytes())

    if (frame + 1) % 150 == 0 or frame == TOTAL_FRAMES - 1:
        print(f"    --> Rendered {frame + 1}/{TOTAL_FRAMES} frames ({((frame + 1) / TOTAL_FRAMES) * 100:.1f}%)...")

ffmpeg_proc.stdin.close()
ffmpeg_proc.wait()

print(f"[+] 5. Daylight Video render complete: {OUT_MP4}")

if poster_frame_image:
    poster_frame_image.convert("RGB").save(str(POSTER_JPG), quality=95)
    print(f"[+] 6. Daylight Poster frame saved: {POSTER_JPG}")

print("[+] ALL DONE!")
