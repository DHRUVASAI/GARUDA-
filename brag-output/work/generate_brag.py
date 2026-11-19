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

FFMPEG_EXE = r"C:\Users\dhruv\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-9.0.2-full_build\bin\ffmpeg.exe"
if not os.path.exists(FFMPEG_EXE):
    FFMPEG_EXE = "ffmpeg"

WIDTH = 1920
HEIGHT = 1080
FPS = 30
TOTAL_FRAMES = 600  # Exactly 20.0 seconds
SAMPLE_RATE = 44100

print("[+] 1. Synthesizing 120 BPM Cyber-Electronic Soundtrack (audio.wav)...")

audio_path = WORK_DIR / "audio.wav"
num_samples = int(SAMPLE_RATE * (TOTAL_FRAMES / FPS))
audio_left = [0.0] * num_samples
audio_right = [0.0] * num_samples

bpm = 120.0
spb = (60.0 / bpm) * SAMPLE_RATE  # 22050 samples per beat
beats = int(num_samples / spb)

for b in range(beats):
    beat_start = int(b * spb)
    
    # 1. Punchy Kick on every beat
    kick_len = int(SAMPLE_RATE * 0.22)
    for i in range(min(kick_len, num_samples - beat_start)):
        t = i / SAMPLE_RATE
        env = math.exp(-t * 22.0)
        freq = 150.0 * math.exp(-t * 30.0) + 42.0
        val = math.sin(2.0 * math.pi * freq * t) * env * 0.75
        idx = beat_start + i
        audio_left[idx] += val
        audio_right[idx] += val

    # 2. Snare / Clap on beats 2 and 4 of each 4-beat bar
    if b % 2 == 1:
        snare_len = int(SAMPLE_RATE * 0.20)
        for i in range(min(snare_len, num_samples - beat_start)):
            t = i / SAMPLE_RATE
            env = math.exp(-t * 18.0)
            # Noise + tone
            noise = ((math.sin(i * 1234.567) * 43758.5453) % 2.0) - 1.0
            tone = math.sin(2.0 * math.pi * 185.0 * t) * 0.4
            val = (noise * 0.6 + tone) * env * 0.45
            idx = beat_start + i
            audio_left[idx] += val * 0.95
            audio_right[idx] += val * 0.95

    # 3. Hi-hat on 8th notes (beat and off-beat)
    for sub in (0, 0.5):
        hh_start = beat_start + int(sub * spb)
        hh_len = int(SAMPLE_RATE * 0.05)
        for i in range(min(hh_len, num_samples - hh_start)):
            t = i / SAMPLE_RATE
            env = math.exp(-t * 60.0)
            noise = ((math.sin((hh_start + i) * 987.654) * 31415.92) % 2.0) - 1.0
            val = noise * env * 0.22
            idx = hh_start + i
            if idx < num_samples:
                audio_left[idx] += val * 0.8
                audio_right[idx] += val * 1.0

# 4. Synth Sub-Bass & Cyber Arpeggio in D Minor
# Notes: D1=36.7, F1=43.6, G1=49.0, A1=55.0
bass_notes = [36.71, 36.71, 43.65, 48.99, 36.71, 36.71, 55.00, 48.99]
arp_notes = [293.66, 349.23, 440.0, 523.25, 587.33, 523.25, 440.0, 349.23]

for b in range(beats):
    beat_start = int(b * spb)
    b_note = bass_notes[(b // 2) % len(bass_notes)]
    
    # Sub-bass pulse
    for i in range(min(int(spb * 0.9), num_samples - beat_start)):
        t = i / SAMPLE_RATE
        env = math.sin(math.pi * (i / (spb * 0.9))) ** 0.5
        val = (math.sin(2 * math.pi * b_note * t) + 0.3 * math.sin(4 * math.pi * b_note * t)) * env * 0.35
        idx = beat_start + i
        audio_left[idx] += val
        audio_right[idx] += val

    # 16th-note Arpeggio (4 notes per beat)
    for sub in range(4):
        arp_start = beat_start + int(sub * (spb / 4))
        a_note = arp_notes[(b * 4 + sub) % len(arp_notes)]
        note_len = int(spb * 0.22)
        pan = 0.5 + 0.35 * math.sin((b * 4 + sub) * 0.8)
        for i in range(min(note_len, num_samples - arp_start)):
            t = i / SAMPLE_RATE
            env = math.exp(-t * 24.0)
            val = math.sin(2 * math.pi * a_note * t) * env * 0.18
            idx = arp_start + i
            if idx < num_samples:
                audio_left[idx] += val * (1.0 - pan)
                audio_right[idx] += val * pan

# 5. Scene Transition Risers & Sub Drops (at frame 0, 96, 204, 312, 420, 516)
transitions = [0, 96, 204, 312, 420, 516]
for frame_idx in transitions:
    trans_sample = int((frame_idx / FPS) * SAMPLE_RATE)
    # Impact drop
    drop_len = int(SAMPLE_RATE * 0.5)
    for i in range(min(drop_len, num_samples - trans_sample)):
        t = i / SAMPLE_RATE
        env = math.exp(-t * 8.0)
        freq = 180.0 * math.exp(-t * 12.0) + 30.0
        val = math.sin(2 * math.pi * freq * t) * env * 0.65
        idx = trans_sample + i
        if idx < num_samples:
            audio_left[idx] += val
            audio_right[idx] += val

# Master Limiter & Export to 16-bit WAV
with wave.open(str(audio_path), "w") as wav_file:
    wav_file.setnchannels(2)
    wav_file.setsampwidth(2)
    wav_file.setframerate(SAMPLE_RATE)
    
    frames_data = bytearray()
    for l, r in zip(audio_left, audio_right):
        # Soft-clip saturation
        l_sat = math.tanh(l * 1.1) * 30000.0
        r_sat = math.tanh(r * 1.1) * 30000.0
        frames_data.extend(struct.pack("<hh", int(l_sat), int(r_sat)))
    wav_file.writeframes(frames_data)

print(f"[+] Audio track synthesized: {audio_path} ({num_samples / SAMPLE_RATE:.1f}s)")

# ==============================================================================
# 2. Rendering 600 Frames (1920x1080 @ 30fps)
# ==============================================================================
print("[+] 2. Rendering 600 motion graphics frames...")

# Try loading Segoe UI or fallback to Arial
font_title = None
font_sub = None
font_body = None
font_mono = None
font_huge = None

for font_path in [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"]:
    if os.path.exists(font_path):
        font_huge = ImageFont.truetype(font_path, 80)
        font_title = ImageFont.truetype(font_path, 54)
        font_sub = ImageFont.truetype(font_path, 34)
        font_body = ImageFont.truetype(font_path, 26)
        font_mono = ImageFont.truetype(font_path, 22)
        break

if not font_title:
    font_huge = font_title = font_sub = font_body = font_mono = ImageFont.load_default()

# Try loading GARUDA icon
garuda_logo = None
logo_path = Path(r"C:\Users\dhruv\Downloads\GARUDA--main\GARUDA--main\public\assets\garuda_icon_192.png")
if logo_path.exists():
    try:
        garuda_logo = Image.open(logo_path).convert("RGBA")
    except Exception:
        pass

def draw_cyber_grid(draw, frame_idx):
    # Dark obsidian background
    # Subtle moving cyber grid lines
    offset = (frame_idx * 3) % 80
    grid_color = (15, 27, 45, 120)
    for x in range(0, WIDTH + 80, 80):
        draw.line([(x - offset, 0), (x - offset, HEIGHT)], fill=grid_color, width=1)
    for y in range(0, HEIGHT + 80, 80):
        draw.line([(0, y), (WIDTH, y)], fill=grid_color, width=1)
    
    # Top banner / branding status bar
    draw.line([(0, 64), (WIDTH, 64)], fill=(14, 165, 233, 90), width=1)
    draw.text((60, 22), "GARUDA v4 // AUTONOMOUS NETWORK GUARDIAN", fill=(14, 165, 233), font=font_mono)
    draw.text((WIDTH - 360, 22), "LIVE SHIELD · SCAPY IDS · ML ENGINE", fill=(16, 185, 129), font=font_mono)

def draw_card(draw, x, y, w, h, bg_color, border_color):
    draw.rounded_rectangle([x, y, x + w, y + h], radius=12, fill=bg_color, outline=border_color, width=2)

def draw_badge(draw, x, y, text, bg=(14, 165, 233, 50), fg=(56, 189, 248)):
    bbox = font_mono.getbbox(text)
    bw = (bbox[2] - bbox[0]) + 20
    bh = 32
    draw.rounded_rectangle([x, y, x + bw, y + bh], radius=6, fill=bg, outline=fg, width=1)
    draw.text((x + 10, y + 5), text, fill=fg, font=font_mono)
    return bw

for frame in range(TOTAL_FRAMES):
    im = Image.new("RGBA", (WIDTH, HEIGHT), (7, 11, 20, 255))
    draw = ImageDraw.Draw(im)
    draw_cyber_grid(draw, frame)

    # -------------------------------------------------------------
    # SCENE 1: THE HOOK (0 - 95 / 0.0s - 3.2s)
    # -------------------------------------------------------------
    if frame < 96:
        progress = frame / 95.0
        # Radar sweep animation in center
        cx, cy = WIDTH // 2, HEIGHT // 2 - 40
        angle = frame * 0.15
        for r in (120, 220, 320):
            draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(14, 165, 233, 80), width=2)
        # Radar beam
        bx = cx + 320 * math.cos(angle)
        by = cy + 320 * math.sin(angle)
        draw.line([(cx, cy), (bx, by)], fill=(56, 189, 248, 200), width=3)
        
        # Red warning blips on radar
        draw.ellipse([cx + 140, cy - 80, cx + 155, cy - 65], fill=(239, 68, 68), outline=(255, 255, 255))
        draw.ellipse([cx - 200, cy + 110, cx - 185, cy + 125], fill=(239, 68, 68), outline=(255, 255, 255))

        # Typography
        draw.text((cx - 520, cy - 35), "YOUR WI-FI ROUTER IS BLIND.", fill=(255, 255, 255), font=font_huge)
        draw.text((cx - 360, cy + 70), "Enterprise SIEMs cost $100,000 / year.", fill=(244, 63, 94), font=font_sub)
        draw.text((cx - 420, cy + 140), "Meet GARUDA v4 — Autonomous Personal Network Defense.", fill=(14, 165, 233), font=font_body)

    # -------------------------------------------------------------
    # SCENE 2: 5-LAYER HARDWARE DISCOVERY (96 - 203 / 3.2s - 6.8s)
    # -------------------------------------------------------------
    elif frame < 204:
        rel = frame - 96
        draw.text((120, 120), "100% REAL HARDWARE RECOGNITION", fill=(255, 255, 255), font=font_huge)
        draw.text((125, 220), "5-Layer Pipeline: mDNS · SSDP UPnP XML · DHCP Option 12 · NetBIOS · 35k OUI Cache", fill=(56, 189, 248), font=font_sub)
        draw.text((125, 270), "Zero 'Unknown Device' labels. Real names, real vendors, real latency.", fill=(148, 163, 184), font=font_body)

        devices = [
            ("omen (This Computer)", "AzureWave / HP Wi-Fi · 192.168.1.13", "Windows 11 Laptop", (14, 165, 233)),
            ("Zyxel / Airtel Fiber Router", "Main Wi-Fi Gateway · 192.168.1.1", "Wi-Fi 6 Gateway", (234, 179, 8)),
            ("[LG] webOS TV UK6360PTE", "LG Electronics / Arcadyan · 192.168.1.2", "4K Smart TV", (168, 85, 247)),
            ("Canon G4070 series Printer", "Canon Inc. · 192.168.1.17", "IPP Office Printer", (16, 185, 129)),
            ("realme-13-Pro-5G", "Realme Mobile · 192.168.1.5", "Android Phone", (59, 130, 246)),
        ]

        for i, (name, meta, dtype, col) in enumerate(devices):
            slide = min(1.0, max(0.0, (rel - i * 8) / 12.0))
            if slide > 0.0:
                card_x = int(120 + (1.0 - slide) * 80)
                card_y = 350 + i * 130
                draw_card(draw, card_x, card_y, 1680, 105, (15, 23, 42, 220), col)
                draw.ellipse([card_x + 30, card_y + 35, card_x + 65, card_y + 70], fill=col)
                draw.text((card_x + 95, card_y + 20), name, fill=(255, 255, 255), font=font_sub)
                draw.text((card_x + 95, card_y + 60), meta, fill=(148, 163, 184), font=font_body)
                draw_badge(draw, card_x + 1430, card_y + 35, dtype, (col[0]//3, col[1]//3, col[2]//3, 80), col)

    # -------------------------------------------------------------
    # SCENE 3: PACKET IDS & DGA DETECTOR (204 - 311 / 6.8s - 10.4s)
    # -------------------------------------------------------------
    elif frame < 312:
        rel = frame - 204
        draw.text((120, 120), "REAL-TIME L2–L7 INTRUSION DETECTION", fill=(255, 255, 255), font=font_huge)
        draw.text((125, 220), "Continuous Scapy Packet Sniffer & Shannon Entropy Classifier", fill=(244, 63, 94), font=font_sub)

        # Critical Alert Banner
        pulse = 0.5 + 0.5 * math.sin(frame * 0.4)
        border_col = (int(239 * pulse), 68, 68)
        draw_card(draw, 120, 290, 1680, 140, (40, 10, 15, 240), border_col)
        draw.text((160, 315), "⚠ CRITICAL ALERT: Possible Man-in-the-Middle Attack (ARP Spoofing)", fill=(255, 255, 255), font=font_title)
        draw.text((160, 375), "Router Gateway MAC altered from 6C:4F:89:99:AA:28 to DE:AD:BE:9F:01:22 in under 11ms.", fill=(254, 202, 202), font=font_body)

        # Telemetry cards
        draw_card(draw, 120, 470, 810, 500, (15, 23, 42, 220), (239, 68, 68))
        draw.text((160, 510), "AI DGA & DNS TUNNEL CLASSIFIER", fill=(239, 68, 68), font=font_sub)
        draw.text((160, 570), "Target: xk9q2z7m4p1w-botnet-c2-v4.biz", fill=(255, 255, 255), font=font_body)
        draw.text((160, 620), "Shannon Entropy: 4.214 bits / char", fill=(244, 63, 94), font=font_body)
        draw.text((160, 670), "DGA Botnet Probability: 84.0%", fill=(244, 63, 94), font=font_body)
        draw.text((160, 720), "Verdict: MALICIOUS_DGA (Flagged in 10.7ms)", fill=(239, 68, 68), font=font_title)
        draw.text((160, 790), "Explainable AI: High consonant clustering + random alphabet entropy.", fill=(148, 163, 184), font=font_mono)

        draw_card(draw, 990, 470, 810, 500, (15, 23, 42, 220), (14, 165, 233))
        draw.text((1030, 510), "BENIGN ZERO-FALSE-POSITIVE TEST", fill=(16, 185, 129), font=font_sub)
        draw.text((1030, 570), "Target: google.com", fill=(255, 255, 255), font=font_body)
        draw.text((1030, 620), "Shannon Entropy: 1.918 bits / char", fill=(16, 185, 129), font=font_body)
        draw.text((1030, 670), "DGA Botnet Probability: 1.0%", fill=(16, 185, 129), font=font_body)
        draw.text((1030, 720), "Verdict: BENIGN (Natural Human Name)", fill=(16, 185, 129), font=font_title)
        draw.text((1030, 790), "Result: Zero false positives across standard browsing workloads.", fill=(148, 163, 184), font=font_mono)

    # -------------------------------------------------------------
    # SCENE 4: CRYPTOGRAPHIC MERKLE LEDGER (312 - 419 / 10.4s - 14.0s)
    # -------------------------------------------------------------
    elif frame < 420:
        rel = frame - 312
        draw.text((120, 120), "Ed25519 MERKLE PROOFS & WEB3 ATTESTATION", fill=(255, 255, 255), font=font_huge)
        draw.text((125, 220), "Court-Admissible, Tamper-Evident Security Forensics Stored On-Chain", fill=(16, 185, 129), font=font_sub)

        draw_card(draw, 120, 300, 1680, 670, (15, 23, 42, 220), (16, 185, 129))
        
        # Merkle Tree graphic nodes
        tree_y = 380
        draw.text((160, tree_y), "ROOT: SHA-256 Merkle Root (bbde75dec4df5758e83df689c49ef1de...)", fill=(16, 185, 129), font=font_title)
        
        # Branch lines
        draw.line([(350, tree_y + 60), (250, tree_y + 140)], fill=(16, 185, 129), width=2)
        draw.line([(350, tree_y + 60), (450, tree_y + 140)], fill=(16, 185, 129), width=2)
        draw.line([(950, tree_y + 60), (850, tree_y + 140)], fill=(16, 185, 129), width=2)
        draw.line([(950, tree_y + 60), (1050, tree_y + 140)], fill=(16, 185, 129), width=2)

        blocks = [
            ("Block #58", "sim_malware_eicar", "YARA Virus Signature Detection in ~/Downloads"),
            ("Block #57", "alert_arp_spoof", "Gateway MAC Impersonation from 192.168.1.109"),
            ("Block #56", "ml_c2_beacon", "Robotic Periodic C2 Beaconing from xk9q2z7m4p1w-iot"),
            ("Block #55", "firewall_block", "Kernel Firewall Quarantine for Attacker 203.0.113.88"),
        ]

        for i, (bnum, btype, bdesc) in enumerate(blocks):
            by = 560 + i * 95
            draw_card(draw, 160, by, 1600, 75, (20, 30, 50, 200), (56, 189, 248))
            draw.text((190, by + 22), bnum, fill=(16, 185, 129), font=font_sub)
            draw.text((380, by + 25), btype, fill=(14, 165, 233), font=font_body)
            draw.text((700, by + 25), bdesc, fill=(255, 255, 255), font=font_body)
            draw_badge(draw, 1530, by + 20, "VERIFIED", (16, 185, 129, 60), (16, 185, 129))

    # -------------------------------------------------------------
    # SCENE 5: IPS FIREWALL & LOCKDOWN (420 - 515 / 14.0s - 17.2s)
    # -------------------------------------------------------------
    elif frame < 516:
        rel = frame - 420
        draw.text((120, 120), "ACTIVE IPS & HOST FIREWALL LOCKDOWN", fill=(255, 255, 255), font=font_huge)
        draw.text((125, 220), "Dynamic Subnet Quarantine · Static Gateway ARP Pinning · Outbound Killswitch", fill=(245, 158, 11), font=font_sub)

        # 3 Pillar Cards
        draw_card(draw, 120, 310, 530, 650, (15, 23, 42, 230), (239, 68, 68))
        draw.text((160, 350), "DYNAMIC FIREWALL", fill=(239, 68, 68), font=font_title)
        draw.text((160, 420), "Target: 203.0.113.88", fill=(255, 255, 255), font=font_sub)
        draw.text((160, 480), "Rule: GARUDA_BLOCK", fill=(148, 163, 184), font=font_body)
        draw.text((160, 540), "Engine: netsh advfirewall", fill=(14, 165, 233), font=font_body)
        draw.text((160, 600), "Status: QUARANTINED", fill=(239, 68, 68), font=font_sub)
        draw.text((160, 680), "Malicious packets severed at OS kernel level before reaching socket layer.", fill=(148, 163, 184), font=font_mono)

        draw_card(draw, 695, 310, 530, 650, (15, 23, 42, 230), (16, 185, 129))
        draw.text((735, 350), "STATIC ARP PINNING", fill=(16, 185, 129), font=font_title)
        draw.text((735, 420), "Gateway: 192.168.1.1", fill=(255, 255, 255), font=font_sub)
        draw.text((735, 480), "MAC: 6C:4F:89:99:AA:28", fill=(148, 163, 184), font=font_body)
        draw.text((735, 540), "Binding: PERMANENT", fill=(16, 185, 129), font=font_body)
        draw.text((735, 600), "Status: MITM IMMUNE", fill=(16, 185, 129), font=font_sub)
        draw.text((735, 680), "Locks router MAC in OS neighbor table to completely block ARP cache poisoning.", fill=(148, 163, 184), font=font_mono)

        draw_card(draw, 1270, 310, 530, 650, (15, 23, 42, 230), (245, 158, 11))
        draw.text((1310, 350), "TOTAL LOCKDOWN", fill=(245, 158, 11), font=font_title)
        draw.text((1310, 420), "Mode: KILLSWITCH", fill=(255, 255, 255), font=font_sub)
        draw.text((1310, 480), "Scope: Non-Loopback Traffic", fill=(148, 163, 184), font=font_body)
        draw.text((1310, 540), "Trigger: 1-Click Panic Button", fill=(245, 158, 11), font=font_body)
        draw.text((1310, 600), "Status: READY", fill=(16, 185, 129), font=font_sub)
        draw.text((1310, 680), "Instantly severs all outbound data channels during active ransomware or data breach.", fill=(148, 163, 184), font=font_mono)

    # -------------------------------------------------------------
    # SCENE 6: OUTRO & CALL TO ACTION (516 - 599 / 17.2s - 20.0s)
    # -------------------------------------------------------------
    else:
        rel = frame - 516
        cx = WIDTH // 2
        cy = HEIGHT // 2 - 20
        
        # Center logo
        if garuda_logo:
            lw, lh = 180, 180
            lx = cx - lw // 2
            ly = cy - 250
            im.paste(garuda_logo.resize((lw, lh)), (lx, ly), garuda_logo.resize((lw, lh)))

        draw.text((cx - 570, cy - 40), "GARUDA v4 — TAKE BACK YOUR WI-FI.", fill=(255, 255, 255), font=font_huge)
        draw.text((cx - 480, cy + 60), "Autonomous Packet IDS · Behavioral ML · Ed25519 Web3 Merkle Ledger", fill=(14, 165, 233), font=font_sub)
        
        # Badges row
        bx = cx - 440
        by = cy + 130
        bx += draw_badge(draw, bx, by, "100% SELF-HOSTED") + 15
        bx += draw_badge(draw, bx, by, "ZERO CLOUD TELEMETRY") + 15
        bx += draw_badge(draw, bx, by, "GRADE A+ RATING (9.3/10)") + 15
        bx += draw_badge(draw, bx, by, "OPEN SOURCE MIT")

        draw_card(draw, cx - 400, cy + 200, 800, 90, (15, 23, 42, 240), (234, 179, 8))
        draw.text((cx - 360, cy + 225), "github.com/DHRUVASAI/GARUDA-", fill=(234, 179, 8), font=font_title)

    # Save frame
    frame_path = WORK_DIR / f"frame_{frame:04d}.png"
    im.save(frame_path, "PNG")

    # Pick Frame 560 as the settled poster frame
    if frame == 560:
        poster_path = OUT_DIR / "brag.jpg"
        im.convert("RGB").save(poster_path, "JPEG", quality=95)
        print(f"[+] Poster frame saved: {poster_path}")

    if frame % 100 == 0:
        print(f"  -> Rendered frame {frame}/{TOTAL_FRAMES}...")

print("[+] All 600 frames rendered successfully!")

# ==============================================================================
# 3. Bake Poster into Frame 0
# ==============================================================================
poster_img = Image.open(OUT_DIR / "brag.jpg").convert("RGBA")
poster_img.save(WORK_DIR / "frame_0000.png", "PNG")
print("[+] Poster baked into frame 0 of video sequence.")

# ==============================================================================
# 4. Encoding Video with FFMPEG
# ==============================================================================
output_mp4 = OUT_DIR / "brag.mp4"
print(f"[+] 3. Encoding brag.mp4 via ffmpeg...")

cmd = [
    FFMPEG_EXE, "-y",
    "-framerate", "30",
    "-i", str(WORK_DIR / "frame_%04d.png"),
    "-i", str(WORK_DIR / "audio.wav"),
    "-c:v", "libx264",
    "-preset", "fast",
    "-crf", "18",
    "-pix_fmt", "yuv420p",
    "-c:a", "aac",
    "-b:a", "192k",
    "-shortest",
    str(output_mp4)
]

res = subprocess.run(cmd, capture_output=True, text=True)
if res.returncode == 0:
    print(f"[✓] SUCCESS! Video generated at: {output_mp4}")
    print(f"    Size: {os.path.getsize(output_mp4) / (1024*1024):.2f} MB")
else:
    print(f"[✗] FFMPEG Error: {res.stderr}")
    sys.exit(1)
