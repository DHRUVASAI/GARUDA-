import os
import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

cmd = [
    sys.executable,
    "-m", "PyInstaller",
    "--name=GARUDA",
    "--onefile",
    "--clean",
    "--noconfirm",
    f"--add-data={BASE_DIR / 'frontend'};frontend",
    f"--add-data={BASE_DIR / 'rules'};rules",
    "--exclude-module=torch",
    "--exclude-module=torchvision",
    "--exclude-module=torchaudio",
    "--exclude-module=scipy",
    "--exclude-module=pytest",
    "--exclude-module=matplotlib",
    "--exclude-module=IPython",
    "--exclude-module=PIL",
    "--hidden-import=uvicorn",
    "--hidden-import=uvicorn.logging",
    "--hidden-import=uvicorn.loops",
    "--hidden-import=uvicorn.loops.auto",
    "--hidden-import=uvicorn.protocols",
    "--hidden-import=uvicorn.protocols.http",
    "--hidden-import=uvicorn.protocols.http.auto",
    "--hidden-import=uvicorn.protocols.websockets",
    "--hidden-import=uvicorn.protocols.websockets.auto",
    "--hidden-import=uvicorn.lifespan",
    "--hidden-import=uvicorn.lifespan.on",
    "--hidden-import=scapy",
    "--hidden-import=scapy.layers.l2",
    "--hidden-import=scapy.layers.inet",
    "--hidden-import=scapy.layers.dhcp",
    "--hidden-import=sqlalchemy.dialects.sqlite",
    "--hidden-import=backend.app.main",
    "--hidden-import=backend.app.routers.admin_and_doctor",
    str(BASE_DIR / "desktop_launcher.py"),
]

print("Executing PyInstaller command:\n", " ".join(cmd))
res = subprocess.run(cmd, cwd=str(BASE_DIR))
sys.exit(res.returncode)
