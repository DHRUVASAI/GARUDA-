"""
GARUDA Desktop Standalone Launcher.
Starts the embedded Uvicorn server, launches the user's default browser,
and runs the local tactical guardian engine with OS socket privileges.
"""

import os
import sys
import time
import socket
import threading
import webbrowser
from pathlib import Path

# Add current directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import uvicorn


def find_free_port(default_port=8000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", default_port))
        s.close()
        return default_port
    except OSError:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port


def open_browser(port):
    time.sleep(1.8)
    url = f"http://localhost:{port}/"
    print(f"\n[GARUDA] Opening browser at {url} ...")
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"[GARUDA] Could not automatically open browser: {e}")


def main():
    print("=" * 64)
    print("  GARUDA -- Tactical Network Guardian & Anomaly Engine")
    print("  Mode: Standalone Native Host Engine")
    print("=" * 64)

    port = find_free_port(8000)

    # Launch browser in a background thread
    t = threading.Thread(target=open_browser, args=(port,), daemon=True)
    t.start()

    print(f"[GARUDA] Server running on http://127.0.0.1:{port}")
    print("[GARUDA] To exit, close this window or press Ctrl+C.\n")

    # Run Uvicorn directly
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=port, log_level="warning")


if __name__ == "__main__":
    main()
