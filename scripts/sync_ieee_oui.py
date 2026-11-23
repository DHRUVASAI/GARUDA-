"""One-command offline/online sync for the full 45,000+ official IEEE OUI registry."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.app.services.oui_db import sync_ieee_oui_database


if __name__ == "__main__":
    res = asyncio.run(sync_ieee_oui_database())
    print(f"Synced {res['synced']} IEEE OUI prefixes to {res['cache_path']}")
