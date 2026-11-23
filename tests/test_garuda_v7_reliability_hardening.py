import concurrent.futures
import os
import tempfile
from fastapi.testclient import TestClient

tmp_db = os.path.join(tempfile.gettempdir(), "garuda_v7_reliability.db")
if os.path.exists(tmp_db):
    os.remove(tmp_db)
os.environ["DATABASE_URL"] = f"sqlite:///{tmp_db}"
os.environ["GARUDA_REQUIRE_AUTH"] = "false"

from backend.app.main import app  # noqa: E402
from backend.app.database import init_db  # noqa: E402


def test_concurrent_requests_and_ledger_integrity():
    init_db()
    with TestClient(app) as client:
        def hit_health(_):
            r = client.get("/health")
            return r.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            codes = list(ex.map(hit_health, range(24)))
        assert all(c == 200 for c in codes)

        # Verify cryptographic ledger integrity endpoint responds cleanly
        verify = client.get("/api/ledger/verify")
        assert verify.status_code == 200

        # Verify adaptive intelligence status & poisoning guard bounds
        st = client.get("/api/adaptive/status")
        assert st.status_code == 200
        assert st.json()["poisoning_guard_bounds"] == [0.45, 0.88]
