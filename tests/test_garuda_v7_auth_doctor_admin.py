import os
import tempfile
from fastapi.testclient import TestClient

# Isolate test DB
tmp_db = os.path.join(tempfile.gettempdir(), "garuda_v7_test.db")
if os.path.exists(tmp_db):
    os.remove(tmp_db)
os.environ["DATABASE_URL"] = f"sqlite:///{tmp_db}"
os.environ["GARUDA_REQUIRE_AUTH"] = "false"

from backend.app.main import app  # noqa: E402
from backend.app.database import init_db  # noqa: E402


def test_v7_auth_doctor_and_admin_flow():
    init_db()
    from backend.app.database import SessionLocal
    from backend.app.models import User
    db = SessionLocal()
    try:
        db.query(User).filter(User.username.in_(["root_admin", "normal_viewer"])).delete()
        db.commit()
    finally:
        db.close()

    with TestClient(app) as client:
        # 1. Health check
        h = client.get("/health")
        assert h.status_code == 200
        assert h.json()["version"] in ("7.0.0", "8.0.0", "9.0.0", "10.0.0")

        # 2. First registered user becomes admin
        r1 = client.post("/api/auth/register", json={
            "username": "root_admin",
            "email": "admin@garuda.test",
            "password": "StrongPassword123!",
        })
        assert r1.status_code == 200
        admin_data = r1.json()
        assert admin_data["role"] == "admin"
        admin_headers = {"Authorization": f"Bearer {admin_data['access_token']}"}

        # 3. Second registered user becomes viewer
        r2 = client.post("/api/auth/register", json={
            "username": "normal_viewer",
            "email": "viewer@garuda.test",
            "password": "ViewerPassword123!",
        })
        assert r2.status_code == 200
        viewer_data = r2.json()
        assert viewer_data["role"] == "viewer"
        viewer_headers = {"Authorization": f"Bearer {viewer_data['access_token']}"}

        # 4. Viewer cannot access Admin Control endpoints
        assert client.get("/api/admin/users", headers=viewer_headers).status_code == 403

        # 5. Admin can list users and promote viewer -> analyst
        users_res = client.get("/api/admin/users", headers=admin_headers)
        assert users_res.status_code == 200
        assert len(users_res.json()) == 2

        promote = client.patch(
            f"/api/admin/users/{viewer_data['id']}/role",
            json={"role": "analyst"},
            headers=admin_headers,
        )
        assert promote.status_code == 200
        assert promote.json()["role"] == "analyst"

        # 6. Network Doctor runs diagnostics & logs history
        doc = client.get("/api/doctor/diagnose", headers=admin_headers)
        assert doc.status_code == 200
        body = doc.json()
        assert 0 <= body["health_score"] <= 100
        assert "dns" in body["checks"]

        # 7. Admin Audit Logs recorded the role update
        logs = client.get("/api/admin/audit-logs", headers=admin_headers)
        assert logs.status_code == 200
        assert any(l["action"] == "ROLE_UPDATE" for l in logs.json())
