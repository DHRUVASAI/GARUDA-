import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import User
from app.services.auth import (
    create_access_token,
    decode_access_token,
    ensure_default_admin,
    hash_password,
    verify_password,
)


@pytest.fixture(autouse=True)
def setup_auth_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    ensure_default_admin(db)
    db.close()
    yield


def test_password_hashing():
    pw = "SuperSecretPassword123!"
    h = hash_password(pw)
    assert h.startswith("pbkdf2_sha256$")
    assert verify_password(pw, h) is True
    assert verify_password("WrongPassword", h) is False
    assert verify_password("", h) is False


def test_access_token_creation_and_decoding():
    token = create_access_token("secops_lead", role="admin", expires_hours=2)
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "secops_lead"
    assert payload["role"] == "admin"
    assert payload["exp"] > payload["iat"]

    # Tampered token
    tampered = token[:-4] + "ABCD"
    assert decode_access_token(tampered) is None


def test_auth_api_login_success():
    client = TestClient(app)
    res = client.post("/api/auth/login", json={"username": "admin", "password": "garuda-admin-secure"})
    assert res.status_code == 200
    data = res.json()
    assert "token" in data
    assert data["token_type"] == "Bearer"
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"


def test_auth_api_login_invalid():
    client = TestClient(app)
    res = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password-here"})
    assert res.status_code == 401
    assert "Invalid username or password" in res.json()["detail"]


def test_auth_api_me_authenticated():
    client = TestClient(app)
    # Login first
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "garuda-admin-secure"})
    token = login_res.json()["token"]

    # Fetch /api/auth/me with bearer token
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["authenticated"] is True
    assert me_data["user"]["username"] == "admin"


def test_auth_api_me_unauthenticated():
    client = TestClient(app)
    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["authenticated"] is False
    assert me_data["user"] is None


def test_auth_api_logout():
    client = TestClient(app)
    res = client.post("/api/auth/logout")
    assert res.status_code == 200
    assert res.json()["ok"] is True
