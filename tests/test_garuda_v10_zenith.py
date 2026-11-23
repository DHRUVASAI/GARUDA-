from backend.app.auth import (
    compute_totp,
    create_refresh_token,
    decode_refresh_token,
    generate_totp_secret,
    hash_password,
    verify_password,
    verify_totp,
)
from backend.app.services.adaptive_intel import adaptive_intel
from backend.app.services.network_doctor import NetworkDoctor, RISKY_PORTS
from backend.app.services.oui_db import lookup_v8_iot_vendor


def test_v10_pbkdf2_handles_long_passwords_no_bcrypt_crash():
    long_pw = "A" * 128 + "!@#$"
    hashed = hash_password(long_pw)
    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password(long_pw, hashed) is True
    assert verify_password("wrong", hashed) is False


def test_v10_refresh_token_and_totp_mfa():
    rt = create_refresh_token({"sub": "admin", "role": "admin"})
    payload = decode_refresh_token(rt)
    assert payload["sub"] == "admin"
    assert payload["type"] == "refresh"

    secret = generate_totp_secret()
    code = compute_totp(secret)
    assert verify_totp(secret, code) is True
    assert verify_totp(secret, "000000") is False or code == "000000"


def test_v10_oui_two_tuple_exact():
    assert lookup_v8_iot_vendor("00:1E:8F:AA:BB:CC") == ("Canon Inc.", "printer")


def test_v10_network_doctor_expanded_ports_and_adaptive_persistence():
    assert len(RISKY_PORTS) >= 8
    assert 5555 in RISKY_PORTS and 27017 in RISKY_PORTS
    doc = NetworkDoctor().run_diagnostics()
    assert 0 <= doc["health_score"] <= 100
    assert doc["checks"]["risky_ports"]["ports_checked"] == len(RISKY_PORTS)

    res = adaptive_intel.record_false_positive(99, "benign.local", "admin")
    assert res["persisted"] is True
    assert 0.45 <= res["new_dynamic_threshold"] <= 0.88
