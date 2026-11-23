"""
GARUDA v10 Authentication, RBAC, Refresh Tokens & RFC-6238 TOTP MFA
-------------------------------------------------------------------
Uses Python stdlib hashlib.pbkdf2_hmac("sha256") with 16-byte random salt:
  - Zero passlib / bcrypt>=4.0 wrap-bug crashes
  - No 72-byte password length restriction
  - Constant-time verification via hmac.compare_digest
  - Rotating Refresh Tokens (/api/auth/refresh)
  - Pure-Python RFC-6238 TOTP 2FA for Admin accounts
"""
import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .config import (
    BOOTSTRAP_ADMIN_EMAIL,
    BOOTSTRAP_ADMIN_PASSWORD,
    BOOTSTRAP_ADMIN_USER,
    JWT_ALGORITHM,
    JWT_EXPIRE_MINUTES,
    JWT_SECRET_KEY,
    REQUIRE_AUTH,
)
from .database import get_db
from .models import AdminAuditLog, User

PBKDF2_ITERATIONS = 260_000
REFRESH_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_DAYS", "14"))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(plain: str, stored: str) -> bool:
    try:
        scheme, iters_s, salt_hex, dk_hex = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), bytes.fromhex(salt_hex), int(iters_s))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_refresh_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh" or not payload.get("sub"):
            raise ValueError("Invalid token type")
        return payload
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")


# ---- Pure-Python RFC 6238 TOTP (Authenticator App 2FA) ----
def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def compute_totp(secret_b32: str, step: int = 30, digits: int = 6, for_time: Optional[int] = None) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int((for_time if for_time is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    now = int(time.time())
    clean = (code or "").strip()
    for delta in range(-window, window + 1):
        if hmac.compare_digest(compute_totp(secret_b32, for_time=now + delta * 30), clean):
            return True
    return False


def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if not username:
            return None
    except JWTError:
        return None
    return db.query(User).filter(User.username == username, User.is_active == True).first()


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required or token expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise cred_exc
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if not username:
            raise cred_exc
    except JWTError:
        raise cred_exc
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user:
        raise cred_exc
    return user


def require_role(*allowed_roles: str):
    def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {', '.join(allowed_roles)}",
            )
        return user
    return _checker


def require_admin_if_enabled(
    user: Optional[User] = Depends(get_optional_user),
) -> Optional[User]:
    if REQUIRE_AUTH:
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required for this action",
            )
    return user


def log_admin_action(
    db: Session,
    actor_username: str,
    action: str,
    target: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    db.add(
        AdminAuditLog(
            actor_username=actor_username,
            action=action,
            target=target,
            detail=detail,
        )
    )
    db.commit()


def ensure_bootstrap_admin(db: Session) -> None:
    if not BOOTSTRAP_ADMIN_USER or not BOOTSTRAP_ADMIN_PASSWORD:
        return
    existing = db.query(User).filter(User.username == BOOTSTRAP_ADMIN_USER).first()
    if not existing:
        db.add(
            User(
                username=BOOTSTRAP_ADMIN_USER,
                email=BOOTSTRAP_ADMIN_EMAIL,
                hashed_password=hash_password(BOOTSTRAP_ADMIN_PASSWORD),
                role="admin",
                is_active=True,
            )
        )
        db.commit()
