# GARUDA v7 — Production & AWS Deployment Guide

## What Was Upgraded Over v6
1. **Multi-User Authentication & RBAC (`backend/app/auth.py`, `backend/app/models.py`)**:
   - JWT Bearer authentication + bcrypt password hashing.
   - Roles: `admin`, `analyst`, `viewer` (first registered user automatically becomes `admin`, or pre-seed via `GARUDA_ADMIN_*` env vars).
   - Automatic PostgreSQL support (`DATABASE_URL`) with SQLite fallback for local development.
2. **Network Doctor (`backend/app/services/network_doctor.py`)**:
   - Diagnostics for DNS latency, outbound TLS (`1.1.1.1:443`), ARP duplicate-MAC spoofing check, risky open ports (`21, 23, 445, 3389, 5900`), and CPU/RAM vitals.
   - Persistent `DoctorReport` history + `/api/doctor/heal` audit logging.
3. **Admin Control Plane (`backend/app/routers/admin_and_doctor.py`)**:
   - User listing, role switching (`viewer` / `analyst` / `admin`), account enable/disable, system status, and immutable `AdminAuditLog` trail.
   - Firewall block/unblock/lockdown routes enforce `admin` role when `GARUDA_REQUIRE_AUTH=true` and log every action.
4. **Frontend Integration (`frontend/index.html`, `frontend/v7-addon.js`, `frontend/v7-addon.css`)**:
   - Login/Register modal with automatic `Authorization: Bearer <token>` attachment on `/api/*` calls.
   - New **Network Doctor** tab and admin-only **Admin Control** tab.
5. **Pre-Deployment Hardening**:
   - Security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`), configurable `ALLOWED_ORIGINS`, `/health` Docker healthcheck, PostgreSQL 16 `docker-compose.yml`, Nginx WebSocket proxy config, and AWS EC2 launch scripts.

## Important Security Step First
Rotate any AWS IAM access key that was pasted into chat before running deployment scripts, and never commit `.env` or `.pem` files to Git.

## Local Verification
```bash
pip install -r requirements.txt
pytest tests/
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

## Deploy to AWS EC2 (`us-east-1`)
### Option A: PowerShell (Windows)
```powershell
$env:AWS_ACCESS_KEY_ID="YOUR_ROTATED_KEY"
$env:AWS_SECRET_ACCESS_KEY="YOUR_ROTATED_SECRET"
$env:AWS_DEFAULT_REGION="us-east-1"
.\deployws_deploy_ec2.ps1
```

### Option B: Bash (Linux / macOS / WSL)
```bash
export AWS_ACCESS_KEY_ID="YOUR_ROTATED_KEY"
export AWS_SECRET_ACCESS_KEY="YOUR_ROTATED_SECRET"
export AWS_DEFAULT_REGION="us-east-1"
bash deploy/aws_deploy_ec2.sh
```

### On the EC2 Server
```bash
cp .env.example .env
# Edit .env with strong POSTGRES_PASSWORD, GARUDA_JWT_SECRET, and GARUDA_ADMIN_PASSWORD
nano .env
docker compose up -d --build
curl http://localhost:8000/health
```
