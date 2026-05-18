"""
FastAPI Backend for SecureScore
Production-ready with rate limiting, API key auth, security headers
"""
import os
import time
import json
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from threading import Lock

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, field_validator
import subprocess
import sys

# ── Config from environment (with safe defaults for local dev) ────────────────
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

API_KEY = os.getenv("SECURESCORE_API_KEY", "")  # empty = disabled locally
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "300"))
MAX_REPORT_AGE_SECONDS = 600

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecureScore API",
    version="1.0.0",
    docs_url=None,   # disable Swagger in production
    redoc_url=None,
)

# ── CORS — only what's needed ─────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)

# ── Security headers middleware ───────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ── Simple in-process rate limiter ────────────────────────────────────────────
_rate_store: dict = defaultdict(list)
_rate_lock = Lock()

# Daily scan counter — resets at midnight UTC
_daily_scans: dict = defaultdict(lambda: {"count": 0, "date": ""})
_daily_lock = Lock()
FREE_SCANS_PER_DAY = int(os.getenv("FREE_SCANS_PER_DAY", "2"))

def rate_limit(request: Request, max_calls: int = 5, window: int = 60):
    """Allow max_calls per IP per window seconds."""
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    with _rate_lock:
        calls = _rate_store[ip]
        # Remove calls outside the window
        _rate_store[ip] = [t for t in calls if now - t < window]
        if len(_rate_store[ip]) >= max_calls:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Max {max_calls} scans per {window}s per IP."
            )
        _rate_store[ip].append(now)

def check_daily_limit(request: Request):
    """Allow FREE_SCANS_PER_DAY scans per IP per calendar day."""
    if FREE_SCANS_PER_DAY == 0:
        return  # 0 = unlimited
    ip = request.client.host if request.client else "unknown"
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with _daily_lock:
        entry = _daily_scans[ip]
        if entry["date"] != today:
            _daily_scans[ip] = {"count": 0, "date": today}
        if _daily_scans[ip]["count"] >= FREE_SCANS_PER_DAY:
            raise HTTPException(
                status_code=429,
                detail=f"You have used your {FREE_SCANS_PER_DAY} free scans for today. "
                       f"Contact fredrick.ighile.dev@gmail.com for full access."
            )
        _daily_scans[ip]["count"] += 1

def scan_rate_limit(request: Request):
    rate_limit(request, max_calls=5, window=60)

# ── Optional API key auth ─────────────────────────────────────────────────────
def check_api_key(request: Request):
    """If API_KEY env var is set, enforce it. Otherwise skip (local dev)."""
    if not API_KEY:
        return  # disabled locally
    key = request.headers.get("X-API-Key", "")
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

# ── Input model ───────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")

        # Strip scheme and path
        v = re.sub(r"^https?://", "", v)
        v = v.split("/")[0].split("?")[0].split("#")[0]

        # Length cap
        if len(v) > 253:
            raise ValueError("Target too long")

        domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        ip_pattern     = r"^(\d{1,3}\.){3}\d{1,3}$"

        is_domain = re.match(domain_pattern, v)
        is_ip     = re.match(ip_pattern, v)

        if not is_domain and not is_ip:
            raise ValueError(
                "Invalid target. Enter a valid domain (example.com) or IP (192.168.1.1)"
            )

        if is_ip:
            parts = v.split(".")
            if any(int(p) > 255 for p in parts):
                raise ValueError("Invalid IP address")

        # Block private / reserved ranges
        blocked = [
            r"^localhost$", r"^127\.", r"^0\.",
            r"^192\.168\.", r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"^169\.254\.", r"^::1$", r"^fc", r"^fd",
        ]
        for pat in blocked:
            if re.match(pat, v, re.IGNORECASE):
                raise ValueError("Scanning private/reserved networks is not allowed")

        return v

# ── Helpers ───────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"

def safe_report_path(filename: str) -> Path:
    """Resolve path and ensure it stays inside REPORTS_DIR."""
    # Strip any traversal characters
    clean = re.sub(r"[^\w\-.]", "", filename)
    resolved = (REPORTS_DIR / clean).resolve()
    if not str(resolved).startswith(str(REPORTS_DIR.resolve())):
        raise HTTPException(status_code=400, detail="Invalid filename")
    return resolved

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "SecureScore API", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/api/scan")
async def scan_target(
    request: Request,
    body: ScanRequest,
    _rate: None = Depends(scan_rate_limit),
    _daily: None = Depends(check_daily_limit),
    _auth: None = Depends(check_api_key),
):
    target = body.target
    print(f"[*] Scan request: {target} from {request.client.host}")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "src.main", target],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            cwd=str(BASE_DIR),
        )

        # Log output safely (truncated)
        if result.stdout:
            print(f"[*] stdout: {result.stdout[-1500:]}")
        if result.stderr:
            print(f"[*] stderr: {result.stderr[-800:]}")

        # Detect Python crashes
        fatal = ["ModuleNotFoundError", "ImportError", "Traceback (most recent call last)"]
        if any(e in result.stderr for e in fatal):
            last_line = [l.strip() for l in result.stderr.strip().splitlines() if l.strip()][-1]
            print(f"[!] Scanner crashed: {last_line}")
            raise HTTPException(
                status_code=500,
                detail=f"Scanner error: {last_line}. Run: pip install python-nmap dnspython requests reportlab"
            )

        if result.returncode not in [0, 1, 2]:
            raise HTTPException(status_code=500, detail="Scan failed. Target may be unreachable.")

        # Find report
        if not REPORTS_DIR.exists():
            raise HTTPException(status_code=500, detail="Reports directory not found")

        pattern = target.replace(".", "_").replace("-", "_")
        matches = list(REPORTS_DIR.glob(f"scan_{pattern}_*.json"))

        if not matches:
            cutoff = time.time() - MAX_REPORT_AGE_SECONDS
            all_json = list(REPORTS_DIR.glob("scan_*.json"))
            matches = [f for f in all_json if pattern in f.name.replace("-", "_")]
            if not matches:
                matches = [f for f in all_json if f.stat().st_mtime > cutoff]

        if not matches:
            raise HTTPException(status_code=500, detail="Scan completed but report not found")

        latest = max(matches, key=lambda p: p.stat().st_mtime)

        with open(latest, "r", encoding="utf-8") as f:
            data = json.load(f)

        return data

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Scan timeout — target may be unreachable")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Corrupt report file")
    except HTTPException:
        raise
    except Exception as e:
        print(f"[!] Unexpected: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/reports")
def list_reports(_auth: None = Depends(check_api_key)):
    try:
        if not REPORTS_DIR.exists():
            return []

        json_files = list(REPORTS_DIR.glob("scan_*.json"))
        pdf_files  = list(REPORTS_DIR.glob("*.pdf"))
        reports    = []

        for f in json_files:
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    d = json.load(fh)
                tname = d.get("target", "").replace(".", "_").replace("-", "_")
                # Match PDFs - handles ransomware_assessment_*, report_*, scan_* naming
                pdf = next(
                    (p.name for p in pdf_files if tname in p.name.replace("-", "_").replace(".", "_")),
                    None
                )
                # Fallback: get newest PDF if no match found
                if not pdf and pdf_files:
                    pdf = max(pdf_files, key=lambda p: p.stat().st_mtime).name
                reports.append({
                    "filename":     f.name,
                    "pdf_filename": pdf,
                    "target":       d.get("target"),
                    "scan_time":    d.get("scan_time"),
                    "risk_score":   d.get("overall_risk", {}).get("total_risk_score", 0),
                    "risk_level":   d.get("overall_risk", {}).get("risk_level", "UNKNOWN"),
                })
            except Exception:
                continue

        reports.sort(key=lambda x: x.get("scan_time", ""), reverse=True)
        return reports

    except Exception as e:
        print(f"[!] list_reports error: {e}")
        return []


@app.get("/api/download-pdf/{filename}")
def download_pdf(filename: str, _auth: None = Depends(check_api_key)):
    try:
        pdf_path = safe_report_path(filename)

        if not pdf_path.exists():
            raise HTTPException(status_code=404, detail="Report not found")

        if pdf_path.suffix.lower() != ".pdf":
            raise HTTPException(status_code=400, detail="Only PDF files can be downloaded")

        return FileResponse(
            path=pdf_path,
            media_type="application/pdf",
            filename=pdf_path.name,
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"[!] download_pdf error: {e}")
        raise HTTPException(status_code=500, detail="Download failed")


# ── 429 handler ───────────────────────────────────────────────────────────────
@app.exception_handler(429)
async def rate_limit_handler(request: Request, exc):
    return JSONResponse(status_code=429, content={"detail": str(exc.detail)})


if __name__ == "__main__":
    import uvicorn
    print("[*] Starting SecureScore API...")
    print(f"[*] Allowed origins: {ALLOWED_ORIGINS}")
    print(f"[*] API key auth: {'ENABLED' if API_KEY else 'DISABLED (local dev)'}")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")