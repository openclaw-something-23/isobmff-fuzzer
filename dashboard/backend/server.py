"""
ISOBMFF Fuzzer Dashboard — FastAPI Backend
Port: 56789
Auth: session cookie (password: configured via DASHBOARD_PASSWORD env)
"""
import os
import time
import hashlib
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Response, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse, HTMLResponse
from pydantic import BaseModel
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from db import init_db, get_db, scan_and_import_results

app = FastAPI(title="ISOBMFF Fuzzer Dashboard", version="1.0.0")

RESULTS_DIR      = os.environ.get("RESULTS_DIR", "/results")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "helloworld")
SECRET_KEY       = os.environ.get("SECRET_KEY", "fuzzer-secret-key-change-me")
SESSION_MAX_AGE  = 60 * 60 * 24 * 7   # 7 days
COOKIE_NAME      = "fuzz_session"

signer = URLSafeTimedSerializer(SECRET_KEY)

# ─────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────
def make_session_token() -> str:
    return signer.dumps({"auth": True, "ts": int(time.time())})

def verify_session(token: str) -> bool:
    try:
        signer.loads(token, max_age=SESSION_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False

def is_authenticated(request: Request) -> bool:
    token = request.cookies.get(COOKIE_NAME)
    return bool(token and verify_session(token))

def check_auth(request: Request):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

# ─────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    init_db()
    scan_and_import_results(RESULTS_DIR)

# ─────────────────────────────────────────────
# Auth routes (public)
# ─────────────────────────────────────────────
@app.get("/auth/login", include_in_schema=False)
async def login_page():
    return FileResponse("/dashboard/static/login.html")

@app.post("/auth/login", include_in_schema=False)
async def do_login(response: Response, password: str = Form(...)):
    if password == DASHBOARD_PASSWORD:
        token = make_session_token()
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="lax",
        )
        return response
    return Response(content="Invalid password", status_code=401)

@app.get("/auth/logout", include_in_schema=False)
async def logout():
    resp = RedirectResponse(url="/auth/login", status_code=303)
    resp.delete_cookie(COOKIE_NAME)
    return resp

# ─────────────────────────────────────────────
# Serve index.html (protected)
# ─────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def serve_index(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/auth/login")
    return FileResponse("/dashboard/static/index.html")

# ─────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────
class RunCreate(BaseModel):
    run_id: str
    status: str = "running"
    started_at: int = 0

class RunUpdate(BaseModel):
    status: Optional[str] = None
    ended_at: Optional[int] = None
    duration_sec: Optional[int] = None
    crashes: Optional[int] = None
    cov_edges: Optional[int] = None
    cov_lines_pct: Optional[float] = None
    cov_funcs_pct: Optional[float] = None
    execs_per_sec: Optional[int] = None
    score: Optional[int] = None
    exit_code: Optional[int] = None

class CrashCreate(BaseModel):
    run_id: str
    crash_file: str
    crash_type: str = "unknown"
    severity: int = 30
    stack_hash: str = ""
    input_size: int = 0
    trace_preview: str = ""

# ─────────────────────────────────────────────
# API — Stats (protected)
# ─────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats(request: Request):
    check_auth(request)
    scan_and_import_results(RESULTS_DIR)
    with get_db() as conn:
        total_runs     = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        running        = conn.execute("SELECT COUNT(*) FROM runs WHERE status='running'").fetchone()[0]
        total_crashes  = conn.execute("SELECT COUNT(*) FROM crashes").fetchone()[0]
        unique_crashes = conn.execute("SELECT COUNT(*) FROM crashes WHERE is_unique=1").fetchone()[0]
        best_score     = conn.execute("SELECT MAX(score) FROM runs").fetchone()[0] or 0
        best_cov       = conn.execute("SELECT MAX(cov_lines_pct) FROM runs").fetchone()[0] or 0.0
        avg_speed      = conn.execute("SELECT AVG(execs_per_sec) FROM runs WHERE status='done'").fetchone()[0] or 0.0
        crash_types    = {r[0]: r[1] for r in conn.execute("SELECT crash_type, COUNT(*) FROM crashes GROUP BY crash_type")}

    # Real-time fuzzer container status
    import subprocess
    try:
        out = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.State.Status}}", "isobmff-fuzzer"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        fuzzer_status = out
    except Exception:
        fuzzer_status = "unknown"

    return {
        "total_runs": total_runs,
        "running": running,
        "total_crashes": total_crashes,
        "unique_crashes": unique_crashes,
        "best_score": best_score,
        "best_coverage_pct": round(best_cov, 2),
        "avg_execs_per_sec": round(avg_speed, 1),
        "crash_types": crash_types,
        "fuzzer_container": fuzzer_status,
        "updated_at": int(time.time()),
    }

# ─────────────────────────────────────────────
# API — Runs
# ─────────────────────────────────────────────
@app.get("/api/runs")
async def list_runs(request: Request, limit: int = 50, offset: int = 0, sort: str = "score"):
    check_auth(request)
    scan_and_import_results(RESULTS_DIR)
    allowed = {"score", "started_at", "crashes", "cov_edges", "cov_lines_pct"}
    if sort not in allowed: sort = "score"
    with get_db() as conn:
        rows  = conn.execute(f"SELECT * FROM runs ORDER BY {sort} DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    return {"total": total, "runs": [dict(r) for r in rows]}

@app.post("/api/runs")
async def create_run(run: RunCreate):
    # Internal (fuzzer → dashboard), no auth required
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO runs (run_id, status, started_at) VALUES (?, ?, ?)",
                     (run.run_id, run.status, run.started_at or int(time.time())))
    return {"run_id": run.run_id}

@app.patch("/api/runs/{run_id}")
async def update_run(run_id: str, data: RunUpdate):
    fields = {k: v for k, v in data.dict().items() if v is not None}
    if not fields: raise HTTPException(400, "No fields to update")
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    with get_db() as conn:
        conn.execute(f"UPDATE runs SET {set_clause} WHERE run_id = ?", list(fields.values()) + [run_id])
    return {"ok": True}

@app.get("/api/runs/{run_id}")
async def get_run(request: Request, run_id: str):
    check_auth(request)
    with get_db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if not row: raise HTTPException(404, "Run not found")
    return dict(row)

# ─────────────────────────────────────────────
# API — Crashes
# ─────────────────────────────────────────────
@app.get("/api/crashes")
async def list_crashes(request: Request, run_id: Optional[str] = None,
                       unique_only: bool = False, limit: int = 100, offset: int = 0):
    check_auth(request)
    scan_and_import_results(RESULTS_DIR)
    conditions, params = [], []
    if run_id:      conditions.append("run_id = ?");    params.append(run_id)
    if unique_only: conditions.append("is_unique = 1")
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    with get_db() as conn:
        rows  = conn.execute(f"SELECT * FROM crashes {where} ORDER BY severity DESC, created_at DESC LIMIT ? OFFSET ?",
                             params + [limit, offset]).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM crashes {where}", params).fetchone()[0]
    return {"total": total, "crashes": [dict(r) for r in rows]}

@app.post("/api/crashes")
async def create_crash(crash: CrashCreate):
    with get_db() as conn:
        dup = conn.execute("SELECT id FROM crashes WHERE stack_hash = ? AND stack_hash != ''", (crash.stack_hash,)).fetchone()
        is_unique = 0 if dup else 1
        conn.execute("""INSERT INTO crashes (run_id, crash_file, crash_type, severity, stack_hash, input_size, trace_preview, is_unique)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                     (crash.run_id, crash.crash_file, crash.crash_type, crash.severity,
                      crash.stack_hash, crash.input_size, crash.trace_preview[:2000], is_unique))
    return {"ok": True, "is_unique": bool(is_unique)}

# ─────────────────────────────────────────────
# API — Coverage timeline
# ─────────────────────────────────────────────
@app.get("/api/coverage/timeline")
async def coverage_timeline(request: Request, limit: int = 100):
    check_auth(request)
    with get_db() as conn:
        rows = conn.execute("""SELECT run_id, started_at, cov_lines_pct, cov_funcs_pct, cov_edges, score
                               FROM runs WHERE status='done' ORDER BY started_at ASC LIMIT ?""", (limit,)).fetchall()
    return [dict(r) for r in rows]

# ─────────────────────────────────────────────
# API — Leaderboard
# ─────────────────────────────────────────────
@app.get("/api/leaderboard")
async def leaderboard(request: Request, limit: int = 20):
    check_auth(request)
    with get_db() as conn:
        rows = conn.execute("""SELECT run_id, score, crashes, cov_edges, cov_lines_pct,
                                      execs_per_sec, duration_sec, started_at
                               FROM runs WHERE status='done' ORDER BY score DESC LIMIT ?""", (limit,)).fetchall()
    return [{"rank": i+1, **dict(r)} for i, r in enumerate(rows)]

# ─────────────────────────────────────────────
# API — Coverage HTML
# ─────────────────────────────────────────────
@app.get("/api/coverage/{run_id}/html")
async def coverage_html(request: Request, run_id: str):
    check_auth(request)
    path = os.path.join(RESULTS_DIR, "coverage", f"{run_id}_coverage.html")
    if not os.path.isfile(path): raise HTTPException(404, "Coverage report not available")
    return FileResponse(path, media_type="text/html")

# ─────────────────────────────────────────────
# API — Rescan
# ─────────────────────────────────────────────
@app.post("/api/rescan")
async def rescan(request: Request, background_tasks: BackgroundTasks):
    check_auth(request)
    background_tasks.add_task(scan_and_import_results, RESULTS_DIR)
    return {"ok": True}

# ─────────────────────────────────────────────
# Static files (protected middleware)
# ─────────────────────────────────────────────
from starlette.middleware.base import BaseHTTPMiddleware

class AuthMiddleware(BaseHTTPMiddleware):
    PUBLIC = {"/auth/login", "/auth/logout", "/favicon.ico"}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Allow public paths and internal API writes (from fuzzer)
        if path in self.PUBLIC:
            return await call_next(request)
        if path.startswith("/api/") and request.method in ("POST", "PATCH"):
            return await call_next(request)
        # Protect everything else
        if not is_authenticated(request):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)
            return RedirectResponse(url="/auth/login")
        return await call_next(request)

app.add_middleware(AuthMiddleware)

# Static files (served after auth check by middleware)
app.mount("/static", StaticFiles(directory="/dashboard/static"), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=56789, reload=False)
