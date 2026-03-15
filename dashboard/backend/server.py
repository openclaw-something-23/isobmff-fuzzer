"""
ISOBMFF Fuzzer Dashboard — FastAPI Backend
Port: 56789
"""
import os, time, subprocess, json
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Response, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import (JSONResponse, FileResponse, RedirectResponse,
                                HTMLResponse, StreamingResponse)
from pydantic import BaseModel
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from starlette.middleware.base import BaseHTTPMiddleware

from db import init_db, get_db, scan_and_import_results

app = FastAPI(title="ISOBMFF Fuzzer Dashboard", version="1.0.0")

RESULTS_DIR        = os.environ.get("RESULTS_DIR", "/results")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "helloworld")
SECRET_KEY         = os.environ.get("SECRET_KEY", "fuzzer-secret-key-change-me")
SESSION_MAX_AGE    = 60 * 60 * 24 * 7
COOKIE_NAME        = "fuzz_session"

signer = URLSafeTimedSerializer(SECRET_KEY)

# ── Auth ──────────────────────────────────────────────────────────────────────
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

class AuthMiddleware(BaseHTTPMiddleware):
    PUBLIC = {"/auth/login", "/auth/logout", "/favicon.ico"}
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in self.PUBLIC:
            return await call_next(request)
        if path.startswith("/api/") and request.method in ("POST", "PATCH"):
            return await call_next(request)
        if not is_authenticated(request):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)
            return RedirectResponse(url="/auth/login")
        return await call_next(request)

app.add_middleware(AuthMiddleware)

# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    init_db()
    scan_and_import_results(RESULTS_DIR)

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.get("/auth/login", include_in_schema=False)
async def login_page():
    return FileResponse("/dashboard/static/login.html")

@app.post("/auth/login", include_in_schema=False)
async def do_login(password: str = Form(...)):
    if password == DASHBOARD_PASSWORD:
        token = make_session_token()
        resp = RedirectResponse(url="/", status_code=303)
        resp.set_cookie(COOKIE_NAME, token, max_age=SESSION_MAX_AGE, httponly=True, samesite="lax")
        return resp
    return Response(content="Invalid password", status_code=401)

@app.get("/auth/logout", include_in_schema=False)
async def logout():
    resp = RedirectResponse(url="/auth/login", status_code=303)
    resp.delete_cookie(COOKIE_NAME)
    return resp

# ── Index ─────────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def serve_index(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/auth/login")
    return FileResponse("/dashboard/static/index.html")

# ── Models ────────────────────────────────────────────────────────────────────
class RunCreate(BaseModel):
    run_id: str; status: str = "running"; started_at: int = 0

class RunUpdate(BaseModel):
    status: Optional[str] = None; ended_at: Optional[int] = None
    duration_sec: Optional[int] = None; crashes: Optional[int] = None
    cov_edges: Optional[int] = None; cov_lines_pct: Optional[float] = None
    cov_funcs_pct: Optional[float] = None; execs_per_sec: Optional[int] = None
    score: Optional[int] = None; exit_code: Optional[int] = None
    corpus_found: Optional[int] = None

class CrashCreate(BaseModel):
    run_id: str; crash_file: str; crash_type: str = "unknown"
    severity: int = 30; stack_hash: str = ""; input_size: int = 0; trace_preview: str = ""

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats(request: Request):
    check_auth(request)
    scan_and_import_results(RESULTS_DIR)
    with get_db() as conn:
        total_runs     = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        total_crashes  = conn.execute("SELECT COUNT(*) FROM crashes").fetchone()[0]
        unique_crashes = conn.execute("SELECT COUNT(*) FROM crashes WHERE is_unique=1").fetchone()[0]
        best_score     = conn.execute("SELECT MAX(score) FROM runs").fetchone()[0] or 0
        best_cov       = conn.execute("SELECT MAX(cov_lines_pct) FROM runs").fetchone()[0] or 0.0
        best_edges     = conn.execute("SELECT MAX(cov_edges) FROM runs WHERE status='done'").fetchone()[0] or 0
        avg_speed      = conn.execute("SELECT AVG(execs_per_sec) FROM runs WHERE status='done' AND execs_per_sec > 0").fetchone()[0] or 0.0
        crash_types    = {r[0]: r[1] for r in conn.execute("SELECT crash_type, COUNT(*) FROM crashes GROUP BY crash_type")}
        # Cumulative corpus entries found by AFL++
        total_corpus_found = conn.execute("SELECT SUM(corpus_found) FROM runs WHERE status='done'").fetchone()[0] or 0

    # ── Corpus count ──────────────────────────────────────────────────────────
    # 1. Seed corpus: count files ≤ 100 to detect the 7-seed init corpus
    #    If the dir has >1000 files it's the stale libFuzzer corpus — ignore it
    seed_dirs = ["/fuzzer/corpus", os.path.join(RESULTS_DIR, "../fuzzer/corpus")]
    seed_count = 0
    for d in seed_dirs:
        if os.path.isdir(d):
            files = [f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))]
            if len(files) <= 1000:   # only count if it's a real seed dir (not 157k libFuzzer corpus)
                seed_count = len(files)
            break

    # 2. AFL++ queue count (from most recent completed run)
    afl_queue_count = 0
    afl_out_dir = os.path.join(RESULTS_DIR, "afl_out")
    if os.path.isdir(afl_out_dir):
        for run_dir in sorted(os.listdir(afl_out_dir), reverse=True)[:5]:
            queue_dir = os.path.join(afl_out_dir, run_dir, "main", "queue")
            if os.path.isdir(queue_dir):
                afl_queue_count = sum(1 for f in os.listdir(queue_dir) if not f.startswith('.'))
                break

    # 3. Latest fuzzer_stats corpus_count (live, from active run)
    live_corpus = 0
    if os.path.isdir(afl_out_dir):
        for run_dir in sorted(os.listdir(afl_out_dir), reverse=True)[:3]:
            stats_file = os.path.join(afl_out_dir, run_dir, "main", "fuzzer_stats")
            if os.path.isfile(stats_file):
                try:
                    with open(stats_file) as f:
                        for line in f:
                            if line.startswith("corpus_count"):
                                live_corpus = int(line.split(":")[1].strip())
                                break
                    if live_corpus:
                        break
                except Exception:
                    pass

    # Best corpus count: live > queue > seeds
    corpus_total = live_corpus or afl_queue_count or seed_count

    # ── Running fuzzer instances (all matching containers) ────────────────────
    fuzzer_status = "unknown"
    running_now = 0
    try:
        # List ALL running containers named isobmff-fuzzer* (supports scale > 1)
        ps_out = subprocess.check_output(
            ["docker", "ps",
             "--filter", "name=isobmff-fuzzer",
             "--filter", "status=running",
             "--format", "{{.Names}}"],
            stderr=subprocess.DEVNULL).decode().strip()
        running_containers = [l for l in ps_out.splitlines() if l.strip()]
        running_now = len(running_containers)

        # Also get the primary container status for display
        inspect_out = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.State.Status}}", "isobmff-fuzzer"],
            stderr=subprocess.DEVNULL).decode().strip()
        fuzzer_status = inspect_out
    except Exception:
        fuzzer_status = "unknown"
        running_now = 0

    return {
        "total_runs": total_runs,
        "total_crashes": total_crashes,
        "unique_crashes": unique_crashes,
        "best_score": best_score,
        "best_coverage_pct": round(best_cov, 2),
        "best_edges": int(best_edges),
        "avg_execs_per_sec": round(avg_speed, 1),
        "crash_types": crash_types,
        "fuzzer_container": fuzzer_status,
        "running": running_now,
        "corpus_seeds": seed_count,
        "corpus_queue": afl_queue_count,
        "corpus_live": live_corpus,
        "corpus_total": corpus_total,
        "corpus_found_cumulative": int(total_corpus_found or 0),
        "updated_at": int(time.time()),
    }

# ── Runs ──────────────────────────────────────────────────────────────────────
@app.get("/api/runs")
async def list_runs(request: Request, limit: int = 50, offset: int = 0, sort: str = "score"):
    check_auth(request)
    scan_and_import_results(RESULTS_DIR)
    if sort not in {"score","started_at","crashes","cov_edges","cov_lines_pct"}: sort = "score"
    with get_db() as conn:
        rows  = conn.execute(f"SELECT * FROM runs ORDER BY {sort} DESC LIMIT ? OFFSET ?", (limit,offset)).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    return {"total": total, "runs": [dict(r) for r in rows]}

@app.post("/api/runs")
async def create_run(run: RunCreate):
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO runs (run_id,status,started_at) VALUES (?,?,?)",
                     (run.run_id, run.status, run.started_at or int(time.time())))
    return {"run_id": run.run_id}

@app.patch("/api/runs/{run_id}")
async def update_run(run_id: str, data: RunUpdate):
    fields = {k:v for k,v in data.dict().items() if v is not None}
    if not fields: raise HTTPException(400,"No fields to update")
    set_clause = ", ".join(f"{k}=?" for k in fields)
    with get_db() as conn:
        conn.execute(f"UPDATE runs SET {set_clause} WHERE run_id=?", list(fields.values())+[run_id])
    return {"ok": True}

@app.get("/api/runs/{run_id}")
async def get_run(request: Request, run_id: str):
    check_auth(request)
    with get_db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if not row: raise HTTPException(404,"Run not found")
    return dict(row)

# ── Crashes ───────────────────────────────────────────────────────────────────
@app.get("/api/crashes")
async def list_crashes(request: Request, run_id: Optional[str]=None,
                       unique_only: bool=False, limit: int=100, offset: int=0):
    check_auth(request)
    scan_and_import_results(RESULTS_DIR)
    conditions, params = [], []
    if run_id:      conditions.append("run_id=?");    params.append(run_id)
    if unique_only: conditions.append("is_unique=1")
    # Never show OOM
    conditions.append("crash_type != 'oom'")
    where = "WHERE " + " AND ".join(conditions)
    with get_db() as conn:
        rows  = conn.execute(f"SELECT * FROM crashes {where} ORDER BY severity DESC, created_at DESC LIMIT ? OFFSET ?",
                             params+[limit,offset]).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM crashes {where}", params).fetchone()[0]
    return {"total": total, "crashes": [dict(r) for r in rows]}

@app.post("/api/crashes")
async def create_crash(crash: CrashCreate):
    # Ignore OOM crashes
    if "oom" in crash.crash_file.lower() or crash.crash_type == "oom":
        return {"ok": True, "is_unique": False, "skipped": "oom"}
    with get_db() as conn:
        dup = conn.execute("SELECT id FROM crashes WHERE stack_hash=? AND stack_hash!=''", (crash.stack_hash,)).fetchone()
        is_unique = 0 if dup else 1
        conn.execute("""INSERT INTO crashes (run_id,crash_file,crash_type,severity,stack_hash,
                                             input_size,trace_preview,is_unique)
                        VALUES (?,?,?,?,?,?,?,?)""",
                     (crash.run_id, crash.crash_file, crash.crash_type, crash.severity,
                      crash.stack_hash, crash.input_size, crash.trace_preview[:2000], is_unique))
    return {"ok": True, "is_unique": bool(is_unique)}

# ── Download crash file ───────────────────────────────────────────────────────
@app.get("/api/crashes/{crash_file}/download")
async def download_crash(request: Request, crash_file: str):
    check_auth(request)
    # Sanitize filename (no path traversal)
    safe = Path(crash_file).name
    path = Path(RESULTS_DIR) / "crashes" / safe
    if not path.is_file():
        raise HTTPException(404, "Crash file not found")
    return FileResponse(str(path), filename=safe,
                        media_type="application/octet-stream")

# ── Live AFL++ stats (from live_stats.json written by run_fuzzer.sh) ──────────
@app.get("/api/live")
async def live_stats(request: Request):
    """Live AFL++ stats polled every 15s by run_fuzzer.sh background reporter."""
    check_auth(request)  # raises HTTPException(401) — NOT inside try/except
    live_file = os.path.join(RESULTS_DIR, "live_stats.json")
    if not os.path.isfile(live_file):
        return {"running": False, "updated_at": 0}
    # NOTE: check_auth is outside try/except so HTTPException propagates correctly
    data = {}
    ok = False
    try:
        with open(live_file) as f:
            data = json.load(f)
        ok = True
    except Exception:
        pass
    if not ok:
        return {"running": False, "updated_at": 0}
    age = int(time.time()) - data.get("updated_at", 0)
    data["stale"] = age > 60
    data["running"] = True
    return data


@app.get("/api/mp4gen")
async def mp4gen_stats(request: Request):
    """Stats from the parallel mp4gen corpus generator."""
    check_auth(request)
    log_file   = os.path.join(RESULTS_DIR, "mp4gen.log")
    stats_file = os.path.join(RESULTS_DIR, "mp4gen_stats.json")

    # running = log file exists AND modified within last 90 seconds
    running = False
    last_log_line = ""
    if os.path.isfile(log_file):
        age = time.time() - os.path.getmtime(log_file)
        running = age < 90
        try:
            # grab last meaningful line for in-progress display
            with open(log_file, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 2048))
                tail = f.read().decode("utf-8", errors="replace")
            lines = [l.strip() for l in tail.splitlines()
                     if l.strip()
                     and "\x1b" not in l
                     and "x264 [" not in l
                     and "WARNING:" not in l
                     and "Did you mean" not in l]
            last_log_line = lines[-1] if lines else ""
        except Exception:
            pass

    # Load stats (may not exist yet if no batch has completed)
    data: dict = {
        "total_generated": 0, "total_cmin": 0, "total_contributed": 0,
        "batch_count": 0, "last_batch_at": None, "batches": [],
    }
    if os.path.isfile(stats_file):
        try:
            with open(stats_file) as f:
                data = json.load(f)
        except Exception:
            pass

    data["running"] = running
    data["last_log_line"] = last_log_line
    data["pct_cmin"] = round(
        100.0 * data["total_cmin"] / max(data["total_generated"], 1), 2
    )
    data["pct_contributed"] = round(
        100.0 * data["total_contributed"] / max(data["total_generated"], 1), 2
    )
    data["pct_contributed_of_cmin"] = round(
        100.0 * data["total_contributed"] / max(data["total_cmin"], 1), 2
    )
    return data


@app.get("/api/coverage/timeline")
async def coverage_timeline(request: Request, limit: int = 200):
    check_auth(request)
    with get_db() as conn:
        # Prefer runs with real coverage (bitmap_cvg > 0); fall back to all recent
        rows = conn.execute("""
            SELECT run_id, started_at, cov_lines_pct, cov_funcs_pct, cov_edges, score, execs_per_sec
            FROM runs
            WHERE status='done' AND cov_edges > 0
            ORDER BY started_at ASC
            LIMIT ?
        """, (limit,)).fetchall()
        if not rows:
            rows = conn.execute("""
                SELECT run_id, started_at, cov_lines_pct, cov_funcs_pct, cov_edges, score, execs_per_sec
                FROM runs WHERE status='done'
                ORDER BY started_at DESC LIMIT ?
            """, (min(limit, 50),)).fetchall()
            rows = list(reversed(rows))
    return [dict(r) for r in rows]

@app.get("/api/coverage/{run_id}/html")
async def coverage_html(request: Request, run_id: str):
    check_auth(request)
    safe = Path(run_id).name
    path = Path(RESULTS_DIR) / "coverage" / f"{safe}_coverage.html"
    if not path.is_file():
        raise HTTPException(404, "Coverage HTML not available for this run")
    return FileResponse(str(path), media_type="text/html")

@app.get("/api/coverage/{run_id}/download")
async def download_coverage(request: Request, run_id: str):
    check_auth(request)
    safe = Path(run_id).name
    path = Path(RESULTS_DIR) / "coverage" / f"{safe}_coverage.html"
    if not path.is_file():
        raise HTTPException(404, "Coverage HTML not available")
    return FileResponse(str(path), filename=f"coverage_{safe}.html",
                        media_type="application/octet-stream")

# ── Leaderboard ───────────────────────────────────────────────────────────────
@app.get("/api/leaderboard")
async def leaderboard(request: Request, limit: int = 20):
    check_auth(request)
    with get_db() as conn:
        rows = conn.execute("""SELECT run_id, score, crashes, cov_edges, cov_lines_pct,
                                      execs_per_sec, duration_sec, started_at
                               FROM runs WHERE status='done' ORDER BY score DESC LIMIT ?""", (limit,)).fetchall()
    return [{"rank": i+1, **dict(r)} for i, r in enumerate(rows)]

# ── Rescan ────────────────────────────────────────────────────────────────────
@app.post("/api/rescan")
async def rescan(request: Request, background_tasks: BackgroundTasks):
    check_auth(request)
    background_tasks.add_task(scan_and_import_results, RESULTS_DIR)
    return {"ok": True}

# ── Static ────────────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="/dashboard/static"), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=56789, reload=False)
