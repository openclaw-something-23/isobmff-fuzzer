"""
ISOBMFF Fuzzer Dashboard — FastAPI Backend
Port: 56789
"""
import os
import time
import json
from typing import Optional, List
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from db import init_db, get_db, scan_and_import_results

app = FastAPI(title="ISOBMFF Fuzzer Dashboard", version="1.0.0")

RESULTS_DIR = os.environ.get("RESULTS_DIR", "/results")

# ─────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    init_db()
    scan_and_import_results(RESULTS_DIR)

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
# Stats
# ─────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats():
    scan_and_import_results(RESULTS_DIR)
    with get_db() as conn:
        total_runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        running    = conn.execute("SELECT COUNT(*) FROM runs WHERE status='running'").fetchone()[0]
        total_crashes = conn.execute("SELECT COUNT(*) FROM crashes").fetchone()[0]
        unique_crashes = conn.execute("SELECT COUNT(*) FROM crashes WHERE is_unique=1").fetchone()[0]
        best_score = conn.execute("SELECT MAX(score) FROM runs").fetchone()[0] or 0
        best_cov   = conn.execute("SELECT MAX(cov_lines_pct) FROM runs").fetchone()[0] or 0.0
        avg_speed  = conn.execute("SELECT AVG(execs_per_sec) FROM runs WHERE status='done'").fetchone()[0] or 0.0

        # Crash breakdown by type
        crash_types = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT crash_type, COUNT(*) FROM crashes GROUP BY crash_type"
            )
        }

    return {
        "total_runs": total_runs,
        "running": running,
        "total_crashes": total_crashes,
        "unique_crashes": unique_crashes,
        "best_score": best_score,
        "best_coverage_pct": round(best_cov, 2),
        "avg_execs_per_sec": round(avg_speed, 1),
        "crash_types": crash_types,
        "updated_at": int(time.time()),
    }

# ─────────────────────────────────────────────
# Runs
# ─────────────────────────────────────────────
@app.get("/api/runs")
async def list_runs(limit: int = 50, offset: int = 0, sort: str = "score"):
    scan_and_import_results(RESULTS_DIR)
    allowed_sorts = {"score", "started_at", "crashes", "cov_edges", "cov_lines_pct"}
    if sort not in allowed_sorts:
        sort = "score"

    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM runs ORDER BY {sort} DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]

    return {
        "total": total,
        "runs": [dict(r) for r in rows],
    }

@app.post("/api/runs")
async def create_run(run: RunCreate):
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO runs (run_id, status, started_at) VALUES (?, ?, ?)",
            (run.run_id, run.status, run.started_at or int(time.time()))
        )
    return {"run_id": run.run_id}

@app.patch("/api/runs/{run_id}")
async def update_run(run_id: str, data: RunUpdate):
    fields = {k: v for k, v in data.dict().items() if v is not None}
    if not fields:
        raise HTTPException(400, "No fields to update")

    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [run_id]

    with get_db() as conn:
        conn.execute(f"UPDATE runs SET {set_clause} WHERE run_id = ?", values)
    return {"ok": True}

@app.get("/api/runs/{run_id}")
async def get_run(run_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Run not found")
    return dict(row)

# ─────────────────────────────────────────────
# Crashes
# ─────────────────────────────────────────────
@app.get("/api/crashes")
async def list_crashes(
    run_id: Optional[str] = None,
    unique_only: bool = False,
    limit: int = 100,
    offset: int = 0
):
    scan_and_import_results(RESULTS_DIR)
    conditions = []
    params = []

    if run_id:
        conditions.append("run_id = ?")
        params.append(run_id)
    if unique_only:
        conditions.append("is_unique = 1")

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM crashes {where} ORDER BY severity DESC, created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM crashes {where}", params).fetchone()[0]

    return {"total": total, "crashes": [dict(r) for r in rows]}

@app.post("/api/crashes")
async def create_crash(crash: CrashCreate):
    with get_db() as conn:
        dup = conn.execute(
            "SELECT id FROM crashes WHERE stack_hash = ? AND stack_hash != ''",
            (crash.stack_hash,)
        ).fetchone()
        is_unique = 0 if dup else 1

        conn.execute("""
            INSERT INTO crashes
            (run_id, crash_file, crash_type, severity, stack_hash,
             input_size, trace_preview, is_unique)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            crash.run_id, crash.crash_file, crash.crash_type,
            crash.severity, crash.stack_hash, crash.input_size,
            crash.trace_preview[:2000], is_unique
        ))
    return {"ok": True, "is_unique": bool(is_unique)}

# ─────────────────────────────────────────────
# Coverage timeline
# ─────────────────────────────────────────────
@app.get("/api/coverage/timeline")
async def coverage_timeline(limit: int = 100):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT run_id, started_at, cov_lines_pct, cov_funcs_pct, cov_edges, score
            FROM runs
            WHERE status = 'done'
            ORDER BY started_at ASC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]

# ─────────────────────────────────────────────
# Leaderboard
# ─────────────────────────────────────────────
@app.get("/api/leaderboard")
async def leaderboard(limit: int = 20):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT run_id, score, crashes, cov_edges, cov_lines_pct,
                   execs_per_sec, duration_sec, started_at
            FROM runs
            WHERE status = 'done'
            ORDER BY score DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [{"rank": i+1, **dict(r)} for i, r in enumerate(rows)]

# ─────────────────────────────────────────────
# Coverage HTML report
# ─────────────────────────────────────────────
@app.get("/api/coverage/{run_id}/html")
async def coverage_html(run_id: str):
    path = os.path.join(RESULTS_DIR, "coverage", f"{run_id}_coverage.html")
    if not os.path.isfile(path):
        raise HTTPException(404, "Coverage report not available")
    return FileResponse(path, media_type="text/html")

# ─────────────────────────────────────────────
# Trigger rescan
# ─────────────────────────────────────────────
@app.post("/api/rescan")
async def rescan(background_tasks: BackgroundTasks):
    background_tasks.add_task(scan_and_import_results, RESULTS_DIR)
    return {"ok": True}

# ─────────────────────────────────────────────
# Static frontend
# ─────────────────────────────────────────────
app.mount("/", StaticFiles(directory="/dashboard/static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=56789, reload=False)
