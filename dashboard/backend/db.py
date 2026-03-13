"""
SQLite database layer for the fuzzing dashboard.
"""
import sqlite3
import os
import json
from contextlib import contextmanager
from typing import Optional

DB_PATH = os.environ.get("DB_PATH", "/results/fuzzer.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    status          TEXT DEFAULT 'running',
    started_at      INTEGER,
    ended_at        INTEGER,
    duration_sec    INTEGER DEFAULT 0,
    crashes         INTEGER DEFAULT 0,
    cov_edges       INTEGER DEFAULT 0,
    cov_lines_pct   REAL    DEFAULT 0.0,
    cov_funcs_pct   REAL    DEFAULT 0.0,
    execs_per_sec   INTEGER DEFAULT 0,
    score           INTEGER DEFAULT 0,
    exit_code       INTEGER DEFAULT 0,
    notes           TEXT    DEFAULT ''
);

CREATE TABLE IF NOT EXISTS crashes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT,
    crash_file      TEXT,
    crash_type      TEXT DEFAULT 'unknown',
    severity        INTEGER DEFAULT 0,
    stack_hash      TEXT,
    input_size      INTEGER DEFAULT 0,
    trace_preview   TEXT DEFAULT '',
    is_unique       INTEGER DEFAULT 1,
    created_at      INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS coverage_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT,
    timestamp       INTEGER DEFAULT (strftime('%s','now')),
    lines_pct       REAL DEFAULT 0.0,
    funcs_pct       REAL DEFAULT 0.0,
    edges           INTEGER DEFAULT 0,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_runs_score     ON runs(score DESC);
CREATE INDEX IF NOT EXISTS idx_crashes_hash   ON crashes(stack_hash);
CREATE INDEX IF NOT EXISTS idx_crashes_run    ON crashes(run_id);
"""

@contextmanager
def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        conn.executescript(SCHEMA)
    # On startup, mark all stale "running" rows as "interrupted"
    with get_db() as conn:
        conn.execute("""
            UPDATE runs SET status='interrupted'
            WHERE status='running'
        """)

def scan_and_import_results(results_dir: str = "/results"):
    """Import any run metadata files not yet in DB."""
    runs_dir = os.path.join(results_dir, "runs")
    if not os.path.isdir(runs_dir):
        return

    with get_db() as conn:
        existing = {row[0] for row in conn.execute("SELECT run_id FROM runs")}

    for run_id in os.listdir(runs_dir):
        if run_id in existing:
            continue
        meta_file = os.path.join(runs_dir, run_id, "meta.json")
        if not os.path.isfile(meta_file):
            continue
        try:
            with open(meta_file) as f:
                meta = json.load(f)
            with get_db() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO runs
                    (run_id, status, started_at, ended_at, duration_sec,
                     crashes, cov_edges, cov_lines_pct, cov_funcs_pct,
                     execs_per_sec, score, exit_code)
                    VALUES (:run_id, :status, :started_at, :ended_at, :duration_sec,
                            :crashes, :cov_edges, :cov_lines_pct, :cov_funcs_pct,
                            :execs_per_sec, :score, :exit_code)
                """, {
                    "run_id": meta.get("run_id", run_id),
                    "status": meta.get("status", "done"),
                    "started_at": meta.get("started_at", 0),
                    "ended_at": meta.get("ended_at", 0),
                    "duration_sec": meta.get("duration_sec", 0),
                    "crashes": meta.get("crashes", 0),
                    "cov_edges": meta.get("cov_edges", 0),
                    "cov_lines_pct": float(meta.get("cov_lines_pct", 0)),
                    "cov_funcs_pct": float(meta.get("cov_funcs_pct", 0)),
                    "execs_per_sec": meta.get("execs_per_sec", 0),
                    "score": meta.get("score", 0),
                    "exit_code": meta.get("exit_code", 0),
                })
        except Exception as e:
            print(f"[!] Failed to import {run_id}: {e}")

    # Import crash metadata
    crashes_dir = os.path.join(results_dir, "crashes")
    if not os.path.isdir(crashes_dir):
        return

    with get_db() as conn:
        existing_crashes = {
            row[0] for row in conn.execute("SELECT crash_file FROM crashes")
        }

    for fname in os.listdir(crashes_dir):
        if not fname.endswith(".json"):
            continue
        crash_name = fname[:-5]
        if crash_name in existing_crashes:
            continue
        try:
            with open(os.path.join(crashes_dir, fname)) as f:
                crash = json.load(f)

            # Mark duplicate if same stack_hash already seen
            with get_db() as conn:
                dup = conn.execute(
                    "SELECT id FROM crashes WHERE stack_hash = ? AND stack_hash != ''",
                    (crash.get("stack_hash", ""),)
                ).fetchone()
                is_unique = 0 if dup else 1
                conn.execute("""
                    INSERT OR IGNORE INTO crashes
                    (run_id, crash_file, crash_type, severity, stack_hash,
                     input_size, trace_preview, is_unique)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    crash.get("run_id", ""),
                    crash_name,
                    crash.get("crash_type", "unknown"),
                    crash.get("severity", 30),
                    crash.get("stack_hash", ""),
                    crash.get("input_size", 0),
                    crash.get("trace_preview", "")[:2000],
                    is_unique,
                ))
        except Exception as e:
            print(f"[!] Failed to import crash {fname}: {e}")
