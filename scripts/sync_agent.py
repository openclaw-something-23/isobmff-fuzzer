#!/usr/bin/env python3
"""
AFL++ Distributed Corpus Sync Agent
====================================
Runs as a background service on WORKER machines.

Bidirectional sync with the controller:
  1. Downloads new corpus entries from controller's main/queue →
     places in local afl_sync/main/queue/ so local AFL++ picks them up
  2. Scans local worker queues for new discoveries →
     uploads to controller so its AFL++ picks them up

Usage:
  CONTROLLER_URL=http://1.2.3.4:56789 \
  WORKER_NAME=worker_ph \
  AFL_SYNC_DIR=/results/afl_sync \
  python3 sync_agent.py

Environment variables:
  CONTROLLER_URL      - controller dashboard URL (required)
  WORKER_NAME         - unique name for this worker machine (e.g. worker_ph)
  AFL_SYNC_DIR        - AFL++ -o sync directory (default: /results/afl_sync)
  SYNC_INTERVAL       - seconds between sync cycles (default: 30)
  DASHBOARD_PASSWORD  - controller dashboard password (default: helloworld)
  MAX_FILE_BYTES      - max corpus entry size to sync (default: 65536)
  SYNC_STATS_FILE     - where to write sync stats JSON (default: /results/sync_stats.json)
"""
import os, sys, time, hashlib, json, logging, signal, socket
from pathlib import Path
import urllib.request, urllib.parse, urllib.error, http.cookiejar

# ── Config ────────────────────────────────────────────────────────────────────
CONTROLLER_URL = os.environ.get("CONTROLLER_URL", "").rstrip("/")
AFL_SYNC_DIR   = Path(os.environ.get("AFL_SYNC_DIR", "/results/afl_sync"))
WORKER_NAME    = os.environ.get("WORKER_NAME", f"worker_{socket.gethostname()[:12]}")
SYNC_INTERVAL  = int(os.environ.get("SYNC_INTERVAL", "30"))
PASSWORD       = os.environ.get("DASHBOARD_PASSWORD", "helloworld")
MAX_FILE_BYTES = int(os.environ.get("MAX_FILE_BYTES", str(65536)))
STATS_FILE     = Path(os.environ.get("SYNC_STATS_FILE", "/results/sync_stats.json"))

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[sync %(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("sync_agent")

# ── HTTP client (stdlib, no external deps) ────────────────────────────────────
_cookie_jar = http.cookiejar.CookieJar()
_opener     = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(_cookie_jar),
    # Don't auto-follow redirects so we can capture the login 303+cookie
    urllib.request.HTTPRedirectHandler()
)

def _login() -> bool:
    """Login to controller and store session cookie."""
    data = urllib.parse.urlencode({"password": PASSWORD}).encode()
    try:
        req = urllib.request.Request(
            f"{CONTROLLER_URL}/auth/login",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST"
        )
        try:
            _opener.open(req, timeout=10)
        except urllib.error.HTTPError as e:
            # 303 redirect is expected - the cookie is on this response
            pass
        for cookie in _cookie_jar:
            if cookie.name == "fuzz_session":
                log.info(f"Logged in to controller at {CONTROLLER_URL}")
                return True
        log.warning("Login: no session cookie received")
        return False
    except Exception as e:
        log.error(f"Login failed: {e}")
        return False

def _api_get(endpoint: str, retry_auth: bool = True):
    """GET /api/<endpoint> → parsed JSON, or None on error."""
    try:
        resp = _opener.open(f"{CONTROLLER_URL}{endpoint}", timeout=20)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 401 and retry_auth:
            if _login():
                return _api_get(endpoint, retry_auth=False)
        log.warning(f"GET {endpoint} → HTTP {e.code}")
        return None
    except Exception as e:
        log.debug(f"GET {endpoint} failed: {e}")
        return None

def _api_post_bytes(endpoint: str, data: bytes,
                    content_type: str = "application/octet-stream",
                    retry_auth: bool = True):
    """POST raw bytes to /api/<endpoint> → parsed JSON, or None."""
    try:
        req = urllib.request.Request(
            f"{CONTROLLER_URL}{endpoint}",
            data=data,
            headers={"Content-Type": content_type},
            method="POST"
        )
        resp = _opener.open(req, timeout=20)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 401 and retry_auth:
            if _login():
                return _api_post_bytes(endpoint, data, content_type, retry_auth=False)
        log.warning(f"POST {endpoint} → HTTP {e.code}")
        return None
    except Exception as e:
        log.debug(f"POST {endpoint} failed: {e}")
        return None

# ── State ─────────────────────────────────────────────────────────────────────
_known_ctrl_hashes:   set[str] = set()   # hashes we already downloaded from controller
_uploaded_hashes:     set[str] = set()   # hashes we already uploaded to controller
_stats = {
    "worker_name":  WORKER_NAME,
    "controller":   CONTROLLER_URL,
    "downloaded":   0,
    "uploaded":     0,
    "errors":       0,
    "last_sync_ts": 0,
    "last_sync":    "",
    "cycles":       0,
}

def _file_hash(path: Path) -> str:
    """SHA1 of file content (matches AFL++ naming convention)."""
    try:
        return hashlib.sha1(path.read_bytes()).hexdigest()
    except Exception:
        return ""

def _write_stats():
    try:
        STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATS_FILE.write_text(json.dumps(_stats, indent=2))
    except Exception:
        pass

# ── Sync: controller → local ──────────────────────────────────────────────────
def sync_from_controller():
    """Download new entries from controller's main/queue into local afl_sync/main/queue/."""
    entries = _api_get("/api/sync/entries")
    if not entries:
        return 0

    local_main_q = AFL_SYNC_DIR / "main" / "queue"
    local_main_q.mkdir(parents=True, exist_ok=True)

    downloaded = 0
    for entry in entries:
        h    = entry.get("hash", "")
        size = entry.get("size", 0)
        if not h or h in _known_ctrl_hashes:
            continue
        if size > MAX_FILE_BYTES:
            _known_ctrl_hashes.add(h)
            continue

        data = None
        try:
            resp = _opener.open(f"{CONTROLLER_URL}/api/sync/entry/{h}", timeout=20)
            data = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                if _login():
                    try:
                        resp = _opener.open(f"{CONTROLLER_URL}/api/sync/entry/{h}", timeout=20)
                        data = resp.read()
                    except Exception:
                        pass
        except Exception as e:
            log.debug(f"Download entry {h[:8]}: {e}")

        if data is None:
            _stats["errors"] += 1
            continue

        # Write to local main/queue with AFL++-compatible name
        dst = local_main_q / f"sync_ctrl_{h[:16]}"
        if not dst.exists():
            try:
                dst.write_bytes(data)
                downloaded += 1
            except Exception as e:
                log.debug(f"Write {dst}: {e}")

        _known_ctrl_hashes.add(h)

    if downloaded:
        log.info(f"← Downloaded {downloaded} new corpus entries from controller")
    return downloaded

# ── Sync: local → controller ──────────────────────────────────────────────────
def sync_to_controller():
    """Upload new worker queue discoveries to controller."""
    if not AFL_SYNC_DIR.is_dir():
        return 0

    uploaded = 0
    # Scan all worker queues (dirs matching worker_<name>_* or WORKER_NAME_*)
    for inst_dir in AFL_SYNC_DIR.iterdir():
        if not inst_dir.is_dir():
            continue
        # Only upload from our own worker instances
        if not inst_dir.name.startswith(WORKER_NAME) and \
           not inst_dir.name.startswith("worker_"):
            continue
        if inst_dir.name == "main":
            continue

        q_dir = inst_dir / "queue"
        if not q_dir.is_dir():
            continue

        for entry in q_dir.iterdir():
            if not entry.is_file():
                continue
            if entry.name.startswith("."):
                continue
            if entry.stat().st_size > MAX_FILE_BYTES:
                continue

            h = _file_hash(entry)
            if not h or h in _uploaded_hashes:
                continue

            try:
                data = entry.read_bytes()
            except Exception:
                continue

            result = _api_post_bytes(
                f"/api/sync/entry/{inst_dir.name}/{entry.name}",
                data
            )
            if result is not None:
                _uploaded_hashes.add(h)
                uploaded += 1
            else:
                _stats["errors"] += 1

    if uploaded:
        log.info(f"→ Uploaded {uploaded} new discoveries to controller")
    return uploaded


# ── Worker ping ───────────────────────────────────────────────────────────────
def ping_controller():
    """Tell controller we're alive + send basic stats."""
    # Gather local AFL stats
    instances = []
    if AFL_SYNC_DIR.is_dir():
        for inst in AFL_SYNC_DIR.iterdir():
            if not inst.is_dir() or inst.name == "main":
                continue
            stats_f = inst / "fuzzer_stats"
            if not stats_f.exists():
                continue
            kv = {}
            try:
                for line in stats_f.read_text().splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        kv[k.strip()] = v.strip()
            except Exception:
                continue
            instances.append({
                "instance":      inst.name,
                "execs_done":    int(kv.get("execs_done", 0)),
                "execs_per_sec": float(kv.get("execs_per_sec", 0)),
                "edges_found":   int(kv.get("edges_found", 0)),
                "corpus_count":  int(kv.get("corpus_count", 0)),
                "saved_crashes": int(kv.get("saved_crashes", 0)),
                "last_update":   int(kv.get("last_update", 0)),
            })

    payload = json.dumps({
        "worker_name":  WORKER_NAME,
        "instances":    instances,
        "downloaded":   _stats["downloaded"],
        "uploaded":     _stats["uploaded"],
        "timestamp":    int(time.time()),
    }).encode()

    _api_post_bytes("/api/sync/worker_ping", payload, "application/json")


# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    if not CONTROLLER_URL:
        log.error("CONTROLLER_URL not set. Exiting.")
        sys.exit(1)

    log.info(f"Sync agent starting: worker={WORKER_NAME} controller={CONTROLLER_URL} interval={SYNC_INTERVAL}s")
    AFL_SYNC_DIR.mkdir(parents=True, exist_ok=True)

    # Initial login
    for attempt in range(5):
        if _login():
            break
        log.warning(f"Login attempt {attempt+1}/5 failed, retrying in 10s...")
        time.sleep(10)
    else:
        log.error("Could not login to controller after 5 attempts. Will retry in loop.")

    def _shutdown(sig, frame):
        log.info("Sync agent shutting down.")
        _write_stats()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    while True:
        cycle_start = time.time()
        try:
            dl = sync_from_controller()
            ul = sync_to_controller()
            ping_controller()

            _stats["downloaded"]   += dl
            _stats["uploaded"]     += ul
            _stats["last_sync_ts"]  = int(time.time())
            _stats["last_sync"]     = time.strftime("%Y-%m-%d %H:%M:%S")
            _stats["cycles"]       += 1
            _write_stats()

        except Exception as e:
            log.error(f"Sync cycle error: {e}", exc_info=True)
            _stats["errors"] += 1

        elapsed = time.time() - cycle_start
        sleep_for = max(0, SYNC_INTERVAL - elapsed)
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
