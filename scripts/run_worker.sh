#!/usr/bin/env bash
# run_worker.sh — AFL++ WORKER mode (remote machine)
#
# Remote workers run AFL++ secondaries and sync corpus with the controller.
# They do NOT run a main instance — the controller owns that.
#
# Instance naming: worker_<WORKER_NAME>_1, worker_<WORKER_NAME>_2, ...
# These names show up in the controller's afl_sync/ dir and dashboard.
#
# Required env vars:
#   WORKER_NAME         - unique ID for this machine (e.g. "ph" for powerhorse)
#   CONTROLLER_URL      - controller dashboard URL (e.g. http://1.2.3.4:56789)
#   DASHBOARD_PASSWORD  - for sync_agent auth (default: helloworld)
#
# Optional:
#   AFL_CORES           - number of AFL++ instances to run (default: nproc)
#   AFL_SYNC_DIR        - local AFL sync dir (default: /results/afl_sync)
#   MAX_TOTAL_TIME      - max run time in seconds (0 = unlimited)

set -euo pipefail

RESULTS="/results"
SEEDS="${SEEDS:-/fuzzer/corpus}"
HARNESS="/fuzzer/fuzz_isobmff_afl"
[ -x "/results/fuzz_isobmff_afl_new" ] && HARNESS="/results/fuzz_isobmff_afl_new"
DICT="${RESULTS}/isobmff.dict"
[ ! -f "${DICT}" ] && DICT="/fuzzer/isobmff.dict"
DASHBOARD_API="${DASHBOARD_API:-http://localhost:56789}"
CONTROLLER_URL="${CONTROLLER_URL:-}"
WORKER_NAME="${WORKER_NAME:-worker}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-0}"
TIMEOUT_MS="${AFL_TIMEOUT:-5000}"
AFL_SYNC_DIR="${AFL_SYNC_DIR:-${RESULTS}/afl_sync}"

# Default cores: all available
N_CORES="${AFL_CORES:-$(nproc 2>/dev/null || echo 1)}"
unset AFL_CORES

mkdir -p "${AFL_SYNC_DIR}" "${RESULTS}/runs" "${RESULTS}/crashes"
[ ! -x "${HARNESS}" ] && echo "[!] Harness not found: ${HARNESS}" && exit 1

RUN_ID=$(date +%Y%m%d_%H%M%S)_$(head -c4 /dev/urandom | xxd -p)
RUN_DIR="${RESULTS}/runs/${RUN_ID}"
mkdir -p "${RUN_DIR}"

echo "[+] Worker run ${RUN_ID} | name=${WORKER_NAME} cores=${N_CORES} controller=${CONTROLLER_URL:-none}"
START_TS=$(date +%s)

# Report to local dashboard
curl -sf -X POST "${DASHBOARD_API}/api/runs" \
  -H "Content-Type: application/json" \
  -d "{\"run_id\":\"${RUN_ID}\",\"status\":\"running\",\"started_at\":${START_TS}}" \
  2>/dev/null || true

# ── System settings ────────────────────────────────────────────────────────────
echo core > /proc/sys/kernel/core_pattern 2>/dev/null || true
echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true

# ── Seed pre-screening ────────────────────────────────────────────────────────
SEEDS_OK="/results/seeds_ok"
ACTIVE_SEEDS="${SEEDS}"

if [ ! -d "${SEEDS_OK}" ] || [ "$(ls "${SEEDS_OK}" 2>/dev/null | wc -l)" -lt 3 ]; then
    mkdir -p "${SEEDS_OK}"
    REPLAY="/fuzzer/fuzz_isobmff_replay"
    [ -x "${REPLAY}" ] || REPLAY="${HARNESS}"
    echo "[*] Pre-screening seeds..."
    SLOW=0; FAST=0
    for f in "${SEEDS}"/*; do
        [ -f "$f" ] || continue
        result=0
        ASAN_OPTIONS="abort_on_error=0:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
        timeout 1.2s "${REPLAY}" "$f" >/dev/null 2>&1 || result=$?
        if [ "$result" -eq 124 ]; then SLOW=$((SLOW+1))
        else cp "$f" "${SEEDS_OK}/$(basename "$f")"; FAST=$((FAST+1)); fi
    done
    echo "[*] Seed screen: ${FAST} kept, ${SLOW} slow"
fi
ACTIVE_SEEDS="${SEEDS_OK}"

# ── Dict flag ─────────────────────────────────────────────────────────────────
DICT_FLAG=""; [ -f "${DICT}" ] && DICT_FLAG="-x ${DICT}"

# ── Custom mutator ────────────────────────────────────────────────────────────
MUTATOR_SO="${MUTATOR_SO:-/results/isobmff_mutator.so}"
[ -f "$MUTATOR_SO" ] || MUTATOR_SO="/fuzzer/isobmff_mutator.so"
[ -f "${MUTATOR_SO}" ] && export AFL_CUSTOM_MUTATOR_LIBRARY="${MUTATOR_SO}"

export AFL_IMPORT_FIRST=1

# ── Start sync agent (background) ─────────────────────────────────────────────
SYNC_PID=""
if [ -n "${CONTROLLER_URL}" ] && [ -f "/scripts/sync_agent.py" ]; then
    echo "[*] Starting sync agent → ${CONTROLLER_URL}"
    CONTROLLER_URL="${CONTROLLER_URL}" \
    WORKER_NAME="${WORKER_NAME}" \
    AFL_SYNC_DIR="${AFL_SYNC_DIR}" \
    DASHBOARD_PASSWORD="${DASHBOARD_PASSWORD:-helloworld}" \
    SYNC_INTERVAL="${SYNC_INTERVAL:-30}" \
    python3 /scripts/sync_agent.py >> "${RUN_DIR}/sync_agent.log" 2>&1 &
    SYNC_PID=$!
    echo "[*] Sync agent PID=${SYNC_PID}"
    # Wait for first sync to populate main/queue before starting AFL
    sleep 15
else
    echo "[!] No CONTROLLER_URL set — running without corpus sync"
fi

# ── Launch worker AFL++ instances ─────────────────────────────────────────────
INSTANCE_PIDS=()
for i in $(seq 1 "${N_CORES}"); do
    INST_NAME="${WORKER_NAME}_${i}"
    echo "[*] Launching AFL++ instance: -S ${INST_NAME}"
    TIME_FLAG=""
    [ "${MAX_TOTAL_TIME:-0}" -gt 0 ] && TIME_FLAG="-V ${MAX_TOTAL_TIME}"

    AFL_IGNORE_SEED_PROBLEMS=1 \
    AFL_AUTORESUME=1 \
    AFL_IMPORT_FIRST=1 \
    AFL_MAP_SIZE=262144 \
    ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
    UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
    afl-fuzz \
      -S "${INST_NAME}" \
      -i "${ACTIVE_SEEDS}" \
      -o "${AFL_SYNC_DIR}" \
      ${TIME_FLAG} \
      -t "${TIMEOUT_MS}" \
      ${DICT_FLAG} \
      -- "${HARNESS}" \
      >> "${RUN_DIR}/fuzzer_${INST_NAME}.log" 2>&1 &
    INSTANCE_PIDS+=($!)
done

echo "[*] All ${N_CORES} worker instances launched"

# ── Live stats reporter ───────────────────────────────────────────────────────
(
    while sleep 15; do
        # Check if any instance is still alive
        ALIVE=0
        for pid in "${INSTANCE_PIDS[@]}"; do
            kill -0 "$pid" 2>/dev/null && ALIVE=1 && break
        done
        [ "$ALIVE" -eq 0 ] && break

        python3 - "${RUN_ID}" "${START_TS}" "${N_CORES}" "${AFL_SYNC_DIR}" "${WORKER_NAME}" <<'PYEOF'
import sys, json, time
from pathlib import Path

run_id, start_ts, n_cores = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sync_dir = Path(sys.argv[4])
worker_name = sys.argv[5]

instances = []
total_edges = 0
total_execs = 0
total_speed = 0.0

if sync_dir.is_dir():
    for d in sync_dir.iterdir():
        if not d.is_dir() or not d.name.startswith(worker_name):
            continue
        fs = d / "fuzzer_stats"
        if not fs.exists():
            continue
        kv = {}
        for line in fs.read_text().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                kv[k.strip()] = v.strip()
        e = int(kv.get("edges_found", 0))
        spd = float(kv.get("execs_per_sec", 0))
        total_edges = max(total_edges, e)
        total_execs += int(kv.get("execs_done", 0))
        total_speed += spd
        instances.append({"name": d.name, "edges": e, "speed": spd})

live = {
    "run_id":        run_id,
    "elapsed_sec":   int(time.time()) - start_ts,
    "edges_found":   total_edges,
    "execs_done":    total_execs,
    "execs_per_sec": total_speed,
    "instances":     len(instances),
    "instance_list": instances,
    "updated_at":    int(time.time()),
    "mode":          "worker",
    "worker_name":   worker_name,
}
json.dump(live, open("/results/live_stats.json", "w"), indent=2)
PYEOF
    done
) &
LIVE_PID=$!

# Wait for first instance to finish (or all to finish)
wait "${INSTANCE_PIDS[0]}" || true
# Give rest a moment to finish naturally
sleep 5
for pid in "${INSTANCE_PIDS[@]:1}"; do kill "$pid" 2>/dev/null || true; done

# Stop sync agent
[ -n "${SYNC_PID}" ] && kill "${SYNC_PID}" 2>/dev/null || true
kill "$LIVE_PID" 2>/dev/null || true

END_TS=$(date +%s)
DURATION=$(( END_TS - START_TS ))

# Gather stats from all worker instances
TOTAL_CRASHES=0
MAX_EDGES=0
TOTAL_SPEED=0
for i in $(seq 1 "${N_CORES}"); do
    STATS_FILE="${AFL_SYNC_DIR}/${WORKER_NAME}_${i}/fuzzer_stats"
    [ -f "${STATS_FILE}" ] || continue
    EDGES=$(grep -oP "^edges_found\s*:\s*\K[0-9]+" "${STATS_FILE}" 2>/dev/null | head -1 || echo 0)
    CRASHES=$(grep -oP "^saved_crashes\s*:\s*\K[0-9]+" "${STATS_FILE}" 2>/dev/null | head -1 || echo 0)
    SPEED=$(grep -oP "^execs_per_sec\s*:\s*\K[0-9.]+" "${STATS_FILE}" 2>/dev/null | head -1 || echo 0)
    [ "${EDGES:-0}" -gt "${MAX_EDGES}" ] 2>/dev/null && MAX_EDGES="${EDGES:-0}"
    TOTAL_CRASHES=$(( TOTAL_CRASHES + ${CRASHES:-0} ))
    TOTAL_SPEED=$(python3 -c "print(${TOTAL_SPEED} + ${SPEED:-0})" 2>/dev/null || echo "${TOTAL_SPEED}")
done
AVG_SPEED=$(python3 -c "print(int(${TOTAL_SPEED}))" 2>/dev/null || echo "0")
SCORE=$(python3 -c "print(${MAX_EDGES}*5 + ${TOTAL_CRASHES}*200 + ${AVG_SPEED}//10)" 2>/dev/null || echo "0")

cat > "${RUN_DIR}/meta.json" <<METAEOF
{
  "run_id": "${RUN_ID}",
  "engine": "afl++ distributed worker",
  "status": "done",
  "started_at": ${START_TS},
  "ended_at": ${END_TS},
  "duration_sec": ${DURATION},
  "crashes": ${TOTAL_CRASHES},
  "cov_edges": ${MAX_EDGES},
  "execs_per_sec": ${AVG_SPEED},
  "score": ${SCORE},
  "afl_out": "${AFL_SYNC_DIR}",
  "mode": "worker",
  "worker_name": "${WORKER_NAME}",
  "exit_code": 0
}
METAEOF

curl -sf -X PATCH "${DASHBOARD_API}/api/runs/${RUN_ID}" \
  -H "Content-Type: application/json" \
  -d @"${RUN_DIR}/meta.json" \
  2>/dev/null || true

rm -f /results/live_stats.json
echo "[+] Done: ${RUN_ID} | edges=${MAX_EDGES} crashes=${TOTAL_CRASHES} speed=${AVG_SPEED}/s"
