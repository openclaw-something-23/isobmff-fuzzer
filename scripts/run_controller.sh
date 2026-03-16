#!/usr/bin/env bash
# run_controller.sh — AFL++ CONTROLLER mode
#
# Differences from run_fuzzer.sh:
#   1. Uses STABLE /results/afl_sync/ output dir (not per-run)
#      → AFL++ from both local instances AND remote workers all sync through here
#   2. Worker queue dirs (afl_sync/worker_*/queue/) are picked up automatically
#      by AFL++ since they're siblings in the same sync directory
#   3. Runs continuously without resetting the sync dir (afl++ resumes naturally)
#   4. Writes live stats from main/fuzzer_stats every 15s
#   5. Still creates per-run metadata in /results/runs/ for dashboard history
#
# AFL++ distributed sync model:
#   afl_sync/
#     main/         ← main controller instance (-M main)
#     s1/           ← local secondary (-S s1)
#     s2/           ← local secondary (-S s2)
#     worker_ph_1/  ← created by remote worker (powerhorse), synced in by sync_agent
#     worker_ph_2/  ← created by remote worker (powerhorse), synced in by sync_agent
#
# AFL++ reads ALL sibling queue/ directories → cross-machine corpus sharing!

set -euo pipefail

RESULTS="/results"
SEEDS="${SEEDS:-/fuzzer/corpus}"
HARNESS="/fuzzer/fuzz_isobmff_afl"
[ -x "/results/fuzz_isobmff_afl_new" ] && HARNESS="/results/fuzz_isobmff_afl_new"
CMPLOG_BIN="${CMPLOG_BIN:-/fuzzer/fuzz_isobmff_cmplog}"
MUTATOR_SO="${MUTATOR_SO:-/results/isobmff_mutator.so}"
[ -f "$MUTATOR_SO" ] || MUTATOR_SO="/fuzzer/isobmff_mutator.so"
DICT="${RESULTS}/isobmff.dict"
[ ! -f "${DICT}" ] && DICT="/fuzzer/isobmff.dict"
DASHBOARD_API="${DASHBOARD_API:-http://localhost:56789}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-0}"        # 0 = run forever (restart on crash only)
TIMEOUT_MS="${AFL_TIMEOUT:-5000}"
N_CORES="${AFL_CORES:-1}"
unset AFL_CORES

# STABLE sync directory — does NOT change between runs
AFL_SYNC_DIR="${AFL_SYNC_DIR:-${RESULTS}/afl_sync}"
mkdir -p "${AFL_SYNC_DIR}"

# ── Power schedule rotation ────────────────────────────────────────────────────
SCHEDULES=("fast" "explore" "exploit" "mmopt" "rare" "coe" "lin" "quad")
SCHEDULE_IDX_FILE="/results/.schedule_idx"
SCHED_IDX=$(cat "${SCHEDULE_IDX_FILE}" 2>/dev/null || echo "0")
SCHED_IDX=$(( SCHED_IDX % ${#SCHEDULES[@]} ))
POWER_SCHEDULE="${SCHEDULES[$SCHED_IDX]}"
echo $(( (SCHED_IDX + 1) % ${#SCHEDULES[@]} )) > "${SCHEDULE_IDX_FILE}"

mkdir -p "${RESULTS}/runs" "${RESULTS}/crashes" "${RESULTS}/coverage" "${RESULTS}/quarantine"
[ ! -x "${HARNESS}" ] && echo "[!] Harness not found: ${HARNESS}" && exit 1

RUN_ID=$(date +%Y%m%d_%H%M%S)_$(head -c4 /dev/urandom | xxd -p)
RUN_DIR="${RESULTS}/runs/${RUN_ID}"
mkdir -p "${RUN_DIR}"

echo "[+] Controller run ${RUN_ID} | cores=${N_CORES} timeout=${TIMEOUT_MS}ms schedule=${POWER_SCHEDULE}"
echo "[+] AFL sync dir: ${AFL_SYNC_DIR}"
START_TS=$(date +%s)

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
    SLOW=0; FAST=0
    REPLAY="/fuzzer/fuzz_isobmff_replay"
    [ -x "${REPLAY}" ] || REPLAY="${HARNESS}"
    echo "[*] Pre-screening seeds..."
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

# ── Dict / cmplog / mutator flags ─────────────────────────────────────────────
DICT_FLAG=""; [ -f "${DICT}" ] && DICT_FLAG="-x ${DICT}"
CMPLOG_FLAG=""; [ -x "${CMPLOG_BIN}" ] && CMPLOG_FLAG="-c ${CMPLOG_BIN}"
[ -f "${MUTATOR_SO}" ] && export AFL_CUSTOM_MUTATOR_LIBRARY="${MUTATOR_SO}"

# ── AFL+ flags for distributed mode ──────────────────────────────────────────
# AFL_IMPORT_FIRST: import from sibling dirs (worker_* dirs) before each cycle
export AFL_IMPORT_FIRST=1
# Keep running even if no new paths: we have remote workers adding corpus
export AFL_BENCH_UNTIL_CRASH="${AFL_BENCH_UNTIL_CRASH:-0}"

# ── Launch main instance ───────────────────────────────────────────────────────
# Use AFL_AUTORESUME: resumes from existing queue if afl_sync/main/ already exists
AFL_IGNORE_SEED_PROBLEMS=1 \
AFL_MAP_SIZE=262144 \
AFL_AUTORESUME=1 \
ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
afl-fuzz \
  -M main \
  -i "${ACTIVE_SEEDS}" \
  -o "${AFL_SYNC_DIR}" \
  ${MAX_TOTAL_TIME:+-V "${MAX_TOTAL_TIME}"} \
  -t "${TIMEOUT_MS}" \
  -p "${POWER_SCHEDULE}" \
  ${DICT_FLAG} \
  ${CMPLOG_FLAG} \
  -- "${HARNESS}" \
  2>&1 | tee "${RUN_DIR}/fuzzer.log" &
MAIN_PID=$!
echo "[*] Main instance PID=${MAIN_PID}"

# ── Launch local secondaries ──────────────────────────────────────────────────
SECONDARY_PIDS=()
if [ "${N_CORES}" -gt 1 ]; then
    sleep 10   # wait for main to finish dry-run
    for i in $(seq 1 $(( N_CORES - 1 ))); do
        AFL_IGNORE_SEED_PROBLEMS=1 \
        AFL_AUTORESUME=1 \
        AFL_IMPORT_FIRST=1 \
        ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
        UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
        afl-fuzz \
          -S "s${i}" \
          -i "${ACTIVE_SEEDS}" \
          -o "${AFL_SYNC_DIR}" \
          ${MAX_TOTAL_TIME:+-V "${MAX_TOTAL_TIME}"} \
          -t "${TIMEOUT_MS}" \
          ${DICT_FLAG} \
          -- "${HARNESS}" \
          >> "${RUN_DIR}/fuzzer_s${i}.log" 2>&1 &
        SECONDARY_PIDS+=($!)
        echo "[*] Secondary s${i} PID=${SECONDARY_PIDS[-1]}"
    done
fi

# ── Live stats reporter ───────────────────────────────────────────────────────
STATS_FILE="${AFL_SYNC_DIR}/main/fuzzer_stats"
(
    while kill -0 $MAIN_PID 2>/dev/null; do
        sleep 15
        if [ -f "${STATS_FILE}" ]; then
            python3 - "${STATS_FILE}" "${RUN_ID}" "${START_TS}" "${N_CORES}" "${AFL_SYNC_DIR}" <<'PYEOF'
import sys, json, time, re, os
from pathlib import Path

stats_file, run_id, start_ts = sys.argv[1], sys.argv[2], int(sys.argv[3])
n_cores = int(sys.argv[4]) if len(sys.argv) > 4 else 1
sync_dir = Path(sys.argv[5]) if len(sys.argv) > 5 else Path("/results/afl_sync")

def parse(f):
    d = {}
    try:
        for line in open(f):
            m = re.match(r'^(\w+)\s*:\s*(.+)', line.strip())
            if m: d[m.group(1)] = m.group(2).strip().rstrip('%')
    except: pass
    return d

s = parse(stats_file)

# Count active instances (both local + worker dirs)
instances = 0
worker_instances = 0
if sync_dir.is_dir():
    for d in sync_dir.iterdir():
        if d.is_dir() and (d / "fuzzer_stats").exists():
            instances += 1
            if d.name not in ("main",) and not (d.name.startswith("s") and d.name[1:].isdigit()):
                worker_instances += 1

live = {
    "run_id":           run_id,
    "elapsed_sec":      int(time.time()) - start_ts,
    "edges_found":      int(s.get("edges_found", 0)),
    "bitmap_cvg":       float(s.get("bitmap_cvg", 0)),
    "execs_per_sec":    float(s.get("execs_per_sec", 0)),
    "corpus_count":     int(s.get("corpus_count", 0)),
    "corpus_found":     int(s.get("corpus_found", 0)),
    "saved_crashes":    int(s.get("saved_crashes", 0)),
    "cycles_done":      int(s.get("cycles_done", 0)),
    "execs_done":       int(s.get("execs_done", 0)),
    "pending_favs":     int(s.get("pending_favs", 0)),
    "instances":        max(instances, n_cores),
    "worker_instances": worker_instances,
    "updated_at":       int(time.time()),
    "mode":             "controller",
}
json.dump(live, open("/results/live_stats.json", "w"), indent=2)
PYEOF
        fi
    done
) &
LIVE_PID=$!

wait $MAIN_PID || true
for pid in "${SECONDARY_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
kill "$LIVE_PID" 2>/dev/null || true

END_TS=$(date +%s)
DURATION=$(( END_TS - START_TS ))

# ── Parse final stats ──────────────────────────────────────────────────────────
parse_stat() {
    local key="$1" default="${2:-0}"
    [ -f "${STATS_FILE}" ] && \
        grep -oP "^${key}\s*:\s*\K[0-9.+e]+" "${STATS_FILE}" 2>/dev/null | head -1 || echo "${default}"
}

COV=$(parse_stat "edges_found" 0)
BITMAP_CVG=$(parse_stat "bitmap_cvg" "0.0")
SPEED_RAW=$(parse_stat "execs_per_sec" 0)
CRASHES=$(parse_stat "saved_crashes" 0)
NEW_UNITS=$(parse_stat "corpus_found" 0)
SPEED=$(python3 -c "import sys; print(int(float('${SPEED_RAW}') + 0.5))" 2>/dev/null || echo "0")
COV=$(echo "$COV" | tr -dc '0-9'); COV=${COV:-0}
CRASHES=$(echo "$CRASHES" | tr -dc '0-9'); CRASHES=${CRASHES:-0}
NEW_UNITS=$(echo "$NEW_UNITS" | tr -dc '0-9'); NEW_UNITS=${NEW_UNITS:-0}
SPEED=$(echo "$SPEED" | tr -dc '0-9'); SPEED=${SPEED:-0}

# Copy crashes
COPIED_CRASHES=0
CRASH_SRC="${AFL_SYNC_DIR}/main/crashes"
if [ -d "${CRASH_SRC}" ]; then
    for f in "${CRASH_SRC}"/id:*; do
        [ -f "$f" ] || continue
        cp "$f" "${RESULTS}/crashes/${RUN_ID}_$(basename "$f")"
        COPIED_CRASHES=$((COPIED_CRASHES+1))
    done
fi

/scripts/collect_coverage.sh "${RUN_ID}" "${AFL_SYNC_DIR}" "${BITMAP_CVG}" "${COV}" 2>/dev/null || true
COV_LINES=$(cat "${RESULTS}/coverage/${RUN_ID}_lines.txt" 2>/dev/null | tr -dc '0-9.'; echo)
COV_LINES=${COV_LINES:-0}

SCORE=$(python3 -c "print(${COV}*5 + ${CRASHES}*200 + ${NEW_UNITS}*20 + ${SPEED}//10)" 2>/dev/null || echo "0")

cat > "${RUN_DIR}/meta.json" <<METAEOF
{
  "run_id": "${RUN_ID}",
  "engine": "afl++ distributed controller",
  "status": "done",
  "started_at": ${START_TS},
  "ended_at": ${END_TS},
  "duration_sec": ${DURATION},
  "crashes": ${CRASHES},
  "cov_edges": ${COV},
  "cov_bitmap_pct": "${BITMAP_CVG}",
  "cov_lines_pct": ${COV_LINES:-0},
  "execs_per_sec": ${SPEED},
  "corpus_found": ${NEW_UNITS},
  "score": ${SCORE},
  "afl_out": "${AFL_SYNC_DIR}",
  "power_schedule": "${POWER_SCHEDULE}",
  "exit_code": 0,
  "mode": "controller"
}
METAEOF

[ "${COPIED_CRASHES}" -gt 0 ] && /scripts/analyze_crashes.sh "${RUN_ID}" || true

curl -sf -X PATCH "${DASHBOARD_API}/api/runs/${RUN_ID}" \
  -H "Content-Type: application/json" \
  -d @"${RUN_DIR}/meta.json" \
  2>/dev/null || true

rm -f /results/live_stats.json
echo "[+] Done: ${RUN_ID} | edges=${COV} crashes=${CRASHES} score=${SCORE}"
