#!/usr/bin/env bash
# run_fuzzer.sh — AFL++ run with:
#   1. Seed pre-screening (removes slow inputs before AFL++ dry-run aborts)
#   2. ISOBMFF dictionary (-x isobmff.dict)
#   3. Multi-instance support (AFL_CORES > 1: main + secondaries in parallel)
#   4. Generous timeout (-t 5000ms) for ISOBMFF file I/O
#   5. Live stats written to /results/live_stats.json during fuzz loop
set -euo pipefail

RESULTS="/results"
SEEDS="${SEEDS:-/fuzzer/corpus}"
HARNESS="/fuzzer/fuzz_isobmff_afl"
# Improvement 8: use new harness from /results if available (hot-swap without rebuild)
[ -x "/results/fuzz_isobmff_afl_new" ] && HARNESS="/results/fuzz_isobmff_afl_new"
CMPLOG_BIN="${CMPLOG_BIN:-/fuzzer/fuzz_isobmff_cmplog}"
# Improvement 2: use new mutator from /results if available
MUTATOR_SO="${MUTATOR_SO:-/results/isobmff_mutator.so}"
[ -f "$MUTATOR_SO" ] || MUTATOR_SO="/fuzzer/isobmff_mutator.so"
DICT="${RESULTS}/isobmff.dict"
[ ! -f "${DICT}" ] && DICT="/fuzzer/isobmff.dict"
DASHBOARD_API="${DASHBOARD_API:-http://localhost:56789}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-3600}"
TIMEOUT_MS="${AFL_TIMEOUT:-5000}"
N_CORES="${AFL_CORES:-1}"
unset AFL_CORES

# Improvement 8: Extended power schedule rotation including COE and LIN
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
AFL_OUT="${RESULTS}/afl_out/${RUN_ID}"
MAIN_DIR="${AFL_OUT}/main"
mkdir -p "${RUN_DIR}" "${AFL_OUT}"

echo "[+] Run ${RUN_ID} starting (max=${MAX_TOTAL_TIME}s cores=${N_CORES} timeout=${TIMEOUT_MS}ms schedule=${POWER_SCHEDULE})"
START_TS=$(date +%s)

curl -sf -X POST "${DASHBOARD_API}/api/runs" \
  -H "Content-Type: application/json" \
  -d "{\"run_id\":\"${RUN_ID}\",\"status\":\"running\",\"started_at\":${START_TS}}" \
  2>/dev/null || true

# ── System settings ────────────────────────────────────────────────────────────
echo core > /proc/sys/kernel/core_pattern 2>/dev/null || true
echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true

# ── Improvement 1: Seed pre-screening ─────────────────────────────────────────
# AFL++ aborts entirely if any seed exceeds the exec timeout during dry-run.
# We pre-screen seeds once (cached in /results/seeds_ok/) using the standalone
# replay binary with a 1.2s cutoff (safely under AFL++ default 1000ms * 1.5x).
SEEDS_OK="/results/seeds_ok"
ACTIVE_SEEDS="${SEEDS}"

if [ ! -d "${SEEDS_OK}" ] || [ "$(ls "${SEEDS_OK}" 2>/dev/null | wc -l)" -lt 3 ]; then
    mkdir -p "${SEEDS_OK}"
    SLOW=0; FAST=0
    # Prefer standalone replay binary (no AFL++ shm overhead)
    REPLAY="/fuzzer/fuzz_isobmff_replay"
    [ -x "${REPLAY}" ] || REPLAY="${HARNESS}"
    echo "[*] Pre-screening seeds (limit: 1.2s each)..."
    for f in "${SEEDS}"/*; do
        [ -f "$f" ] || continue
        result=0
        ASAN_OPTIONS="abort_on_error=0:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
        timeout 1.2s "${REPLAY}" "$f" >/dev/null 2>&1 || result=$?
        if [ "$result" -eq 124 ]; then
            SLOW=$((SLOW+1))
        else
            cp "$f" "${SEEDS_OK}/$(basename "$f")"
            FAST=$((FAST+1))
        fi
    done
    echo "[*] Seed screen: ${FAST} kept, ${SLOW} slow/removed"
fi
ACTIVE_SEEDS="${SEEDS_OK}"

# ── Improvement 4: Slow seed quarantine ───────────────────────────────────────
# Move seeds that took >timeout in previous runs to quarantine.
# AFL++ writes timeouts to <afl_out>/main/hangs/ — we pick those up.
QUARANTINE="${RESULTS}/quarantine"
QUARANTINE_COUNT=0
for prev_afl_out in "${RESULTS}/afl_out"/*/main/hangs; do
    [ -d "$prev_afl_out" ] || continue
    for f in "${prev_afl_out}"/id:*; do
        [ -f "$f" ] || continue
        fname=$(basename "$f")
        # Find the original seed this hang was derived from
        orig_name=$(echo "$fname" | grep -oP "orig:\K[^,]+" || true)
        if [ -n "$orig_name" ] && [ -f "${SEEDS_OK}/${orig_name}" ]; then
            mv "${SEEDS_OK}/${orig_name}" "${QUARANTINE}/${orig_name}" 2>/dev/null && \
            QUARANTINE_COUNT=$((QUARANTINE_COUNT+1)) || true
        fi
    done
done
[ "$QUARANTINE_COUNT" -gt 0 ] && echo "[*] Quarantined ${QUARANTINE_COUNT} slow seed(s)"

# ── Dictionary ────────────────────────────────────────────────────────────────
DICT_FLAG=""
[ -f "${DICT}" ] && DICT_FLAG="-x ${DICT}" && echo "[*] Dict: ${DICT}"

# ── Custom mutator ────────────────────────────────────────────────────────────
MUTATOR_FLAG=""
if [ -f "${MUTATOR_SO}" ]; then
    export AFL_CUSTOM_MUTATOR_LIBRARY="${MUTATOR_SO}"
    echo "[*] Custom mutator: ${MUTATOR_SO}"
fi

# ── CMPLOG flag ───────────────────────────────────────────────────────────────
CMPLOG_FLAG=""
[ -x "${CMPLOG_BIN}" ] && CMPLOG_FLAG="-c ${CMPLOG_BIN}" && \
    echo "[*] CMPLOG: ${CMPLOG_BIN}"

# ── Multi-instance launch ─────────────────────────────────────────────────────
SECONDARY_PIDS=()

# Improvement 10: AFL_MAP_SIZE=262144 for more precise edge tracking (was 65536)
AFL_IGNORE_SEED_PROBLEMS=1 \
AFL_MAP_SIZE=262144 \
AFL_DISABLE_TRIM=0 \
ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
afl-fuzz \
  -M main \
  -i "${ACTIVE_SEEDS}" \
  -o "${AFL_OUT}" \
  -V "${MAX_TOTAL_TIME}" \
  -t "${TIMEOUT_MS}" \
  -p "${POWER_SCHEDULE}" \
  ${DICT_FLAG} \
  ${CMPLOG_FLAG} \
  -- "${HARNESS}" \
  2>&1 | tee "${RUN_DIR}/fuzzer.log" &
MAIN_PID=$!
echo "[*] Main instance PID=${MAIN_PID}"

# Give main 10s to complete dry-run and create the queue before secondaries join
if [ "${N_CORES}" -gt 1 ]; then
    sleep 10
    for i in $(seq 1 $(( N_CORES - 1 ))); do
        AFL_IGNORE_SEED_PROBLEMS=1 \
        ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
        UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
        afl-fuzz \
          -S "s${i}" \
          -i "${ACTIVE_SEEDS}" \
          -o "${AFL_OUT}" \
          -V "${MAX_TOTAL_TIME}" \
          -t "${TIMEOUT_MS}" \
          ${DICT_FLAG} \
          -- "${HARNESS}" \
          >> "${RUN_DIR}/fuzzer_s${i}.log" 2>&1 &
        SECONDARY_PIDS+=($!)
        echo "[*] Secondary s${i} PID=${SECONDARY_PIDS[-1]}"
    done
fi

# ── Improvement 5: Live stats background reporter ──────────────────────────────
# Every 15s, read fuzzer_stats and write /results/live_stats.json so the
# dashboard can poll a /api/live endpoint without waiting for run completion.
STATS_FILE="${MAIN_DIR}/fuzzer_stats"
(
    while kill -0 $MAIN_PID 2>/dev/null; do
        sleep 15
        if [ -f "${STATS_FILE}" ]; then
            python3 - "${STATS_FILE}" "${RUN_ID}" "${START_TS}" "${N_CORES}" <<'PYEOF'
import sys, json, time, re

stats_file, run_id, start_ts = sys.argv[1], sys.argv[2], int(sys.argv[3])

def parse(f):
    d = {}
    try:
        for line in open(f):
            m = re.match(r'^(\w+)\s*:\s*(.+)', line.strip())
            if m: d[m.group(1)] = m.group(2).strip().rstrip('%')
    except: pass
    return d

s = parse(stats_file)
live = {
    "run_id":        run_id,
    "elapsed_sec":   int(time.time()) - start_ts,
    "edges_found":   int(s.get("edges_found", 0)),
    "bitmap_cvg":    float(s.get("bitmap_cvg", 0)),
    "execs_per_sec": float(s.get("execs_per_sec", 0)),
    "corpus_count":  int(s.get("corpus_count", 0)),
    "corpus_found":  int(s.get("corpus_found", 0)),
    "saved_crashes": int(s.get("saved_crashes", 0)),
    "cycles_done":   int(s.get("cycles_done", 0)),
    "execs_done":    int(s.get("execs_done", 0)),
    "pending_favs":  int(s.get("pending_favs", 0)),
    "instances":     int(sys.argv[4]) if len(sys.argv) > 4 else 1,
    "updated_at":    int(time.time()),
}
json.dump(live, open("/results/live_stats.json", "w"), indent=2)
PYEOF
        fi
    done
) &
LIVE_PID=$!

# Wait for main to finish
wait $MAIN_PID || true

# Kill secondaries and live reporter
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

echo "[+] AFL++ stats: edges=${COV} bitmap=${BITMAP_CVG}% crashes=${CRASHES} new=${NEW_UNITS} speed=${SPEED}/s"

# ── Copy crashes ───────────────────────────────────────────────────────────────
COPIED_CRASHES=0
CRASH_SRC="${MAIN_DIR}/crashes"
if [ -d "${CRASH_SRC}" ]; then
    for f in "${CRASH_SRC}"/id:*; do
        [ -f "$f" ] || continue
        cp "$f" "${RESULTS}/crashes/${RUN_ID}_$(basename "$f")"
        COPIED_CRASHES=$((COPIED_CRASHES+1))
    done
fi

# ── Coverage ───────────────────────────────────────────────────────────────────
/scripts/collect_coverage.sh "${RUN_ID}" "${AFL_OUT}" "${BITMAP_CVG}" "${COV}" || true
COV_LINES=$(cat "${RESULTS}/coverage/${RUN_ID}_lines.txt" 2>/dev/null | tr -dc '0-9.'; echo)
COV_LINES=${COV_LINES:-0}

# ── Score ──────────────────────────────────────────────────────────────────────
SCORE=$(python3 -c "print(${COV}*5 + ${CRASHES}*200 + ${NEW_UNITS}*20 + ${SPEED}//10)" 2>/dev/null || echo "0")

echo "[+] ${RUN_ID}: duration=${DURATION}s edges=${COV} crashes=${CRASHES} new=${NEW_UNITS} speed=${SPEED}/s score=${SCORE}"

# ── Save metadata ──────────────────────────────────────────────────────────────
cat > "${RUN_DIR}/meta.json" <<METAEOF
{
  "run_id": "${RUN_ID}",
  "engine": "afl++",
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
  "afl_out": "${AFL_OUT}",
  "power_schedule": "${POWER_SCHEDULE}",
  "exit_code": 0
}
METAEOF

[ "${COPIED_CRASHES}" -gt 0 ] && /scripts/analyze_crashes.sh "${RUN_ID}" || true

# ── Improvement 4: afl-tmin — auto-minimize crashes ──────────────────────────
# Finds the smallest input that still triggers the same crash.
# Makes triage much easier: typical 32KB crash → 8-64 bytes.
MINIMIZED_CRASHES=0
if [ "${COPIED_CRASHES}" -gt 0 ]; then
    for crash_file in "${RESULTS}/crashes/${RUN_ID}_id:"*; do
        [ -f "$crash_file" ] || continue
        min_out="${crash_file%.mp4}_min.mp4"
        [ -f "$min_out" ] && continue  # already minimized
        echo "[*] afl-tmin: minimizing $(basename $crash_file)..."
        ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
        timeout 60s afl-tmin \
            -i "$crash_file" \
            -o "$min_out" \
            -t "${TIMEOUT_MS}" \
            -- "${HARNESS}" >/dev/null 2>&1 && \
        echo "[+] Minimized: $(wc -c < "$crash_file")B → $(wc -c < "$min_out")B" && \
        MINIMIZED_CRASHES=$((MINIMIZED_CRASHES+1)) || true
    done
    [ "$MINIMIZED_CRASHES" -gt 0 ] && echo "[+] Minimized ${MINIMIZED_CRASHES} crash(es)"
fi

# ── Improvement 5: Continuous corpus growth (every 3rd run only) ──────────────
# afl-cmin is expensive (~90s) — run it every 3 runs, not every run.
RUN_COUNT=$(ls "${RESULTS}/runs/" 2>/dev/null | wc -l)
if [ $(( RUN_COUNT % 3 )) -eq 0 ] && [ -d "${MAIN_DIR}/queue" ]; then
    NEW_QUEUE_COUNT=$(ls "${MAIN_DIR}/queue" | grep -v '^\.' | wc -l)
    if [ "$NEW_QUEUE_COUNT" -gt 10 ]; then
        echo "[*] Corpus growth pass (run #${RUN_COUNT}): merging ${NEW_QUEUE_COUNT} queue entries..."
        CMIN_OUT="/tmp/cmin_${RUN_ID}"
        mkdir -p "${CMIN_OUT}"
        AFL_IGNORE_SEED_PROBLEMS=1 \
        ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
        timeout 120s afl-cmin \
            -i "${MAIN_DIR}/queue" \
            -o "${CMIN_OUT}" \
            -t "${TIMEOUT_MS}" \
            -- "${HARNESS}" >/dev/null 2>&1 || true
        MERGED=0
        for f in "${CMIN_OUT}"/*; do
            [ -f "$f" ] || continue
            sz=$(wc -c < "$f")
            [ "$sz" -lt 8 ] && continue
            [ "$sz" -gt 65536 ] && continue
            fname="queue_${RUN_ID}_$(basename $f)"
            [ -f "${SEEDS_OK}/${fname}" ] && continue
            cp "$f" "${SEEDS_OK}/${fname}" && MERGED=$((MERGED+1))
        done
        rm -rf "${CMIN_OUT}"
        [ "$MERGED" -gt 0 ] && echo "[+] Seeds_ok grew by ${MERGED} (now $(ls ${SEEDS_OK} | wc -l) total)"
    fi
fi

# ── Report to dashboard ────────────────────────────────────────────────────────
curl -sf -X PATCH "${DASHBOARD_API}/api/runs/${RUN_ID}" \
  -H "Content-Type: application/json" \
  -d @"${RUN_DIR}/meta.json" \
  2>/dev/null || true

# Cleanup live stats (run is done)
rm -f /results/live_stats.json

echo "[+] Done: ${RUN_ID}"
