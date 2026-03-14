#!/usr/bin/env bash
# run_fuzzer.sh — single AFL++ run with dashboard integration
# AFL++ stores output in: /results/afl_out/<RUN_ID>/main/
# Stats parsed from:      /results/afl_out/<RUN_ID>/main/fuzzer_stats
set -euo pipefail

RESULTS="/results"
SEEDS="/fuzzer/corpus"              # read-only seed corpus
HARNESS="/fuzzer/fuzz_isobmff_afl"
DASHBOARD_API="${DASHBOARD_API:-http://localhost:56789}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-300}"    # -V flag (seconds)
MAX_LEN="${MAX_LEN:-65536}"               # -g flag (max input length)
AFL_CORES="${AFL_CORES:-1}"               # number of parallel instances

mkdir -p "${RESULTS}/runs" "${RESULTS}/crashes" "${RESULTS}/coverage"

# ── Verify harness ─────────────────────────────────────────────────────────────
if [ ! -x "${HARNESS}" ]; then
    echo "[!] Harness not found: ${HARNESS}"
    echo "[!] Run: cd /fuzzer && make afl"
    exit 1
fi

# ── Run ID ─────────────────────────────────────────────────────────────────────
RUN_ID=$(date +%Y%m%d_%H%M%S)_$(head -c4 /dev/urandom | xxd -p)
RUN_DIR="${RESULTS}/runs/${RUN_ID}"
AFL_OUT="${RESULTS}/afl_out/${RUN_ID}"
MAIN_DIR="${AFL_OUT}/main"
mkdir -p "${RUN_DIR}" "${AFL_OUT}"

echo "[+] Run ${RUN_ID} starting (max=${MAX_TOTAL_TIME}s, cores=${AFL_CORES})"
START_TS=$(date +%s)

# Register with dashboard
curl -sf -X POST "${DASHBOARD_API}/api/runs" \
  -H "Content-Type: application/json" \
  -d "{\"run_id\":\"${RUN_ID}\",\"status\":\"running\",\"started_at\":${START_TS}}" \
  2>/dev/null || true

# ── AFL++ system settings ──────────────────────────────────────────────────────
# Disable CPU frequency scaling warning (best-effort)
echo core > /proc/sys/kernel/core_pattern 2>/dev/null || true
echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true

# ── Launch AFL++ ───────────────────────────────────────────────────────────────
# -M main  : primary instance (required when running >1 cores)
# -i       : seed corpus directory
# -o       : sync/output directory
# -V       : time limit in seconds (replaces libFuzzer's -max_total_time)
# -g       : max input length
# -x       : dictionary (if available)
# --        : separator before target binary

ASAN_OPTIONS="halt_on_error=0:abort_on_error=0:detect_leaks=0:allocator_may_return_null=1" \
UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
afl-fuzz \
  -M main \
  -i "${SEEDS}" \
  -o "${AFL_OUT}" \
  -V "${MAX_TOTAL_TIME}" \
  -g "${MAX_LEN}" \
  -- "${HARNESS}" \
  2>&1 | tee "${RUN_DIR}/fuzzer.log" || true

# ── Wait for secondary instances (if any) ─────────────────────────────────────
# Secondary instances (-S s1, -S s2, ...) can be launched separately via
# docker-compose scale. They share the same AFL_OUT directory and auto-stop
# when the main instance finishes.

END_TS=$(date +%s)
DURATION=$(( END_TS - START_TS ))

# ── Parse AFL++ stats from fuzzer_stats ───────────────────────────────────────
# fuzzer_stats uses key : value format, one per line.
STATS_FILE="${MAIN_DIR}/fuzzer_stats"

parse_stat() {
    local key="$1"
    local default="${2:-0}"
    if [ -f "${STATS_FILE}" ]; then
        grep -oP "^${key}\s*:\s*\K[0-9.+e]+" "${STATS_FILE}" 2>/dev/null | head -1 || echo "${default}"
    else
        echo "${default}"
    fi
}

COV=$(parse_stat "edges_found" 0)           # unique edge coverage
BITMAP_CVG=$(parse_stat "bitmap_cvg" "0.0") # percentage of bitmap hit
SPEED_RAW=$(parse_stat "execs_per_sec" 0)   # may be float like "1234.56"
CRASHES=$(parse_stat "saved_crashes" 0)
NEW_UNITS=$(parse_stat "corpus_found" 0)    # new corpus entries discovered
EXECS=$(parse_stat "execs_done" 0)

# Convert float speed to integer
SPEED=$(echo "${SPEED_RAW}" | python3 -c "import sys; print(int(float(sys.stdin.read().strip()) + 0.5))" 2>/dev/null || echo "0")

# Sanitize to plain integers
COV=$(echo "$COV" | tr -dc '0-9'); COV=${COV:-0}
CRASHES=$(echo "$CRASHES" | tr -dc '0-9'); CRASHES=${CRASHES:-0}
NEW_UNITS=$(echo "$NEW_UNITS" | tr -dc '0-9'); NEW_UNITS=${NEW_UNITS:-0}
SPEED=$(echo "$SPEED" | tr -dc '0-9'); SPEED=${SPEED:-0}

echo "[+] AFL++ stats: edges=${COV} bitmap=${BITMAP_CVG}% crashes=${CRASHES} new=${NEW_UNITS} speed=${SPEED}/s"

# ── Copy crashes to central directory ─────────────────────────────────────────
CRASH_SRC="${MAIN_DIR}/crashes"
COPIED_CRASHES=0
if [ -d "${CRASH_SRC}" ]; then
    for f in "${CRASH_SRC}"/id:*; do
        [ -f "$f" ] || continue
        fname=$(basename "$f")
        dest="${RESULTS}/crashes/${RUN_ID}_${fname}"
        cp "$f" "${dest}"
        COPIED_CRASHES=$((COPIED_CRASHES+1))
    done
fi

echo "[+] Copied ${COPIED_CRASHES} crash(es) to ${RESULTS}/crashes/"

# ── Coverage ───────────────────────────────────────────────────────────────────
/scripts/collect_coverage.sh "${RUN_ID}" "${AFL_OUT}" "${BITMAP_CVG}" "${COV}" || true
COV_LINES=$(cat "${RESULTS}/coverage/${RUN_ID}_lines.txt" 2>/dev/null | tr -dc '0-9.'; echo)
COV_LINES=${COV_LINES:-0}

# ── Score (same formula, AFL++ native metrics) ─────────────────────────────────
# score = (edges × 5) + (unique_crashes × 200) + (new_units × 20) + (speed ÷ 10)
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
  "exit_code": 0
}
METAEOF

# ── Analyze crashes ────────────────────────────────────────────────────────────
[ "${COPIED_CRASHES}" -gt 0 ] && /scripts/analyze_crashes.sh "${RUN_ID}" || true

# ── Corpus minimization + merge (afl-cmin) ─────────────────────────────────────
# Only merge if run ended cleanly (no crashes)
MERGED=0
if [ "${CRASHES}" -eq 0 ] && [ -d "${MAIN_DIR}/queue" ]; then
    CMIN_OUT="/tmp/cmin_${RUN_ID}"
    mkdir -p "${CMIN_OUT}"
    # afl-cmin deduplicates corpus by coverage; requires the harness binary
    afl-cmin \
      -i "${MAIN_DIR}/queue" \
      -o "${CMIN_OUT}" \
      -- "${HARNESS}" 2>/dev/null || true
    for f in "${CMIN_OUT}"/*; do
        [ -f "$f" ] || continue
        fname=$(basename "$f")
        [ -f "${SEEDS}/${fname}" ] && continue
        cp "$f" "${SEEDS}/${fname}" && MERGED=$((MERGED+1))
    done
    rm -rf "${CMIN_OUT}"
    [ "$MERGED" -gt 0 ] && echo "[+] Merged ${MERGED} minimized corpus entries"
else
    [ "${CRASHES}" -gt 0 ] && echo "[~] Skipping corpus merge (run had ${CRASHES} crash(es))"
fi

# ── Report to dashboard ────────────────────────────────────────────────────────
curl -sf -X PATCH "${DASHBOARD_API}/api/runs/${RUN_ID}" \
  -H "Content-Type: application/json" \
  -d @"${RUN_DIR}/meta.json" \
  2>/dev/null || true

# ── Optional: cleanup AFL++ output dir (large, gitignored) ─────────────────────
# Uncomment to save disk space (loses queue/crashes for post-analysis):
# rm -rf "${AFL_OUT}"

echo "[+] Done: ${RUN_ID}"
