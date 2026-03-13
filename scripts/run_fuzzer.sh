#!/usr/bin/env bash
# run_fuzzer.sh — single libFuzzer run with clean corpus isolation
set -euo pipefail

RESULTS="/results"
SEEDS="/fuzzer/corpus"        # read-only seed corpus (never written by fuzzer)
HARNESS="/fuzzer/fuzz_isobmff"
DASHBOARD_API="${DASHBOARD_API:-http://localhost:56789}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-300}"
MAX_LEN="${MAX_LEN:-65536}"

mkdir -p "${RESULTS}/runs" "${RESULTS}/crashes" "${RESULTS}/coverage"

# ── Verify harness ─────────────────────────────────────────────────────────────
if [ ! -x "${HARNESS}" ]; then
    echo "[!] Harness not found: ${HARNESS}"
    exit 1
fi

# ── Run ID ─────────────────────────────────────────────────────────────────────
RUN_ID=$(date +%Y%m%d_%H%M%S)_$(head -c4 /dev/urandom | xxd -p)
RUN_DIR="${RESULTS}/runs/${RUN_ID}"
WORK_CORPUS="/tmp/corpus_${RUN_ID}"   # per-run corpus (isolated from seeds)
mkdir -p "${RUN_DIR}" "${WORK_CORPUS}"

# Copy seeds into work corpus so fuzzer can grow from them
cp "${SEEDS}"/*.mp4 "${WORK_CORPUS}/" 2>/dev/null || true
cp "${SEEDS}"/*.mov "${WORK_CORPUS}/" 2>/dev/null || true

echo "[+] Run ${RUN_ID} starting (max=${MAX_TOTAL_TIME}s)"

START_TS=$(date +%s)

# Register with dashboard
curl -sf -X POST "${DASHBOARD_API}/api/runs" \
  -H "Content-Type: application/json" \
  -d "{\"run_id\":\"${RUN_ID}\",\"status\":\"running\",\"started_at\":${START_TS}}" \
  2>/dev/null || true

# ── Fuzzer run ─────────────────────────────────────────────────────────────────
export LLVM_PROFILE_FILE="/tmp/fuzz_${RUN_ID}_%p.profraw"

UBSAN_OPTIONS="halt_on_error=0:abort_on_error=0:print_stacktrace=1" \
"${HARNESS}" \
    "${WORK_CORPUS}" \
    -artifact_prefix="${RESULTS}/crashes/${RUN_ID}_" \
    -max_total_time="${MAX_TOTAL_TIME}" \
    -max_len="${MAX_LEN}" \
    -rss_limit_mb=512 \
    -detect_leaks=0 \
    -print_final_stats=1 \
    2>&1 | tee "${RUN_DIR}/fuzzer.log" || true

END_TS=$(date +%s)
DURATION=$(( END_TS - START_TS ))

# ── Extract stats ──────────────────────────────────────────────────────────────
COV=$(grep -oP 'cov: \K[0-9]+' "${RUN_DIR}/fuzzer.log" 2>/dev/null | tail -1 || echo "0")
SPEED=$(grep -oP 'exec/s: \K[0-9]+' "${RUN_DIR}/fuzzer.log" 2>/dev/null | tail -1 || echo "0")
# Count only real crashes (not OOM — those are documented separately)
CRASHES=$(find "${RESULTS}/crashes" -maxdepth 1 -name "${RUN_ID}_*" ! -name "*.json" ! -name "*oom*" 2>/dev/null | wc -l)
# Remove OOM artifacts (we don't track them)
find "${RESULTS}/crashes" -maxdepth 1 -name "${RUN_ID}_*oom*" -delete 2>/dev/null || true
NEW_UNITS=$(grep -oP 'new_units_added: \K[0-9]+' "${RUN_DIR}/fuzzer.log" 2>/dev/null | tail -1 || echo "0")
EXECS=$(grep -oP 'number_of_executed_units: \K[0-9]+' "${RUN_DIR}/fuzzer.log" 2>/dev/null | tail -1 || echo "0")

# Sanitize to plain integers
COV=$(echo "$COV" | tr -dc '0-9'); COV=${COV:-0}
SPEED=$(echo "$SPEED" | tr -dc '0-9'); SPEED=${SPEED:-0}
CRASHES=$(echo "$CRASHES" | tr -dc '0-9'); CRASHES=${CRASHES:-0}
NEW_UNITS=$(echo "$NEW_UNITS" | tr -dc '0-9'); NEW_UNITS=${NEW_UNITS:-0}

# ── Coverage ───────────────────────────────────────────────────────────────────
/scripts/collect_coverage.sh "${RUN_ID}" || true
COV_LINES=$(cat "${RESULTS}/coverage/${RUN_ID}_lines.txt" 2>/dev/null | tr -dc '0-9.'; echo)
COV_LINES=${COV_LINES:-0}
COV_FUNCS=$(cat "${RESULTS}/coverage/${RUN_ID}_funcs.txt" 2>/dev/null | tr -dc '0-9.'; echo)
COV_FUNCS=${COV_FUNCS:-0}

# ── Score ──────────────────────────────────────────────────────────────────────
# score = (edges × 5) + (unique_crashes × 200) + (new_units × 20) + (speed ÷ 10)
SCORE=$(python3 -c "print(${COV}*5 + ${CRASHES}*200 + ${NEW_UNITS}*20 + ${SPEED}//10)" 2>/dev/null || echo "0")

echo "[+] ${RUN_ID}: duration=${DURATION}s edges=${COV} crashes=${CRASHES} new=${NEW_UNITS} speed=${SPEED}/s score=${SCORE}"

# ── Save metadata ──────────────────────────────────────────────────────────────
cat > "${RUN_DIR}/meta.json" <<METAEOF
{
  "run_id": "${RUN_ID}",
  "status": "done",
  "started_at": ${START_TS},
  "ended_at": ${END_TS},
  "duration_sec": ${DURATION},
  "crashes": ${CRASHES},
  "cov_edges": ${COV},
  "cov_lines_pct": ${COV_LINES:-0},
  "cov_funcs_pct": ${COV_FUNCS:-0},
  "execs_per_sec": ${SPEED},
  "score": ${SCORE},
  "exit_code": 0
}
METAEOF

# ── Analyze crashes ────────────────────────────────────────────────────────────
[ "${CRASHES}" -gt 0 ] && /scripts/analyze_crashes.sh "${RUN_ID}" || true

# ── Merge new corpus entries (only if run ended cleanly — no crashes) ──────────
MERGED=0
if [ "${CRASHES}" -eq 0 ]; then
    for f in "${WORK_CORPUS}"/*; do
        [ -f "$f" ] || continue
        fname=$(basename "$f")
        [ -f "${SEEDS}/${fname}" ] && continue
        [[ "$fname" == slow-* || "$fname" == timeout-* || "$fname" == oom-* || "$fname" == crash-* ]] && continue
        # Validate: only merge files that don't cause OOM/crash themselves
        if ASAN_OPTIONS="halt_on_error=0:abort_on_error=0:allocator_may_return_null=1:detect_leaks=0" \
           timeout 3s "${HARNESS}" -runs=1 "$f" >/dev/null 2>&1; then
            cp "$f" "${SEEDS}/${fname}" && MERGED=$((MERGED+1))
        fi
    done
    [ "$MERGED" -gt 0 ] && echo "[+] Merged ${MERGED} validated corpus entries"
else
    echo "[~] Skipping corpus merge (run had ${CRASHES} crash(es))"
fi

# ── Report to dashboard ────────────────────────────────────────────────────────
curl -sf -X PATCH "${DASHBOARD_API}/api/runs/${RUN_ID}" \
  -H "Content-Type: application/json" \
  -d @"${RUN_DIR}/meta.json" \
  2>/dev/null || true

# ── Cleanup ────────────────────────────────────────────────────────────────────
rm -rf "${WORK_CORPUS}"

echo "[+] Done: ${RUN_ID}"
