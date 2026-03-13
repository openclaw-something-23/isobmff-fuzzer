#!/usr/bin/env bash
# run_fuzzer.sh — starts a libFuzzer run and records metadata to the DB
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
RESULTS="${ROOT}/results"
RUNS_DIR="${RESULTS}/runs"
CRASHES_DIR="${RESULTS}/crashes"
CORPUS_DIR="${ROOT}/fuzzer/corpus"
HARNESS="${ROOT}/fuzzer/fuzz_isobmff"
DASHBOARD_API="${DASHBOARD_API:-http://localhost:56789}"

mkdir -p "${RUNS_DIR}" "${CRASHES_DIR}"

# ── Generate run ID ────────────────────────────────────────────
RUN_ID=$(date +%Y%m%d_%H%M%S)_$(head -c4 /dev/urandom | xxd -p)
RUN_DIR="${RUNS_DIR}/${RUN_ID}"
mkdir -p "${RUN_DIR}"

echo "[+] Starting run: ${RUN_ID}"

# ── Fuzzer settings (tunable via env) ─────────────────────────
MAX_TOTAL_TIME=${MAX_TOTAL_TIME:-300}   # seconds per run (default 5 min)
MAX_LEN=${MAX_LEN:-65536}               # max input size
JOBS=${JOBS:-2}                          # parallel workers

# ── Start timestamp ────────────────────────────────────────────
START_TS=$(date +%s)

# Register run start with dashboard
curl -sf -X POST "${DASHBOARD_API}/api/runs" \
  -H "Content-Type: application/json" \
  -d "{\"run_id\":\"${RUN_ID}\",\"status\":\"running\",\"started_at\":${START_TS}}" \
  2>/dev/null || true

# ── Run libFuzzer ──────────────────────────────────────────────
LLVM_PROFILE_FILE="/tmp/fuzz_${RUN_ID}_%p.profraw"
export LLVM_PROFILE_FILE

set +e
"${HARNESS}" \
  "${CORPUS_DIR}" \
  -artifact_prefix="${CRASHES_DIR}/${RUN_ID}_" \
  -max_total_time="${MAX_TOTAL_TIME}" \
  -max_len="${MAX_LEN}" \
  -jobs="${JOBS}" \
  -workers="${JOBS}" \
  -print_final_stats=1 \
  2>&1 | tee "${RUN_DIR}/fuzzer.log"

EXIT_CODE=$?
set -e

END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))

# ── Parse stats from log ───────────────────────────────────────
EXECS=$(grep -oP 'cov: \K[0-9]+' "${RUN_DIR}/fuzzer.log" | tail -1 || echo 0)
COV=$(grep -oP 'cov: [0-9]+' "${RUN_DIR}/fuzzer.log" | tail -1 | grep -oP '[0-9]+' || echo 0)
CRASHES=$(ls "${CRASHES_DIR}/${RUN_ID}_"* 2>/dev/null | wc -l || echo 0)
EXECS_PER_SEC=$(grep -oP 'exec/s: \K[0-9]+' "${RUN_DIR}/fuzzer.log" | tail -1 || echo 0)

# ── Collect coverage ───────────────────────────────────────────
"${SCRIPT_DIR}/collect_coverage.sh" "${RUN_ID}" || true

COV_LINES=$(cat "${RESULTS}/coverage/${RUN_ID}_lines.txt" 2>/dev/null || echo "0")
COV_FUNCS=$(cat "${RESULTS}/coverage/${RUN_ID}_funcs.txt" 2>/dev/null || echo "0")

# ── Compute score ──────────────────────────────────────────────
# Score = (edges * 5) + (crashes * 200) + (execs_per_sec / 10)
SCORE=$(python3 -c "
edges = int('${COV}') if '${COV}'.isdigit() else 0
crashes = int('${CRASHES}')
speed = int('${EXECS_PER_SEC}') if '${EXECS_PER_SEC}'.isdigit() else 0
score = (edges * 5) + (crashes * 200) + (speed // 10)
print(score)
")

echo "[+] Run ${RUN_ID} complete | duration=${DURATION}s | crashes=${CRASHES} | cov_edges=${COV} | score=${SCORE}"

# ── Save run metadata ──────────────────────────────────────────
cat > "${RUN_DIR}/meta.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "status": "done",
  "started_at": ${START_TS},
  "ended_at": ${END_TS},
  "duration_sec": ${DURATION},
  "crashes": ${CRASHES},
  "cov_edges": ${COV},
  "cov_lines_pct": "${COV_LINES}",
  "cov_funcs_pct": "${COV_FUNCS}",
  "execs_per_sec": ${EXECS_PER_SEC:-0},
  "score": ${SCORE},
  "exit_code": ${EXIT_CODE}
}
EOF

# ── Analyze crashes ────────────────────────────────────────────
if [ "${CRASHES}" -gt 0 ]; then
    "${SCRIPT_DIR}/analyze_crashes.sh" "${RUN_ID}" || true
fi

# ── Report to dashboard ────────────────────────────────────────
curl -sf -X PATCH "${DASHBOARD_API}/api/runs/${RUN_ID}" \
  -H "Content-Type: application/json" \
  -d @"${RUN_DIR}/meta.json" \
  2>/dev/null || true

# ── Commit to git ──────────────────────────────────────────────
cd "${ROOT}"
git add results/runs/ results/crashes/ results/coverage/ 2>/dev/null || true
git commit -m "run: ${RUN_ID} | score=${SCORE} | crashes=${CRASHES} | cov=${COV}" \
  2>/dev/null || true

echo "[+] Done: ${RUN_ID}"
