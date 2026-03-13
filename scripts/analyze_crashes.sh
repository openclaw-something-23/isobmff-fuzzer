#!/usr/bin/env bash
# analyze_crashes.sh <run_id>
# Deduplicates crashes by stack hash, assigns severity scores
set -euo pipefail

RUN_ID="${1:-unknown}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
CRASHES_DIR="${ROOT}/results/crashes"
HARNESS="${ROOT}/fuzzer/fuzz_isobmff"
DASHBOARD_API="${DASHBOARD_API:-http://localhost:56789}"

mapfile -t CRASH_FILES < <(ls "${CRASHES_DIR}/${RUN_ID}_"* 2>/dev/null | grep -v '\.json$' || true)

if [ ${#CRASH_FILES[@]} -eq 0 ]; then
    echo "[*] No crashes to analyze for ${RUN_ID}"
    exit 0
fi

echo "[*] Analyzing ${#CRASH_FILES[@]} crash(es) for run ${RUN_ID}..."

for CRASH_FILE in "${CRASH_FILES[@]}"; do
    [ -f "${CRASH_FILE}" ] || continue

    CRASH_NAME=$(basename "${CRASH_FILE}")
    CRASH_SIZE=$(wc -c < "${CRASH_FILE}")

    # Run under ASAN to get stack trace
    TRACE=$(timeout 10s "${HARNESS}" "${CRASH_FILE}" 2>&1 || true)

    # Extract crash type
    if echo "${TRACE}" | grep -q "heap-buffer-overflow"; then
        CRASH_TYPE="heap-buffer-overflow"
        SEVERITY=90
    elif echo "${TRACE}" | grep -q "stack-buffer-overflow"; then
        CRASH_TYPE="stack-buffer-overflow"
        SEVERITY=95
    elif echo "${TRACE}" | grep -q "use-after-free"; then
        CRASH_TYPE="use-after-free"
        SEVERITY=85
    elif echo "${TRACE}" | grep -q "SEGV"; then
        CRASH_TYPE="segfault"
        SEVERITY=70
    elif echo "${TRACE}" | grep -q "undefined"; then
        CRASH_TYPE="undefined-behavior"
        SEVERITY=50
    elif echo "${TRACE}" | grep -q "FPE\|divide"; then
        CRASH_TYPE="division-by-zero"
        SEVERITY=60
    else
        CRASH_TYPE="unknown"
        SEVERITY=30
    fi

    # Hash = md5 of first 3 unique stack frames (dedup key)
    STACK_HASH=$(echo "${TRACE}" | grep -oP '#[0-9]+ 0x[0-9a-f]+ in \S+' | head -3 | md5sum | cut -c1-8)

    # Save crash metadata
    CRASH_META="${CRASHES_DIR}/${CRASH_NAME}.json"
    cat > "${CRASH_META}" <<EOF
{
  "run_id": "${RUN_ID}",
  "crash_file": "${CRASH_NAME}",
  "crash_type": "${CRASH_TYPE}",
  "severity": ${SEVERITY},
  "stack_hash": "${STACK_HASH}",
  "input_size": ${CRASH_SIZE},
  "trace_preview": $(echo "${TRACE}" | head -20 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
}
EOF

    echo "[+] ${CRASH_NAME}: type=${CRASH_TYPE} severity=${SEVERITY} hash=${STACK_HASH}"

    # Report to dashboard
    curl -sf -X POST "${DASHBOARD_API}/api/crashes" \
      -H "Content-Type: application/json" \
      -d @"${CRASH_META}" \
      2>/dev/null || true
done

echo "[+] Crash analysis done for ${RUN_ID}"
