#!/usr/bin/env bash
# analyze_crashes.sh <run_id>
# Deduplicates AFL++ crashes by stack hash, assigns severity scores.
#
# AFL++ crash file naming: id:000000,sig:11,src:000001,time:1234,...
# We run the standalone replay binary (ASAN-instrumented) to get stack traces.
set -euo pipefail

RUN_ID="${1:-unknown}"
CRASHES_DIR="/results/crashes"
# Prefer standalone replay binary (no fuzzer overhead, just ASAN+UBSAN)
REPLAY_BIN="/fuzzer/fuzz_isobmff_replay"
# Fall back to AFL++ binary itself
AFL_BIN="/fuzzer/fuzz_isobmff_afl"
DASHBOARD_API="${DASHBOARD_API:-http://localhost:56789}"

# Pick the best available binary for crash replay
if [ -x "${REPLAY_BIN}" ]; then
    CRASH_BIN="${REPLAY_BIN}"
elif [ -x "${AFL_BIN}" ]; then
    CRASH_BIN="${AFL_BIN}"
else
    echo "[!] No replay binary found. Build with: make afl standalone"
    exit 0
fi

# Find crash files for this run (copied by run_fuzzer.sh with RUN_ID prefix)
mapfile -t CRASH_FILES < <(ls "${CRASHES_DIR}/${RUN_ID}_"* 2>/dev/null | grep -v '\.json$' || true)

if [ ${#CRASH_FILES[@]} -eq 0 ]; then
    echo "[*] No crashes to analyze for ${RUN_ID}"
    exit 0
fi

echo "[*] Analyzing ${#CRASH_FILES[@]} crash(es) for run ${RUN_ID} using ${CRASH_BIN}..."

for CRASH_FILE in "${CRASH_FILES[@]}"; do
    [ -f "${CRASH_FILE}" ] || continue

    CRASH_NAME=$(basename "${CRASH_FILE}")
    CRASH_SIZE=$(wc -c < "${CRASH_FILE}")

    # Run crash input under ASAN to get the stack trace
    TRACE=$(
        ASAN_OPTIONS="halt_on_error=1:detect_leaks=0:print_stacktrace=1:fast_unwind_on_malloc=0" \
        UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
        timeout 15s "${CRASH_BIN}" "${CRASH_FILE}" 2>&1 || true
    )

    # Extract signal from AFL++ filename (sig:NN)
    AFL_SIG=$(echo "${CRASH_NAME}" | grep -oP 'sig:\K[0-9]+' || echo "0")

    # Determine crash type from ASAN output
    if echo "${TRACE}" | grep -q "heap-buffer-overflow"; then
        CRASH_TYPE="heap-buffer-overflow"
        SEVERITY=90
    elif echo "${TRACE}" | grep -q "stack-buffer-overflow"; then
        CRASH_TYPE="stack-buffer-overflow"
        SEVERITY=95
    elif echo "${TRACE}" | grep -q "use-after-free"; then
        CRASH_TYPE="use-after-free"
        SEVERITY=85
    elif echo "${TRACE}" | grep -q "heap-use-after-free"; then
        CRASH_TYPE="use-after-free"
        SEVERITY=85
    elif echo "${TRACE}" | grep -q "double-free"; then
        CRASH_TYPE="double-free"
        SEVERITY=80
    elif echo "${TRACE}" | grep -qiE "SEGV|segfault|signal 11|sig:11"; then
        CRASH_TYPE="segfault"
        SEVERITY=70
    elif echo "${TRACE}" | grep -q "undefined"; then
        CRASH_TYPE="undefined-behavior"
        SEVERITY=50
    elif echo "${TRACE}" | grep -qE "FPE|divide|signal 8|sig:8"; then
        CRASH_TYPE="division-by-zero"
        SEVERITY=60
    elif echo "${TRACE}" | grep -qE "signal 6|sig:6|abort|ABORT"; then
        CRASH_TYPE="abort"
        SEVERITY=65
    else
        CRASH_TYPE="unknown-sig${AFL_SIG}"
        SEVERITY=30
    fi

    # Deduplication: hash the top 3 unique stack frames
    STACK_HASH=$(echo "${TRACE}" \
        | grep -oP '#[0-9]+ 0x[0-9a-f]+ in \S+' \
        | head -3 \
        | md5sum \
        | cut -c1-8)

    # Extract AFL++ src input (which corpus entry triggered this crash)
    SRC_ID=$(echo "${CRASH_NAME}" | grep -oP 'src:\K[0-9,+]+' || echo "unknown")

    # Save crash metadata
    CRASH_META="${CRASHES_DIR}/${CRASH_NAME}.json"
    cat > "${CRASH_META}" <<EOF
{
  "run_id": "${RUN_ID}",
  "engine": "afl++",
  "crash_file": "${CRASH_NAME}",
  "crash_type": "${CRASH_TYPE}",
  "severity": ${SEVERITY},
  "stack_hash": "${STACK_HASH}",
  "input_size": ${CRASH_SIZE},
  "afl_signal": "${AFL_SIG}",
  "afl_src": "${SRC_ID}",
  "trace_preview": $(echo "${TRACE}" | head -20 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
}
EOF

    echo "[+] ${CRASH_NAME}: type=${CRASH_TYPE} severity=${SEVERITY} hash=${STACK_HASH} sig=${AFL_SIG}"

    # Report to dashboard
    curl -sf -X POST "${DASHBOARD_API}/api/crashes" \
      -H "Content-Type: application/json" \
      -d @"${CRASH_META}" \
      2>/dev/null || true
done

echo "[+] Crash analysis done for ${RUN_ID}"
