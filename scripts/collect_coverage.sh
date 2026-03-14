#!/usr/bin/env bash
# collect_coverage.sh <run_id> [afl_out_dir] [bitmap_cvg] [edges_found]
#
# AFL++ native coverage: parses fuzzer_stats directly.
# No LLVM profraw needed — AFL++ tracks edge coverage in its bitmap.
#
# Outputs:
#   /results/coverage/<run_id>_lines.txt   — bitmap_cvg percentage (best proxy)
#   /results/coverage/<run_id>_funcs.txt   — edges_found count
#   /results/coverage/<run_id>_summary.json
set -euo pipefail

RUN_ID="${1:-unknown}"
AFL_OUT="${2:-}"
BITMAP_CVG="${3:-0.0}"
EDGES="${4:-0}"
RESULTS="/results"
COV_DIR="${RESULTS}/coverage"
mkdir -p "${COV_DIR}"

# ── Primary: parse fuzzer_stats from AFL++ output directory ───────────────────
STATS_FILE="${AFL_OUT}/main/fuzzer_stats"

if [ -f "${STATS_FILE}" ]; then
    echo "[*] Parsing AFL++ fuzzer_stats for run ${RUN_ID}..."

    # Re-read from file in case args were stale (e.g., called post-run)
    parse_stat() {
        local key="$1"
        local default="${2:-0}"
        grep -oP "^${key}\s*:\s*\K[0-9.+e-]+" "${STATS_FILE}" 2>/dev/null | head -1 || echo "${default}"
    }

    BITMAP_CVG=$(parse_stat "bitmap_cvg" "${BITMAP_CVG}")
    BITMAP_CVG=$(echo "${BITMAP_CVG}" | tr -d '%')  # strip trailing % if present
    EDGES=$(parse_stat "edges_found" "${EDGES}")
    EXECS=$(parse_stat "execs_done" 0)
    SPEED=$(parse_stat "execs_per_sec" 0)
    STABILITY=$(parse_stat "stability" "0.0")
    STABILITY=$(echo "${STABILITY}" | tr -d '%')
    CORPUS=$(parse_stat "corpus_count" 0)
    CYCLES=$(parse_stat "cycles_done" 0)

    echo "[+] bitmap_cvg=${BITMAP_CVG}% edges=${EDGES} execs=${EXECS} stability=${STABILITY}%"
else
    echo "[!] No fuzzer_stats found at ${STATS_FILE}, using passed arguments"
    EDGES="${4:-0}"
    EXECS="0"
    SPEED="0"
    STABILITY="0.0"
    CORPUS="0"
    CYCLES="0"
fi

# Sanitize bitmap_cvg (may be "2.34" or "2.34%")
BITMAP_CVG=$(echo "${BITMAP_CVG}" | python3 -c "
import sys
s = sys.stdin.read().strip().rstrip('%')
try:
    print(round(float(s), 2))
except:
    print(0.0)
" 2>/dev/null || echo "0.0")

# We use bitmap_cvg as the "lines" percentage (best AFL++ coverage metric)
# and edges_found as the "funcs" count (absolute, not percentage)
echo "${BITMAP_CVG}" > "${COV_DIR}/${RUN_ID}_lines.txt"
echo "${EDGES}"       > "${COV_DIR}/${RUN_ID}_funcs.txt"

# ── JSON summary ───────────────────────────────────────────────────────────────
cat > "${COV_DIR}/${RUN_ID}_summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "engine": "afl++",
  "bitmap_cvg_pct": ${BITMAP_CVG},
  "edges_found": ${EDGES},
  "execs_done": ${EXECS},
  "execs_per_sec": ${SPEED},
  "stability_pct": ${STABILITY},
  "corpus_count": ${CORPUS},
  "cycles_done": ${CYCLES},
  "lines_pct": ${BITMAP_CVG},
  "funcs_pct": 0.0
}
EOF

echo "[+] Coverage summary: bitmap=${BITMAP_CVG}% edges=${EDGES}"

# ── Improvement 5: Source-level coverage with llvm-cov ────────────────────────
# Runs AFL++ corpus through the libFuzzer-instrumented build to get real
# line/branch/function coverage %. Produces HTML + JSON summary with exact %.
LIBFUZZER_BIN="/fuzzer/fuzz_isobmff"
ISOBMFF_SRC="/opt/ISOBMFF/ISOBMFF/source"
QUEUE_DIR="${AFL_OUT}/main/queue"

if [ -x "${LIBFUZZER_BIN}" ] && [ -d "${QUEUE_DIR}" ]; then
    QUEUE_COUNT=$(ls "${QUEUE_DIR}" | grep -c "^id:" 2>/dev/null || echo 0)
    echo "[*] Running ${QUEUE_COUNT} corpus files through libFuzzer for LLVM coverage..."

    PROFRAW="/tmp/fuzz_${RUN_ID}_%p.profraw"
    PROFDATA="/tmp/fuzz_${RUN_ID}.profdata"
    export LLVM_PROFILE_FILE="${PROFRAW}"

    ASAN_OPTIONS="halt_on_error=0:abort_on_error=0:detect_leaks=0:allocator_may_return_null=1" \
    "${LIBFUZZER_BIN}" "${QUEUE_DIR}" -runs=0 >/dev/null 2>&1 || true

    PROFRAW_FILES=(/tmp/fuzz_${RUN_ID}_*.profraw)
    if [ -e "${PROFRAW_FILES[0]:-}" ]; then
        llvm-profdata merge -sparse "${PROFRAW_FILES[@]}" -o "${PROFDATA}" 2>/dev/null || true

        if [ -f "${PROFDATA}" ]; then
            # ── HTML report (line-by-line source view) ────────────────────────
            llvm-cov show "${LIBFUZZER_BIN}" \
              -instr-profile="${PROFDATA}" \
              -format=html \
              -show-line-counts-or-regions \
              "${ISOBMFF_SRC}"/*.cpp \
              > "${COV_DIR}/${RUN_ID}_coverage.html" 2>/dev/null || true

            # ── Text summary: extract line/branch/function % ──────────────────
            SUMMARY=$(llvm-cov report "${LIBFUZZER_BIN}" \
              -instr-profile="${PROFDATA}" \
              "${ISOBMFF_SRC}"/*.cpp 2>/dev/null | tail -2 || true)

            # Parse TOTAL line: "TOTAL  N  N  LL%  N  N  BB%  N  N  FF%"
            LINE_PCT=$(echo "${SUMMARY}" | awk '/TOTAL/{print $4}' | tr -d '%')
            BRANCH_PCT=$(echo "${SUMMARY}" | awk '/TOTAL/{print $7}' | tr -d '%')
            FUNC_PCT=$(echo "${SUMMARY}" | awk '/TOTAL/{print $10}' | tr -d '%')
            LINE_PCT=${LINE_PCT:-0}; BRANCH_PCT=${BRANCH_PCT:-0}; FUNC_PCT=${FUNC_PCT:-0}

            echo "[+] Source coverage: lines=${LINE_PCT}% branches=${BRANCH_PCT}% functions=${FUNC_PCT}%"

            # Write source-level metrics (overwrite AFL++ bitmap metrics)
            echo "${LINE_PCT}"   > "${COV_DIR}/${RUN_ID}_lines.txt"
            echo "${FUNC_PCT}"   > "${COV_DIR}/${RUN_ID}_funcs.txt"

            # Enrich summary JSON with source-level data
            python3 - <<PYEOF 2>/dev/null || true
import json, os
sf = "${COV_DIR}/${RUN_ID}_summary.json"
d = json.load(open(sf)) if os.path.isfile(sf) else {}
d.update({
    "lines_pct":    float("${LINE_PCT}" or 0),
    "branch_pct":   float("${BRANCH_PCT}" or 0),
    "funcs_pct":    float("${FUNC_PCT}" or 0),
    "html_report":  "${RUN_ID}_coverage.html",
})
json.dump(d, open(sf, "w"), indent=2)
PYEOF
        fi
        rm -f "${PROFRAW_FILES[@]}" "${PROFDATA}" 2>/dev/null || true
        echo "[+] LLVM HTML coverage: ${COV_DIR}/${RUN_ID}_coverage.html"
    else
        echo "[~] No profraw files generated (libFuzzer build may be incomplete)"
    fi
else
    echo "[~] libFuzzer build not found at ${LIBFUZZER_BIN}, skipping source coverage"
fi
