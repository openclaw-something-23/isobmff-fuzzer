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

# ── Optional: generate LLVM HTML coverage if libFuzzer build exists ───────────
# This runs the AFL++ corpus through a separately-built libFuzzer harness.
LIBFUZZER_BIN="/fuzzer/fuzz_isobmff"
if [ -x "${LIBFUZZER_BIN}" ] && [ -d "${AFL_OUT}/main/queue" ]; then
    echo "[*] Generating LLVM HTML coverage from AFL++ queue..."
    PROFRAW="/tmp/fuzz_${RUN_ID}_%p.profraw"
    export LLVM_PROFILE_FILE="${PROFRAW}"
    ASAN_OPTIONS="halt_on_error=0:abort_on_error=0:detect_leaks=0:allocator_may_return_null=1" \
    "${LIBFUZZER_BIN}" "${AFL_OUT}/main/queue/" -runs=0 >/dev/null 2>&1 || true

    PROFRAW_FILES=(/tmp/fuzz_${RUN_ID}_*.profraw)
    if [ -e "${PROFRAW_FILES[0]}" ]; then
        PROFDATA="/tmp/fuzz_${RUN_ID}_merged.profdata"
        llvm-profdata merge -sparse "${PROFRAW_FILES[@]}" -o "${PROFDATA}" 2>/dev/null || true
        ISOBMFF_SRC="/opt/ISOBMFF/ISOBMFF/source"
        llvm-cov show "${LIBFUZZER_BIN}" \
          -instr-profile="${PROFDATA}" \
          -format=html \
          "${ISOBMFF_SRC}"/*.cpp \
          > "${COV_DIR}/${RUN_ID}_coverage.html" 2>/dev/null || true
        rm -f "${PROFRAW_FILES[@]}" "${PROFDATA}" 2>/dev/null || true
        echo "[+] LLVM HTML coverage: ${COV_DIR}/${RUN_ID}_coverage.html"
    fi
fi
