#!/usr/bin/env bash
# collect_coverage.sh <run_id>
# Merges LLVM profraw files and extracts coverage percentages
set -euo pipefail

RUN_ID="${1:-unknown}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
RESULTS="${ROOT}/results"
COV_DIR="${RESULTS}/coverage"
HARNESS="${ROOT}/fuzzer/fuzz_isobmff"
ISOBMFF_SRC="/opt/ISOBMFF/ISOBMFF/source"

mkdir -p "${COV_DIR}"

PROFRAW_FILES=(/tmp/fuzz_${RUN_ID}_*.profraw)

if [ ! -e "${PROFRAW_FILES[0]}" ]; then
    echo "0" > "${COV_DIR}/${RUN_ID}_lines.txt"
    echo "0" > "${COV_DIR}/${RUN_ID}_funcs.txt"
    echo "[!] No profraw files for ${RUN_ID}"
    exit 0
fi

PROFDATA="/tmp/fuzz_${RUN_ID}_merged.profdata"

echo "[*] Merging ${#PROFRAW_FILES[@]} profraw files..."
llvm-profdata merge -sparse "${PROFRAW_FILES[@]}" -o "${PROFDATA}"

# Generate text report
REPORT="${COV_DIR}/${RUN_ID}_report.txt"
llvm-cov report "${HARNESS}" \
  -instr-profile="${PROFDATA}" \
  "${ISOBMFF_SRC}"/*.cpp \
  > "${REPORT}" 2>/dev/null || true

# Extract line and function coverage percentages
LINES_PCT=$(grep -oP 'Lines.*?\K[0-9]+\.[0-9]+%' "${REPORT}" | tail -1 | tr -d '%' || echo "0")
FUNCS_PCT=$(grep -oP 'Functions.*?\K[0-9]+\.[0-9]+%' "${REPORT}" | tail -1 | tr -d '%' || echo "0")

echo "${LINES_PCT}" > "${COV_DIR}/${RUN_ID}_lines.txt"
echo "${FUNCS_PCT}"  > "${COV_DIR}/${RUN_ID}_funcs.txt"

# Generate HTML coverage report
llvm-cov show "${HARNESS}" \
  -instr-profile="${PROFDATA}" \
  -format=html \
  "${ISOBMFF_SRC}"/*.cpp \
  > "${COV_DIR}/${RUN_ID}_coverage.html" 2>/dev/null || true

# Generate JSON summary for dashboard
python3 - <<PYEOF
import re, json

report = open("${REPORT}").read() if open.__module__ else ""
try:
    lines = float("${LINES_PCT}") if "${LINES_PCT}" else 0.0
    funcs = float("${FUNCS_PCT}") if "${FUNCS_PCT}" else 0.0
except:
    lines, funcs = 0.0, 0.0

summary = {
    "run_id": "${RUN_ID}",
    "lines_pct": lines,
    "funcs_pct": funcs,
    "html_report": "${RUN_ID}_coverage.html"
}
with open("${COV_DIR}/${RUN_ID}_summary.json", "w") as f:
    json.dump(summary, f)
PYEOF

# Cleanup profraw
rm -f "${PROFRAW_FILES[@]}" "${PROFDATA}"

echo "[+] Coverage: lines=${LINES_PCT}% funcs=${FUNCS_PCT}%"
