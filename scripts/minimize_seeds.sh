#!/usr/bin/env bash
# minimize_seeds.sh — Run afl-tmin on all seeds_ok to shrink them.
# Smaller seeds = faster fuzzing (AFL++ executes more per second).
# Usage: ./minimize_seeds.sh [seeds_dir] [timeout_ms]
set -euo pipefail

SEEDS_OK="${1:-/results/seeds_ok}"
TIMEOUT_MS="${2:-5000}"
HARNESS="/fuzzer/fuzz_isobmff_afl"
ASAN_OPTS="abort_on_error=0:detect_leaks=0:allocator_may_return_null=1:symbolize=0"

echo "[*] Minimizing seeds in ${SEEDS_OK} (timeout=${TIMEOUT_MS}ms)"
TOTAL=0; SHRUNK=0; SAVED=0; FAILED=0
START=$(date +%s)

for f in "${SEEDS_OK}"/*; do
    [ -f "$f" ] || continue
    TOTAL=$((TOTAL+1))
    orig_size=$(wc -c < "$f")
    [ "$orig_size" -lt 8 ] && continue   # skip already-tiny

    tmp_out="${f}.min_tmp"
    ASAN_OPTIONS="$ASAN_OPTS" \
    timeout 30s afl-tmin \
        -i "$f" \
        -o "$tmp_out" \
        -t "${TIMEOUT_MS}" \
        -- "${HARNESS}" >/dev/null 2>&1 && result=0 || result=$?

    if [ "$result" -eq 0 ] && [ -f "$tmp_out" ]; then
        new_size=$(wc -c < "$tmp_out")
        if [ "$new_size" -lt "$orig_size" ] && [ "$new_size" -ge 8 ]; then
            pct=$(( (orig_size - new_size) * 100 / orig_size ))
            echo "  [+] $(basename $f): ${orig_size}B → ${new_size}B (-${pct}%)"
            mv "$tmp_out" "$f"
            SHRUNK=$((SHRUNK+1))
            SAVED=$((SAVED + orig_size - new_size))
        else
            rm -f "$tmp_out"
        fi
    else
        rm -f "$tmp_out" 2>/dev/null || true
        [ "$result" -ne 124 ] && FAILED=$((FAILED+1))
    fi
done

END=$(date +%s)
echo "[+] Done in $((END-START))s: ${TOTAL} processed, ${SHRUNK} shrunk, ${FAILED} failed"
echo "[+] Total bytes saved: ${SAVED}B"
