#!/usr/bin/env bash
# prescreen_seeds.sh <seeds_dir> <harness_binary> [max_ms]
# Removes any seed file that causes the harness to take longer than max_ms.
# AFL++ aborts if any initial seed exceeds the exec timeout — this prevents that.
set -euo pipefail

SEEDS_DIR="${1:-/seeds}"
HARNESS="${2:-/fuzzer/fuzz_isobmff_afl}"
MAX_MS="${3:-800}"   # 800ms = safely under AFL++ default 1000ms limit

removed=0
kept=0
total=$(ls "$SEEDS_DIR" | wc -l)

echo "[*] Pre-screening $total seeds (limit: ${MAX_MS}ms each)..."

for f in "$SEEDS_DIR"/*; do
    [ -f "$f" ] || continue
    fname=$(basename "$f")

    # Time the harness on this seed (standalone mode or via /usr/bin/time)
    elapsed_ms=$(
        TIMEFORMAT="%R"
        { time timeout 2s env \
            ASAN_OPTIONS="abort_on_error=0:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
            "$HARNESS" "$f" 2>/dev/null || true
        } 2>&1 | awk '{printf "%d\n", $1 * 1000}'
    )

    if [ "${elapsed_ms:-0}" -gt "$MAX_MS" ]; then
        echo "  [!] Slow seed (${elapsed_ms}ms > ${MAX_MS}ms): $fname — removing"
        rm -f "$f"
        removed=$((removed+1))
    else
        kept=$((kept+1))
    fi
done

echo "[+] Pre-screen done: ${kept} kept, ${removed} removed (${total} total)"
