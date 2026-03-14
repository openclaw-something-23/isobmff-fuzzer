#!/bin/bash
# generate_corpus.sh — Parallel mp4gen corpus generator for AFL++ fuzzing
#
# Runs continuously in the background alongside AFL++ fuzzing:
#   1. mp4gen generates 10000 diverse MP4 files into a tmpfs dir
#   2. afl-cmin minimizes to unique-coverage set
#   3. New files are merged into:
#      a. /results/seeds_ok  (for future AFL++ runs)
#      b. The live AFL++ queue (for the currently-running instance)
#   4. Repeat forever

set -uo pipefail

HARNESS="${HARNESS:-/fuzzer/fuzz_isobmff_afl}"
SEEDS_OK="${SEEDS_OK:-/results/seeds_ok}"
GEN_DIR="/tmp/mp4gen_out"
CMIN_DIR="/tmp/mp4gen_cmin"
BATCH_SIZE="${GEN_BATCH_SIZE:-10000}"
TIMEOUT_MS="${AFL_TIMEOUT:-5000}"
GEN_BIN="/fuzzer/mp4gen"

[ -x "$GEN_BIN" ] || { echo "[gen] mp4gen not found at $GEN_BIN, exiting"; exit 0; }
[ -x "$HARNESS" ] || { echo "[gen] harness not found at $HARNESS, exiting"; exit 0; }

mkdir -p "$SEEDS_OK" "$GEN_DIR" "$CMIN_DIR"

batch=0
total_merged=0

echo "[gen] Starting corpus generator (batch_size=${BATCH_SIZE})"

while true; do
    batch=$((batch + 1))
    echo "[gen] ── Batch #${batch} ─────────────────────────────────"

    # ── Step 1: Generate files ─────────────────────────────────────────────
    rm -f "$GEN_DIR"/*.mp4
    echo "[gen] Generating ${BATCH_SIZE} MP4 files..."

    # Run at lower CPU priority so AFL++ isn't starved
    nice -n 10 "$GEN_BIN" "$GEN_DIR" "$BATCH_SIZE" 2>/dev/null
    actual=$(ls "$GEN_DIR"/*.mp4 2>/dev/null | wc -l)
    echo "[gen] Generated: ${actual} files"

    if [ "$actual" -lt 50 ]; then
        echo "[gen] Too few files, sleeping 30s..."
        sleep 30
        continue
    fi

    # ── Step 2: afl-cmin — keep only unique-coverage files ────────────────
    rm -rf "$CMIN_DIR" && mkdir -p "$CMIN_DIR"
    echo "[gen] Running afl-cmin on ${actual} files..."

    AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=0" \
    timeout 300s afl-cmin \
        -i "$GEN_DIR" \
        -o "$CMIN_DIR" \
        -t "$TIMEOUT_MS" \
        -- "$HARNESS" >/dev/null 2>&1

    cmin_status=$?
    cmin_count=$(ls "$CMIN_DIR" 2>/dev/null | wc -l)

    if [ $cmin_status -ne 0 ] || [ "$cmin_count" -lt 1 ]; then
        echo "[gen] afl-cmin failed or empty, copying random 200 for seeds"
        ls "$GEN_DIR"/*.mp4 | shuf | head -200 | while read f; do
            cp "$f" "$CMIN_DIR/$(basename $f)" 2>/dev/null || true
        done
        cmin_count=$(ls "$CMIN_DIR" | wc -l)
    fi

    echo "[gen] After cmin: ${cmin_count} unique-coverage files"

    # ── Step 3a: Merge into seeds_ok (for future runs) ─────────────────────
    merged=0
    for f in "$CMIN_DIR"/*; do
        [ -f "$f" ] || continue
        sz=$(wc -c < "$f" 2>/dev/null || echo 0)
        [ "$sz" -lt 8 ] && continue
        [ "$sz" -gt 204800 ] && continue
        fname="gen_b${batch}_$(basename $f)"
        [ -f "${SEEDS_OK}/${fname}" ] && continue
        cp "$f" "${SEEDS_OK}/${fname}" && merged=$((merged + 1))
    done
    total_merged=$((total_merged + merged))
    echo "[gen] Merged ${merged} → seeds_ok now has $(ls $SEEDS_OK | wc -l) files"

    # ── Step 3b: Feed into the live AFL++ queue ─────────────────────────────
    # AFL++ syncs between instances via their queue directories.
    # We create a "generator" pseudo-instance directory that the main/secondary
    # instances will pick up during their next sync cycle.
    AFL_OUT_DIR=$(find /results/afl_out -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1)
    if [ -n "$AFL_OUT_DIR" ] && [ "$merged" -gt 0 ]; then
        QUEUE_DIR="${AFL_OUT_DIR}/generator/queue"
        mkdir -p "$QUEUE_DIR"
        fed=0
        for f in "$CMIN_DIR"/*; do
            [ -f "$f" ] || continue
            sz=$(wc -c < "$f" 2>/dev/null || echo 0)
            # Only feed compact files to the live queue (avoid slowing AFL++)
            [ "$sz" -lt 8 ] && continue
            [ "$sz" -gt 65536 ] && continue
            qname="id:$(printf '%06d' $fed),src:generator,$(basename $f)"
            cp "$f" "${QUEUE_DIR}/${qname}" 2>/dev/null && fed=$((fed + 1))
        done
        [ "$fed" -gt 0 ] && echo "[gen] Fed ${fed} files to live AFL++ queue: $QUEUE_DIR"
    fi

    echo "[gen] Batch #${batch} done. Total merged so far: ${total_merged}"

    # ── Rest between batches (don't thrash disk) ───────────────────────────
    sleep 60
done
