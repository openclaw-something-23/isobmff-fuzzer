#!/bin/bash
# generate_corpus.sh — Parallel mp4gen corpus generator for AFL++
#
# Runs as a background process alongside AFL++ fuzzing.
# Each batch:
#   1. mp4gen generates BATCH_SIZE MP4 files
#   2. afl-cmin finds the minimal unique-coverage subset
#   3. Per-file afl-showmap vs known coverage → only genuine new-coverage files survive
#   4. Contributors go to seeds_ok + live AFL++ queue; all others are deleted
#   5. Stats updated in /results/mp4gen_stats.json (exposed via /api/mp4gen)

set -uo pipefail

HARNESS="${HARNESS:-/fuzzer/fuzz_isobmff_afl}"
SEEDS_OK="${SEEDS_OK:-/results/seeds_ok}"
STATS_FILE="/results/mp4gen_stats.json"
WORK_ROOT="/results/mp4gen_work"   # NOT /tmp — afl-cmin refuses to work there
GEN_DIR="${WORK_ROOT}/gen"
CMIN_DIR="${WORK_ROOT}/cmin"
BATCH_SIZE="${GEN_BATCH_SIZE:-10000}"
TIMEOUT_MS="${GEN_TIMEOUT_MS:-5000}"
GEN_BIN="/fuzzer/mp4gen"
LOG_PREFIX="[gen]"

# AFL++ env vars (exported so child processes inherit them)
export AFL_NO_AFFINITY=1
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=0"

[ -x "$GEN_BIN" ]  || { echo "$LOG_PREFIX mp4gen not found at $GEN_BIN"; exit 0; }
[ -x "$HARNESS" ]  || { echo "$LOG_PREFIX harness not found at $HARNESS"; exit 0; }

mkdir -p "$SEEDS_OK" "$GEN_DIR" "$CMIN_DIR"

# ── Update /results/mp4gen_stats.json ──────────────────────────────────────
update_stats() {
    local generated=$1 cmin_count=$2 contributed=$3 batch_time=$4
    python3 - <<PYEOF
import json, time
sf = "$STATS_FILE"
try:
    with open(sf) as f: s = json.load(f)
except:
    s = {"total_generated":0,"total_cmin":0,"total_contributed":0,"batch_count":0,"batches":[]}
s["total_generated"]  += $generated
s["total_cmin"]       += $cmin_count
s["total_contributed"]+= $contributed
s["batch_count"]       = s.get("batch_count",0) + 1
s["last_batch_at"]     = time.strftime('%Y-%m-%dT%H:%M:%S')
s["batches"].append({"batch":s["batch_count"],"generated":$generated,
                      "cmin":$cmin_count,"contributed":$contributed,"time_sec":$batch_time})
s["batches"] = s["batches"][-100:]
with open(sf,'w') as f: json.dump(s,f)
print(f"[gen] stats: total_generated={s['total_generated']} total_cmin={s['total_cmin']} total_contributed={s['total_contributed']}")
PYEOF
}

# ── Build known-edge set from seeds_ok via afl-showmap ───────────────────
build_known_edges() {
    local out_file="$1"
    > "$out_file"
    local n=0
    for f in "$SEEDS_OK"/*; do
        [ -f "$f" ] || continue
        afl-showmap -q -o "${WORK_ROOT}/sm_tmp.map" -t "$TIMEOUT_MS" \
            -- "$HARNESS" < "$f" 2>/dev/null && \
        cut -d: -f1 "${WORK_ROOT}/sm_tmp.map" >> "$out_file" 2>/dev/null || true
        n=$((n+1))
    done
    sort -u "$out_file" -o "$out_file"
    echo "$LOG_PREFIX Known coverage: $(wc -l < $out_file) edges from $n seed files"
}

echo "$LOG_PREFIX ============================================"
echo "$LOG_PREFIX mp4gen corpus generator starting"
echo "$LOG_PREFIX   batch_size=$BATCH_SIZE  timeout=${TIMEOUT_MS}ms"
echo "$LOG_PREFIX   work_dir=$WORK_ROOT"
echo "$LOG_PREFIX ============================================"

batch=0

while true; do
    batch=$((batch + 1))
    BATCH_START=$(date +%s)
    echo "$LOG_PREFIX"
    echo "$LOG_PREFIX ── Batch #${batch} ───────────────────────────────────"

    # ── 1. Generate ────────────────────────────────────────────────────────
    rm -f "$GEN_DIR"/*.mp4 2>/dev/null || true
    echo "$LOG_PREFIX Generating ${BATCH_SIZE} MP4 files..."
    nice -n 10 "$GEN_BIN" "$GEN_DIR" "$BATCH_SIZE"

    GENERATED=$(ls "$GEN_DIR"/*.mp4 2>/dev/null | wc -l)
    echo "$LOG_PREFIX Generated: ${GENERATED} valid files ($(( BATCH_SIZE - GENERATED )) failed/oversized)"

    if [ "$GENERATED" -lt 10 ]; then
        echo "$LOG_PREFIX Too few files, skipping batch"
        update_stats 0 0 0 $(($(date +%s) - BATCH_START))
        sleep 60; continue
    fi

    # ── 2. afl-cmin: minimal unique-coverage subset ────────────────────────
    rm -rf "$CMIN_DIR" && mkdir -p "$CMIN_DIR"
    echo "$LOG_PREFIX Running afl-cmin on ${GENERATED} files..."

    timeout 600s afl-cmin \
        -i "$GEN_DIR" \
        -o "$CMIN_DIR" \
        -t "$TIMEOUT_MS" \
        -- "$HARNESS" 2>&1 | grep -E "Narrowed|Processed|tuples|error|Error" || true

    CMIN_COUNT=$(ls "$CMIN_DIR" 2>/dev/null | wc -l)

    if [ "$CMIN_COUNT" -lt 1 ]; then
        echo "$LOG_PREFIX afl-cmin produced 0 files — skipping batch"
        rm -f "$GEN_DIR"/*.mp4
        update_stats "$GENERATED" 0 0 $(($(date +%s) - BATCH_START))
        sleep 60; continue
    fi

    echo "$LOG_PREFIX afl-cmin: ${GENERATED} → ${CMIN_COUNT} unique-coverage files"

    # ── 3. Build known-edge baseline from current seeds_ok ─────────────────
    KNOWN_EDGES="${WORK_ROOT}/known_edges.map"
    build_known_edges "$KNOWN_EDGES"
    KNOWN_EDGE_COUNT=$(wc -l < "$KNOWN_EDGES")

    # ── 4. Per-file coverage check: keep only genuinely new ────────────────
    echo "$LOG_PREFIX Checking ${CMIN_COUNT} files for new edges vs ${KNOWN_EDGE_COUNT} known..."

    CONTRIBUTED=0
    NEW_EDGE_TOTAL=0

    # Find current AFL++ queue for live feeding
    AFL_RUN_DIR=$(ls -d /results/afl_out/*/ 2>/dev/null | sort | tail -1)
    GEN_QUEUE=""
    if [ -n "$AFL_RUN_DIR" ]; then
        GEN_QUEUE="${AFL_RUN_DIR}generator/queue"
        mkdir -p "$GEN_QUEUE"
    fi

    for f in "$CMIN_DIR"/*; do
        [ -f "$f" ] || continue

        # Get this file's coverage
        afl-showmap -q -o "${WORK_ROOT}/check.map" -t "$TIMEOUT_MS" \
            -- "$HARNESS" < "$f" 2>/dev/null || continue

        cut -d: -f1 "${WORK_ROOT}/check.map" | sort > "${WORK_ROOT}/check_edges.map"

        # Count edges NOT in known set
        NEW_EDGES=$(comm -23 "${WORK_ROOT}/check_edges.map" "$KNOWN_EDGES" | wc -l)

        if [ "$NEW_EDGES" -gt 0 ]; then
            # ✓ Contributes new coverage — keep it
            FNAME="gen_b${batch}_$(basename $f)"
            cp "$f" "${SEEDS_OK}/${FNAME}"

            # Feed to live AFL++ queue
            if [ -n "$GEN_QUEUE" ]; then
                cp "$f" "${GEN_QUEUE}/id:$(printf '%06d' $CONTRIBUTED),src:mp4gen,${FNAME}" 2>/dev/null || true
            fi

            # Update known edges incrementally (so later files don't double-count)
            sort -m "$KNOWN_EDGES" "${WORK_ROOT}/check_edges.map" \
                | uniq > "${WORK_ROOT}/known_updated.map"
            mv "${WORK_ROOT}/known_updated.map" "$KNOWN_EDGES"

            CONTRIBUTED=$((CONTRIBUTED + 1))
            NEW_EDGE_TOTAL=$((NEW_EDGE_TOTAL + NEW_EDGES))
        fi
        # Whether it contributed or not, delete the generated file — we don't keep raw generated files
    done

    # Delete all generated files (only seeds_ok copies survive)
    rm -f "$GEN_DIR"/*.mp4 "$CMIN_DIR"/* 2>/dev/null || true

    BATCH_TIME=$(($(date +%s) - BATCH_START))
    FINAL_KNOWN=$(wc -l < "$KNOWN_EDGES")
    SEEDS_COUNT=$(ls "$SEEDS_OK" | wc -l)

    echo "$LOG_PREFIX ── Batch #${batch} results ─────────────────────────"
    echo "$LOG_PREFIX   Generated:   ${GENERATED}"
    echo "$LOG_PREFIX   After cmin:  ${CMIN_COUNT} ($(( GENERATED - CMIN_COUNT )) duplicates removed)"
    echo "$LOG_PREFIX   Contributed: ${CONTRIBUTED} files adding ${NEW_EDGE_TOTAL} new edges"
    echo "$LOG_PREFIX   Discarded:   $((CMIN_COUNT - CONTRIBUTED)) (no new coverage)"
    echo "$LOG_PREFIX   seeds_ok:    ${SEEDS_COUNT} files total"
    echo "$LOG_PREFIX   Coverage:    ${KNOWN_EDGE_COUNT} → ${FINAL_KNOWN} edges (+$((FINAL_KNOWN - KNOWN_EDGE_COUNT)))"
    echo "$LOG_PREFIX   Time:        ${BATCH_TIME}s"
    [ -n "$GEN_QUEUE" ] && echo "$LOG_PREFIX   AFL++ queue: ${CONTRIBUTED} files → ${GEN_QUEUE}"

    update_stats "$GENERATED" "$CMIN_COUNT" "$CONTRIBUTED" "$BATCH_TIME"

    # Improvement 7: Stuck detection — if N consecutive batches contribute 0,
    # regenerate known_edges from current seeds_ok (coverage may have grown
    # via AFL++ mutations, making the old edge map stale).
    STUCK_FILE="/results/.mp4gen_stuck_count"
    if [ "$CONTRIBUTED" -eq 0 ]; then
        STUCK=$(( $(cat "$STUCK_FILE" 2>/dev/null || echo 0) + 1 ))
        echo $STUCK > "$STUCK_FILE"
        echo "$LOG_PREFIX [stuck=${STUCK}/5] No contribution this batch."
        if [ "$STUCK" -ge 5 ]; then
            echo "$LOG_PREFIX [!] Stuck for 5 batches — rebuilding known_edges.map from seeds_ok..."
            > "$KNOWN_EDGES"
            for f in "$SEEDS_OK"/*; do
                [ -f "$f" ] || continue
                afl-showmap -q -o "${WORK_ROOT}/sm_rebuild.map" -t "$TIMEOUT_MS" \
                    -- "$HARNESS" < "$f" 2>/dev/null && \
                cut -d: -f1 "${WORK_ROOT}/sm_rebuild.map" >> "$KNOWN_EDGES" 2>/dev/null || true
            done
            sort -u "$KNOWN_EDGES" -o "$KNOWN_EDGES"
            NEW_TOTAL=$(wc -l < "$KNOWN_EDGES")
            echo "$LOG_PREFIX [reset] Rebuilt known_edges: ${NEW_TOTAL} edges. Resuming..."
            echo 0 > "$STUCK_FILE"
        fi
    else
        echo 0 > "$STUCK_FILE"
    fi

    echo "$LOG_PREFIX Sleeping 30s before next batch..."
    sleep 30
done
