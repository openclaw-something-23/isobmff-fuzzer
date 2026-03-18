#!/usr/bin/env bash
# fetch_corpus_extra.sh — Fetch ISOBMFF corpus files from public sources
#
# Sources:
#  1. androidx.media3  — 150+ MP4/3GP/MOV + CMAF/DASH fMP4 segments
#  2. mplayerhq.hu     — Old/weird QuickTime MOV + MPEG-4 files
#  3. GPAC test suite  — ISOBMFF parser edge cases
#  4. libheif samples  — HEIC/HEIF/AVIF files
#  5. WPT (Web Platform Tests) — Browser conformance MP4 files
#  6. Bento4 extras    — ISOBMFF toolkit test files
#  7. MPEG DASH IF     — Fragmented MP4 init + media segments
#  8. open GCS buckets — Google TV, WebM Project, Shaka Player

set -euo pipefail

SEEDS_DIR="${1:-$(dirname "$0")/../seeds}"
SEEDS_DIR="$(realpath "$SEEDS_DIR")"
mkdir -p "$SEEDS_DIR"

TMPDIR=$(mktemp -d /tmp/fetch_corpus_XXXXX)
trap "rm -rf $TMPDIR" EXIT

ADDED=0
SKIPPED=0
FAILED=0

log()   { echo "[+] $*"; }
warn()  { echo "[!] $*" >&2; }
debug() { echo "    $*"; }

# Download a file with prefix, skip if hash already exists
fetch() {
    local url="$1" prefix="$2" ext="${3:-}"
    local tmpfile="$TMPDIR/tmp_$$"

    if ! curl -sfL --max-time 30 --max-filesize 5242880 \
         -A "Mozilla/5.0 isobmff-fuzzer-corpus-fetcher" \
         -o "$tmpfile" "$url" 2>/dev/null; then
        FAILED=$((FAILED+1))
        return 1
    fi

    local sz
    sz=$(wc -c < "$tmpfile" 2>/dev/null || echo 0)
    if [ "$sz" -lt 8 ]; then
        FAILED=$((FAILED+1))
        return 1
    fi

    local hash
    hash=$(sha1sum "$tmpfile" | cut -d' ' -f1)
    local hash_short="${hash:0:8}"

    # Determine extension
    if [ -z "$ext" ]; then
        local fname
        fname=$(basename "$url" | sed 's/[?#].*//')
        ext="${fname##*.}"
        [ "$ext" = "$fname" ] && ext="bin"
    fi
    ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]')

    local destname="${prefix}_${hash_short}.${ext}"
    local dest="$SEEDS_DIR/$destname"

    # Skip if same hash already in seeds
    if find "$SEEDS_DIR" -name "*${hash_short}*" 2>/dev/null | grep -q .; then
        SKIPPED=$((SKIPPED+1))
        return 0
    fi

    cp "$tmpfile" "$dest"
    ADDED=$((ADDED+1))
    debug "  + $destname (${sz}B)"
}

# Fetch all files listed by GitHub API in a directory
fetch_github_dir() {
    local repo="$1" path="$2" prefix="$3"
    local api_url="https://api.github.com/repos/${repo}/contents/${path}"

    local listing
    listing=$(curl -sfL --max-time 15 \
        -H "Accept: application/vnd.github.v3+json" \
        "$api_url" 2>/dev/null) || { warn "Failed to list $repo/$path"; return 1; }

    local urls
    urls=$(echo "$listing" | python3 -c "
import sys,json
items=json.load(sys.stdin)
for i in items:
    if i.get('type')=='file' and i.get('download_url'):
        name=i['name'].lower()
        if any(name.endswith(x) for x in ('.mp4','.m4a','.m4v','.m4s','.mov','.3gp','.3g2','.heic','.heif','.avif','.caf','.cmf')):
            print(i['download_url'])
" 2>/dev/null)

    local count=0
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local fname ext
        fname=$(basename "$url")
        ext="${fname##*.}"
        fetch "$url" "$prefix" "$ext" && count=$((count+1)) || true
    done <<< "$urls"
    log "$repo/$path → $count files queued"
}

# ── 1. androidx.media3 — mp4/ dir (150 files) ─────────────────────────────────
log "=== androidx.media3/mp4 ==="
fetch_github_dir "androidx/media" \
    "libraries/test_data/src/test/assets/media/mp4" \
    "media3"

# ── 2. androidx.media3 — CMAF fMP4 segments ───────────────────────────────────
log "=== androidx.media3/cmaf ==="
fetch_github_dir "androidx/media" \
    "libraries/test_data/src/test/assets/media/cmaf/multi-segment" \
    "media3_cmaf"

# Also recurse into DASH dirs for fMP4 init segments
log "=== androidx.media3/dash dirs ==="
DASH_DIRS=$(curl -sfL --max-time 10 \
    "https://api.github.com/repos/androidx/media/contents/libraries/test_data/src/test/assets/media/dash" \
    2>/dev/null | python3 -c "
import sys,json
items=json.load(sys.stdin)
for i in items:
    if i['type']=='dir': print(i['name'])
" 2>/dev/null || true)

while IFS= read -r d; do
    [ -z "$d" ] && continue
    fetch_github_dir "androidx/media" \
        "libraries/test_data/src/test/assets/media/dash/$d" \
        "media3_dash"
done <<< "$DASH_DIRS"

# ── 3. androidx.media3 — HEIF/AVIF ────────────────────────────────────────────
log "=== androidx.media3/heif+avif ==="
fetch_github_dir "androidx/media" \
    "libraries/test_data/src/test/assets/media/heif" \
    "media3_heif"
fetch_github_dir "androidx/media" \
    "libraries/test_data/src/test/assets/media/avif" \
    "media3_avif"

# ── 4. mplayerhq.hu — Old/weird QuickTime MOV ─────────────────────────────────
log "=== mplayerhq MOV files ==="
MOV_FILES=$(curl -sfL --max-time 15 "http://samples.mplayerhq.hu/mov/" 2>/dev/null \
    | grep -oP 'href="([^"]+\.mov)"' | grep -oP '"[^"]+"' | tr -d '"' || true)
while IFS= read -r f; do
    [ -z "$f" ] && continue
    fetch "http://samples.mplayerhq.hu/mov/$f" "mplayerhq_mov" "mov" || true
done <<< "$MOV_FILES"

log "=== mplayerhq MPEG-4 files ==="
MP4_FILES=$(curl -sfL --max-time 15 "http://samples.mplayerhq.hu/MPEG-4/" 2>/dev/null \
    | grep -oP 'href="([^"]+\.mp4)"' | grep -oP '"[^"]+"' | tr -d '"' || true)
while IFS= read -r f; do
    [ -z "$f" ] && continue
    fetch "http://samples.mplayerhq.hu/MPEG-4/$f" "mplayerhq_mp4" "mp4" || true
done <<< "$MP4_FILES"

# Also 3GPP files
log "=== mplayerhq 3GPP files ==="
GPP_FILES=$(curl -sfL --max-time 15 "http://samples.mplayerhq.hu/3gp/" 2>/dev/null \
    | grep -oP 'href="([^"]+\.(3gp|3g2))"' | grep -oP '"[^"]+"' | tr -d '"' || true)
while IFS= read -r f; do
    [ -z "$f" ] && continue
    ext="${f##*.}"
    fetch "http://samples.mplayerhq.hu/3gp/$f" "mplayerhq_3gp" "$ext" || true
done <<< "$GPP_FILES"

# ── 5. GPAC test suite ────────────────────────────────────────────────────────
log "=== GPAC test files ==="
fetch_github_dir "gpac/gpac" "tests/media/mp4" "gpac"
fetch_github_dir "gpac/gpac" "tests/media/heif" "gpac_heif" 2>/dev/null || true

# ── 6. libheif test images ────────────────────────────────────────────────────
log "=== libheif test images ==="
fetch_github_dir "strukturag/libheif" "tests/images" "libheif"

# Also check libavif test files
log "=== libavif test files ==="
fetch_github_dir "AOMediaCodec/libavif" "tests/data" "libavif" 2>/dev/null || true

# ── 7. MPEGGroup/isobmff reference files ──────────────────────────────────────
log "=== MPEGGroup/isobmff reference files ==="
fetch_github_dir "MPEGGroup/isobmff" "IsoLib/test_files" "mpeggroup" 2>/dev/null || true

# ── 8. WebPlatformTests (WPT) media files ─────────────────────────────────────
# WPT has many edge-case MP4s for browser testing
log "=== WPT media files ==="
WPT_DIRS=(
    "media-source/resources"
    "html/semantics/embedded-content/media/video"
)
for wpt_dir in "${WPT_DIRS[@]}"; do
    fetch_github_dir "web-platform-tests/wpt" "$wpt_dir" "wpt" 2>/dev/null || true
done

# ── 9. Bento4 test files (extras beyond what we have) ─────────────────────────
log "=== Bento4 test files ==="
fetch_github_dir "axiomatic-systems/Bento4" "Source/Python/utils" "bento4" 2>/dev/null || true
fetch_github_dir "axiomatic-systems/Bento4" "Tests/Data" "bento4" 2>/dev/null || true

# ── 10. Open GCS buckets ──────────────────────────────────────────────────────
# Google TV sample videos (publicly accessible)
log "=== Google TV sample videos ==="
GTV_FILES=(
    "BigBuckBunny_320x180.mp4"
    "ElephantsDream_320x180.mp4"
    "ForBiggerBlazes.mp4"
    "ForBiggerEscapes.mp4"
    "ForBiggerFun.mp4"
    "ForBiggerJoyrides.mp4"
    "ForBiggerMeltdowns.mp4"
    "Subaru_Outback_PCS.mp4"
    "TearsOfSteel.mp4"
    "VolkswagenGTIReview.mp4"
    "WeAreGoingOnBullrun.mp4"
    "WhatCarCanYouGetForAGrand.mp4"
)
for f in "${GTV_FILES[@]}"; do
    fetch "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/$f" \
        "gtv" "mp4" || true
done

# ── 11. Shaka Player demo assets (publicly accessible) ────────────────────────
log "=== Shaka Player CMAF init segments ==="
SHAKA_ASSETS=(
    "tears-of-steel-dash-v2-hd/v-0144p-0100k-libx264-init.mp4"
    "tears-of-steel-dash-v2-hd/v-0240p-0300k-libx264-init.mp4"
    "tears-of-steel-dash-v2-hd/a-en-0128k-aac-init.mp4"
    "tears-of-steel-hevc/v-0144p-0100k-hevc-init.mp4"
    "tears-of-steel-hevc/a-en-0128k-aac-init.mp4"
    "bbb-vp9-dash/video/init.mp4"
)
for asset in "${SHAKA_ASSETS[@]}"; do
    fetch "https://storage.googleapis.com/shaka-demo-assets/$asset" \
        "shaka_init" "mp4" || true
done

# ── 12. Common CVE/fuzzing targets — known-tricky files ───────────────────────
# MP4 files from the mp4v2 / gpac / FFmpeg CVE databases that are publicly available
log "=== Known CVE-related public test files ==="
CVE_FILES=(
    # gpac crash PoCs (some public in issue tracker)
    "https://raw.githubusercontent.com/nicktindall/cyclopedia-mp4/master/test-vectors/atom_basic.mp4"
    # Various MPEG-DASH test init segments from DASH-IF reference player
    "https://dash.akamaized.net/dash264/TestCases/1a/netflix/exMPD_BIP_TC1.mpd"
)
for url in "${CVE_FILES[@]}"; do
    ext="${url##*.}"
    [[ "$ext" == "mpd" ]] && continue  # skip manifests
    fetch "$url" "cve_poc" "$ext" || true
done

# ── 13. Apple HEIF samples ─────────────────────────────────────────────────────
log "=== Apple-style HEIF (via libheif conformance) ==="
HEIF_SAMPLES=(
    "https://raw.githubusercontent.com/nokiatech/heif/master/conformance/images/C012.heic"
    "https://raw.githubusercontent.com/nokiatech/heif/master/conformance/images/C008.heic"
    "https://raw.githubusercontent.com/nokiatech/heif/master/conformance/images/C004.heic"
    "https://raw.githubusercontent.com/nokiatech/heif/master/conformance/images/C001.heic"
)
for url in "${HEIF_SAMPLES[@]}"; do
    fetch "$url" "nokia_heif" "heic" || true
done

# ── 14. FFmpeg FATE corpus (direct links) ─────────────────────────────────────
log "=== FFmpeg FATE sample files ==="
FATE_FILES=(
    "https://fate.ffmpeg.org/fate-suite/mov/mp4-with-mov-box.mp4"
    "https://fate.ffmpeg.org/fate-suite/mov/mov-3elist.mov"
    "https://fate.ffmpeg.org/fate-suite/mov/mov-3elist-boom.mov"
    "https://fate.ffmpeg.org/fate-suite/mov/quicktime.mov"
    "https://fate.ffmpeg.org/fate-suite/mp4/unspecified_channel_configuration.mp4"
    "https://fate.ffmpeg.org/fate-suite/mp4/mov_3gp_weird_offsets.mp4"
    "https://fate.ffmpeg.org/fate-suite/mp4/mp4-with-mov-box.mp4"
    "https://fate.ffmpeg.org/fate-suite/mp4/corrupt-duration-in-edit-list.mp4"
    "https://fate.ffmpeg.org/fate-suite/hevc/ps_change.mp4"
)
for url in "${FATE_FILES[@]}"; do
    ext="${url##*.}"
    fetch "$url" "fate" "$ext" || true
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════╗"
echo "║  fetch_corpus_extra — complete   ║"
echo "╠══════════════════════════════════╣"
printf "║  %-10s  %6d files      ║\n" "Added:"   "$ADDED"
printf "║  %-10s  %6d files      ║\n" "Skipped:" "$SKIPPED"
printf "║  %-10s  %6d files      ║\n" "Failed:"  "$FAILED"
echo "║                                  ║"
printf "║  Seeds dir now: %-4d total      ║\n" "$(ls "$SEEDS_DIR" | wc -l)"
echo "╚══════════════════════════════════╝"
