#!/usr/bin/env bash
# fetch_corpus.sh — bulk download of real-world ISOBMFF samples
# Sources: archive.org, codec repos, sample sites, conformance test suites
set -euo pipefail

SEEDS_DIR="${1:-/home/ubuntu/.openclaw/workspace/isobmff-fuzzer/seeds}"
WORK="/tmp/corpus_fetch_$$"
mkdir -p "$SEEDS_DIR" "$WORK"
ADDED=0; FAILED=0

dl() {
    local url="$1" name="${2:-$(basename "$1")}"
    local out="${WORK}/${name}"
    if wget -q --timeout=20 --tries=2 --no-check-certificate -O "$out" "$url" 2>/dev/null \
       && [ -s "$out" ] && [ "$(wc -c < "$out")" -ge 8 ]; then
        echo "  [+] $name ($(wc -c < "$out" | numfmt --to=iec))"
    else
        rm -f "$out"
        FAILED=$((FAILED+1))
    fi
}

echo "[*] === Downloading real-world ISOBMFF corpus ==="

# ────────────────────────────────────────────────────────────────────────────
# 1. Archive.org — large collection of public domain MP4/MOV files
# ────────────────────────────────────────────────────────────────────────────
echo "[*] Archive.org test vectors..."
BASE="https://archive.org/download"

# Blender open movies (small versions)
dl "${BASE}/ElephantsDream/ed_1024_512kb.mp4"                "archive_ed_512k.mp4"
dl "${BASE}/BigBuckBunny_124/BigBuckBunny_512kb.mp4"         "archive_bbb_512k.mp4"
dl "${BASE}/Sintel/sintel-1024-surround.mp4"                 "archive_sintel.mp4"

# Various format samples
dl "${BASE}/test_mp4/test.mp4"                               "archive_test.mp4"
dl "${BASE}/ForBiggerBlazes/ForBiggerBlazes.mp4"             "archive_blazes.mp4"
dl "${BASE}/ForBiggerEscapes/ForBiggerEscapes.mp4"           "archive_escapes.mp4"
dl "${BASE}/ForBiggerFun/ForBiggerFun.mp4"                   "archive_fun.mp4"
dl "${BASE}/ForBiggerJoyrides/ForBiggerJoyrides.mp4"         "archive_joyrides.mp4"
dl "${BASE}/ForBiggerMeltdowns/ForBiggerMeltdowns.mp4"       "archive_meltdowns.mp4"
dl "${BASE}/SubaruOutbackOnDirtRoad/SubaruOutbackOnDirtRoad.mp4" "archive_subaru.mp4"
dl "${BASE}/WildlifeSample/Wildlife.mp4"                     "archive_wildlife.mp4"

# ────────────────────────────────────────────────────────────────────────────
# 2. W3C / MPEG conformance samples (direct URLs)
# ────────────────────────────────────────────────────────────────────────────
echo "[*] Sample sites..."
dl "https://www.w3schools.com/html/mov_bbb.mp4"              "w3s_bbb.mp4"
dl "https://www.w3schools.com/html/movie.mp4"                "w3s_movie.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4" \
                                                             "gcs_bbb.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4" \
                                                             "gcs_ed.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4" \
                                                             "gcs_blazes.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerEscapes.mp4" \
                                                             "gcs_escapes.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerFun.mp4" \
                                                             "gcs_fun.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerJoyrides.mp4" \
                                                             "gcs_joyrides.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerMeltdowns.mp4" \
                                                             "gcs_meltdowns.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/SubaruOutbackOnDirtRoad.mp4" \
                                                             "gcs_subaru.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/TearsOfSteel.mp4" \
                                                             "gcs_tos.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/WhatCarCanYouGetForAGrand.mp4" \
                                                             "gcs_car.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/WeAreGoingOnBullrun.mp4" \
                                                             "gcs_bullrun.mp4"
dl "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/VolkswagenGTIReview.mp4" \
                                                             "gcs_vw.mp4"

# ────────────────────────────────────────────────────────────────────────────
# 3. GitHub raw — codec/parser test suites with direct binary files
# ────────────────────────────────────────────────────────────────────────────
echo "[*] GitHub raw test files..."
GPAC="https://raw.githubusercontent.com/gpac/gpac/master"
dl "${GPAC}/tests/media/auxiliary_tracks/mpeg4.mp4"          "gpac_mpeg4.mp4"
dl "${GPAC}/tests/media/auxiliary_tracks/hevc.mp4"           "gpac_hevc.mp4"
dl "${GPAC}/tests/media/hevctile/tile_1920x1080.mp4"         "gpac_tile.mp4"
dl "${GPAC}/tests/media/frag/fragmented.mp4"                 "gpac_frag.mp4"
dl "${GPAC}/tests/media/dash/seg_1.m4s"                      "gpac_seg1.m4s"
dl "${GPAC}/tests/media/mp4/test.mp4"                        "gpac_test.mp4"
dl "${GPAC}/tests/media/mp4/file.mp4"                        "gpac_file.mp4"
dl "${GPAC}/tests/media/audio/file.m4a"                      "gpac_audio.m4a"
dl "${GPAC}/tests/media/hls/prog_index.m3u8"                 "gpac_hls.m3u8"

LIBHEIF="https://raw.githubusercontent.com/strukturag/libheif/master"
dl "${LIBHEIF}/examples/example.heic"                        "libheif_example.heic"
dl "${LIBHEIF}/examples/example.avif"                        "libheif_example.avif"
dl "${LIBHEIF}/tests/images/heic_brands.heic"                "libheif_brands.heic"
dl "${LIBHEIF}/tests/images/hvc1.heic"                       "libheif_hvc1.heic"
dl "${LIBHEIF}/tests/images/no_idat.heic"                    "libheif_no_idat.heic"
dl "${LIBHEIF}/tests/images/invalid.heic"                    "libheif_invalid.heic"

BENTO="https://raw.githubusercontent.com/axiomatic-systems/Bento4/master"
dl "${BENTO}/Source/Python/tests/streams/test-1.mp4"         "bento4_test1.mp4"
dl "${BENTO}/Source/Python/tests/streams/test-2.mp4"         "bento4_test2.mp4"
dl "${BENTO}/Source/Python/tests/streams/prog_index.m3u8"    "bento4_hls.m3u8"

# MP4-parser focused repos
MP4PARSE="https://raw.githubusercontent.com/mozilla/mp4parse-rust/master"
dl "${MP4PARSE}/mp4parse/tests/minimal.mp4"                  "mp4parse_minimal.mp4"
dl "${MP4PARSE}/mp4parse/tests/audio-video.mp4"              "mp4parse_av.mp4"
dl "${MP4PARSE}/mp4parse/tests/bipbop-cenc-keyid.mp4"        "mp4parse_cenc.mp4"
dl "${MP4PARSE}/mp4parse/tests/corrupted.mp4"                "mp4parse_corrupted.mp4"
dl "${MP4PARSE}/mp4parse/tests/opus.mp4"                     "mp4parse_opus.mp4"
dl "${MP4PARSE}/mp4parse/tests/tiny.mp4"                     "mp4parse_tiny.mp4"
dl "${MP4PARSE}/mp4parse/tests/flac.mp4"                     "mp4parse_flac.mp4"
dl "${MP4PARSE}/mp4parse/tests/short-cenc.mp4"               "mp4parse_cenc_short.mp4"
dl "${MP4PARSE}/mp4parse/tests/bipbop-cenc-v2.mp4"           "mp4parse_cenc_v2.mp4"
dl "${MP4PARSE}/mp4parse/tests/avc3.mp4"                     "mp4parse_avc3.mp4"
dl "${MP4PARSE}/mp4parse/tests/frag-video.mp4"               "mp4parse_frag.mp4"
dl "${MP4PARSE}/mp4parse/tests/frag-sync-samples.mp4"        "mp4parse_frag_sync.mp4"
dl "${MP4PARSE}/mp4parse/tests/h263.3gp"                     "mp4parse_h263.3gp"
dl "${MP4PARSE}/mp4parse/tests/unknown-codec.mp4"            "mp4parse_unknown_codec.mp4"
dl "${MP4PARSE}/mp4parse/tests/mov.mov"                      "mp4parse_mov.mov"

# mp4box.js (GPAC JS port) test files
MP4BOXJS="https://raw.githubusercontent.com/nicktindall/cyclon.js/master/test/data"
dl "${MP4BOXJS}/sample.mp4"                                  "cyclon_sample.mp4"

# Chromium test data
CHROMIUM="https://raw.githubusercontent.com/chromium/chromium/main"
dl "${CHROMIUM}/media/test/data/bear.mp4"                    "chrome_bear.mp4"
dl "${CHROMIUM}/media/test/data/bear-1280x720.mp4"           "chrome_bear_hd.mp4"
dl "${CHROMIUM}/media/test/data/bear-av1.mp4"                "chrome_bear_av1.mp4"
dl "${CHROMIUM}/media/test/data/bear-vp9.mp4"                "chrome_bear_vp9.mp4"
dl "${CHROMIUM}/media/test/data/bear_silent.mp4"             "chrome_bear_silent.mp4"
dl "${CHROMIUM}/media/test/data/sfx.mp4"                     "chrome_sfx.mp4"
dl "${CHROMIUM}/media/test/data/sfx-opus.mp4"                "chrome_sfx_opus.mp4"
dl "${CHROMIUM}/media/test/data/sfx_f32le.mp4"               "chrome_sfx_f32le.mp4"
dl "${CHROMIUM}/media/test/data/bear-no-moov.mp4"            "chrome_no_moov.mp4"
dl "${CHROMIUM}/media/test/data/bear-moov-fragmented.mp4"    "chrome_frag.mp4"
dl "${CHROMIUM}/media/test/data/bear-hevc.mp4"               "chrome_hevc.mp4"
dl "${CHROMIUM}/media/test/data/bear-vp9-hdr.mp4"            "chrome_vp9_hdr.mp4"
dl "${CHROMIUM}/media/test/data/bear-flac.mp4"               "chrome_flac.mp4"
dl "${CHROMIUM}/media/test/data/dash_mobile.mp4"             "chrome_dash_mobile.mp4"
dl "${CHROMIUM}/media/test/data/bipbop.mp4"                  "chrome_bipbop.mp4"
dl "${CHROMIUM}/media/test/data/sample-cbcs-2-encrypt.mp4"   "chrome_cbcs.mp4"
dl "${CHROMIUM}/media/test/data/muxed-av-cenc-subsample.mp4" "chrome_cenc_sub.mp4"
dl "${CHROMIUM}/media/test/data/bear-a-only.mp4"             "chrome_audio_only.mp4"
dl "${CHROMIUM}/media/test/data/bear-v-only.mp4"             "chrome_video_only.mp4"

# WebKit test media
WEBKIT="https://raw.githubusercontent.com/WebKit/WebKit/main"
dl "${WEBKIT}/LayoutTests/media/content/test.mp4"            "webkit_test.mp4"
dl "${WEBKIT}/LayoutTests/media/content/video-with-metadata.mp4" "webkit_meta.mp4"

# ExoPlayer test data
EXOPLAYER="https://raw.githubusercontent.com/google/ExoPlayer/release-v2"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample.mp4" "exo_sample.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_ac4.mp4" "exo_ac4.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_fragmented.mp4" "exo_frag.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_with_metadata.mp4" "exo_meta.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/testvid_1022ms.mp4" "exo_1022ms.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_mdat_before_moov.mp4" "exo_mdat_first.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_with_colr_hdr_contents.mp4" "exo_hdr.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_with_edts_and_elst.mp4" "exo_edts.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_fragmented_seekable.mp4" "exo_frag_seek.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_with_chapters.mp4" "exo_chapters.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_iPod.m4v"         "exo_ipod.m4v"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_ac3.mp4"          "exo_ac3.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_eac3.mp4"         "exo_eac3.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_opus.mp4"         "exo_opus.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_with_smpte_tt.mp4" "exo_smpte.mp4"
dl "${EXOPLAYER}/testdata/src/test/assets/media/mp4/sample_fragmented_no_sync_frame_near_start.mp4" "exo_no_sync.mp4"

# ────────────────────────────────────────────────────────────────────────────
# 4. MP4 conformance / edge cases (various GitHub)
# ────────────────────────────────────────────────────────────────────────────
echo "[*] Edge case & conformance files..."
# mp4ff (Go MP4 library) tests
MP4FF="https://raw.githubusercontent.com/Eyevinn/mp4ff/master"
dl "${MP4FF}/mp4/testdata/prog_8s.mp4"                       "mp4ff_prog8s.mp4"
dl "${MP4FF}/mp4/testdata/segmented.mp4"                     "mp4ff_segmented.mp4"

# Shaka packager tests
SHAKA="https://raw.githubusercontent.com/shaka-project/shaka-packager/main"
dl "${SHAKA}/packager/media/test/data/bear-1280x720.mp4"     "shaka_bear.mp4"
dl "${SHAKA}/packager/media/test/data/bear-1280x720-av_frag.mp4" "shaka_frag.mp4"

# dash.js reference player test content
DASHJS="https://raw.githubusercontent.com/Dash-Industry-Forum/dash.js/development"
dl "${DASHJS}/test/functional/content/BigBuckBunny_8s_init.mp4" "dash_bbb_init.mp4"

# ────────────────────────────────────────────────────────────────────────────
# 5. Validate + size-limit + copy to seeds dir
# ────────────────────────────────────────────────────────────────────────────
echo "[*] Validating ${WORK}/ → ${SEEDS_DIR}/ ..."
for f in "${WORK}"/*; do
    [ -f "$f" ] || continue
    sz=$(wc -c < "$f")
    [ "$sz" -lt 8 ]       && rm -f "$f" && continue
    [ "$sz" -gt 4194304 ] && rm -f "$f" && continue   # drop >4MB
    # Accept if offset 4 has a printable 4CC
    if python3 -c "
d=open('$f','rb').read(16)
if len(d)<8: exit(1)
# Check offset 4-8 (standard box FourCC)
fcc=d[4:8]
if all(32<=b<=126 for b in fcc): exit(0)
# Also accept files starting with common magic (e.g. ISO BMFF after skip)
exit(1)
" 2>/dev/null; then
        dest="${SEEDS_DIR}/$(basename "$f")"
        if [ ! -f "$dest" ]; then
            cp "$f" "$dest"
            ADDED=$((ADDED+1))
        fi
    fi
done

rm -rf "${WORK}"

echo ""
echo "[+] ─────────────────────────────────────────────"
echo "[+] New files added : ${ADDED}"
echo "[+] Failed downloads: ${FAILED}"
echo "[+] Total seeds     : $(ls "${SEEDS_DIR}" | wc -l)"
echo "[+] ─────────────────────────────────────────────"
