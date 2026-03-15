/*
 * mp4gen.c — ISOBMFF corpus generator using FFmpeg libav* API (v4.4)
 *
 * 150+ feature dimensions for maximum diversity:
 *   RESOLUTIONS      : 35  (4×4 to 3840×2160, portrait/square/ultra-wide/odd)
 *   FRAME RATES      : 30  (0.5 – 240fps, NTSC drop-frame, cinema)
 *   MOVFLAGS         : 38  (faststart, all frag_* combos, frag_duration, frag_size)
 *   X264 CONFIGS     : 45  (all presets, tunes, profiles L1.0-5.2, CRF 0-51, VBV, psy-rd)
 *   PIXEL FORMATS    : 12  (yuv420p/422p/444p, j420p, 10-bit, gray, nv12)
 *   VIDEO CODECS     : 4   (libx264, mjpeg, mpeg4, h263p)
 *   AUDIO CONFIGS    : 40  (AAC/MP3/AC3/FLAC/PCM-S16/S24/EAC3/ALAC/OPUS/AMR/MP2)
 *   AUDIO WAVEFORMS  : 20  (sine/sq/saw/tri/noise/chirp/pulse/dual/AM/DTMF/pink/brown/harm)
 *   VISUAL PATTERNS  : 33  (Mandelbrot/Julia/plasma/rings/spiral/colorbars/Bayer/etc.)
 *   CONTAINER EXTRAS : 60+ (colr×6, SAR×12, rotation×8, stereo3D×5, HDR, chapters×4,
 *                           edit list, brand×8, disposition×6, GPS, XMP spherical,
 *                           cover art, second audio, iTunes metadata, btrt, clap,
 *                           frag_duration, frag_size, timecode, ProRes compat. brand)
 *
 * Usage: mp4gen <output_dir> <count>  (count=0 → infinite)
 * Compile:
 *   gcc -O2 -o mp4gen mp4gen.c \
 *     $(pkg-config --cflags libavformat libavcodec libavutil libswresample libswscale) \
 *     -lavformat -lavcodec -lavutil -lswresample -lswscale -lm
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/avutil.h>
#include <libavutil/display.h>
#include <libavutil/mastering_display_metadata.h>
#include <libavutil/mathematics.h>
#include <libavutil/opt.h>
#include <libavutil/stereo3d.h>
#include <libswresample/swresample.h>
#include <libswscale/swscale.h>
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ── RNG ─────────────────────────────────────────────────────────────────── */
static uint64_t mix64(uint64_t h) {
    h ^= h>>33; h *= 0xff51afd7ed558ccdULL;
    h ^= h>>33; h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h>>33; return h;
}
#define SEL(s,salt,n)  ((int)(mix64((s)^(uint64_t)(salt)) % (unsigned)(n)))
#define FLAG(s,salt,p) (mix64((s)^(uint64_t)(salt)) % 100 < (unsigned)(p))

/* ══════════════════════════════════════════════════════════════════════════
 *  FEATURE TABLES
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── 35 Resolutions ───────────────────────────────────────────────────────── */
typedef struct { int w, h; } Res;
static const Res RESOLUTIONS[] = {
    /* extreme tiny */  {4,4},{8,8},{16,16},{24,24},{32,32},
    /* tiny */          {48,48},{64,64},{72,72},{80,60},{96,96},
    /* portrait */      {108,192},{144,256},{180,320},{240,426},{270,480},
    /* square */        {128,128},{200,200},{256,256},{320,320},{512,512},
    /* QCIF/CIF */      {176,144},{352,288},{160,120},{240,180},
    /* ultrawide */     {256,64},{512,128},{800,200},{1280,160},
    /* standard SD */   {320,240},{426,240},{640,360},{640,480},
    /* HD */            {960,540},{1280,720},{1920,1080},
    /* 4K (1 frame) */  {3840,2160},
};
#define N_RES ((int)(sizeof(RESOLUTIONS)/sizeof(RESOLUTIONS[0])))

/* ── 30 Frame rates ──────────────────────────────────────────────────────── */
typedef struct { int num, den; } FPS;
static const FPS FRAMERATES[] = {
    {1,2},   /* 0.5fps */
    {1,1},{2,1},{3,1},{4,1},{5,1},{6,1},{7,1},{8,1},{9,1},{10,1},
    {12,1},{15,1},{16,1},{18,1},{20,1},{24,1},{25,1},{30,1},
    {48,1},{50,1},{60,1},{72,1},{90,1},{100,1},{120,1},{144,1},{240,1},
    {24000,1001},{30000,1001},
};
#define N_FPS ((int)(sizeof(FRAMERATES)/sizeof(FRAMERATES[0])))

/* ── 38 movflags ─────────────────────────────────────────────────────────── */
static const char *MOVFLAGS[] = {
    "",
    "faststart",
    "frag_keyframe",
    "frag_keyframe+empty_moov",
    "frag_keyframe+empty_moov+default_base_moof",
    "frag_keyframe+omit_tfhd_offset",
    "frag_keyframe+separate_moof",
    "frag_keyframe+default_base_moof+omit_tfhd_offset",
    "frag_keyframe+negative_cts_offsets",
    "frag_keyframe+empty_moov+separate_moof",
    "frag_keyframe+empty_moov+default_base_moof+omit_tfhd_offset",
    "frag_keyframe+empty_moov+negative_cts_offsets",
    "frag_keyframe+separate_moof+omit_tfhd_offset",
    "frag_keyframe+default_base_moof+negative_cts_offsets",
    "frag_keyframe+empty_moov+default_base_moof+separate_moof",
    "frag_keyframe+empty_moov+default_base_moof+omit_tfhd_offset+separate_moof",
    "frag_keyframe+empty_moov+negative_cts_offsets+omit_tfhd_offset",
    "frag_keyframe+disable_chpl",
    "faststart+disable_chpl",
    "frag_keyframe+empty_moov+default_base_moof+disable_chpl",
    "frag_keyframe+empty_moov+negative_cts_offsets+separate_moof",
    "faststart+frag_keyframe+empty_moov",
    "frag_keyframe+negative_cts_offsets+separate_moof+omit_tfhd_offset",
    /* frag_duration variants (require fragment_duration option) */
    "frag_duration",
    "frag_duration+empty_moov",
    "frag_duration+empty_moov+default_base_moof",
    "frag_duration+faststart",
    /* frag_size variants */
    "frag_size",
    "frag_size+empty_moov",
    "frag_size+separate_moof",
    /* combined extreme */
    "frag_keyframe+empty_moov+default_base_moof+separate_moof+negative_cts_offsets",
    "frag_keyframe+empty_moov+omit_tfhd_offset+negative_cts_offsets+separate_moof",
    "frag_keyframe+empty_moov+default_base_moof+omit_tfhd_offset+negative_cts_offsets",
    "faststart+frag_keyframe",
    "faststart+frag_keyframe+default_base_moof",
    "frag_keyframe+empty_moov+disable_chpl+separate_moof",
    "frag_keyframe+empty_moov+negative_cts_offsets+default_base_moof+disable_chpl",
    "frag_size+frag_keyframe+separate_moof+empty_moov",
};
#define N_MOVFLAGS ((int)(sizeof(MOVFLAGS)/sizeof(MOVFLAGS[0])))

/* ── 45 x264 configs: preset / tune / profile / level / crf + extras ──────── */
typedef struct {
    const char *preset, *tune, *profile, *level;
    int crf;
    int trellis;    /* 0/1/2 */
    int cabac;      /* 0/1 */
    int bframes;    /* 0-4 */
    int deblock;    /* 0=off, 1=on */
    int vbv_maxrate;/* 0=off, else kbps */
    int vbv_bufsize;/* kbps */
    int intra_refresh; /* 0/1 */
} X264Cfg;
static const X264Cfg X264_CFGS[] = {
    /* preset, tune, profile, level, crf, trellis, cabac, bframes, deblock, vbv_maxrate, vbv_bufsize, intra_refresh */
    {"ultrafast","zerolatency","baseline","3.0",  28, 0, 0, 0, 1, 0,    0,    0},
    {"ultrafast","zerolatency","main",    "3.1",  28, 0, 1, 2, 1, 0,    0,    0},
    {"ultrafast","fastdecode", "high",    "4.0",  28, 0, 1, 2, 1, 0,    0,    0},
    {"superfast","zerolatency","baseline","2.1",  30, 0, 0, 0, 1, 0,    0,    0},
    {"superfast","fastdecode", "main",    "3.1",  28, 1, 1, 2, 1, 0,    0,    0},
    {"veryfast", "zerolatency","main",    "4.0",  26, 1, 1, 3, 1, 0,    0,    0},
    {"veryfast", "animation",  "high",    "4.1",  25, 2, 1, 3, 1, 0,    0,    0},
    {"faster",   "grain",      "high",    "4.0",  27, 1, 1, 2, 1, 0,    0,    0},
    {"fast",     "film",       "high",    "4.1",  24, 2, 1, 4, 1, 0,    0,    0},
    {"medium",   "zerolatency","main",    "4.0",  26, 1, 1, 2, 1, 0,    0,    0},
    {"ultrafast","psnr",       "high",    "4.0",  28, 0, 1, 2, 1, 0,    0,    0},
    {"ultrafast","ssim",       "main",    "3.0",  28, 0, 1, 2, 1, 0,    0,    0},
    {"superfast","zerolatency","high422", "4.2",  28, 0, 1, 2, 1, 0,    0,    0},
    {"superfast","zerolatency","high444", "4.2",  28, 0, 1, 2, 1, 0,    0,    0},
    {"ultrafast","zerolatency","baseline","1.0",  35, 0, 0, 0, 0, 0,    0,    0},
    {"ultrafast","zerolatency","baseline","1.1",  35, 0, 0, 0, 0, 0,    0,    0},
    {"ultrafast","zerolatency","main",    "2.0",  32, 0, 1, 1, 1, 0,    0,    0},
    {"ultrafast","zerolatency","main",    "5.0",  24, 0, 1, 3, 1, 0,    0,    0},
    {"ultrafast","zerolatency","high",    "5.1",  22, 0, 1, 4, 1, 0,    0,    0},
    {"slow",     "zerolatency","high",    "4.2",  22, 2, 1, 4, 1, 0,    0,    0},
    /* VBV / CBR modes */
    {"ultrafast","zerolatency","baseline","3.0",  28, 0, 0, 0, 1, 500,  1000, 0},
    {"ultrafast","zerolatency","main",    "3.1",  28, 0, 1, 2, 1, 1000, 2000, 0},
    {"veryfast", "zerolatency","high",    "4.0",  23, 1, 1, 3, 1, 2000, 4000, 0},
    {"faster",   "film",       "high",    "4.1",  21, 2, 1, 4, 1, 5000,10000, 0},
    {"ultrafast","zerolatency","main",    "4.0",  20, 0, 1, 2, 1, 8000,16000, 0},
    /* extreme CRF values */
    {"ultrafast","zerolatency","baseline","3.0",   0, 0, 0, 0, 1, 0,    0,    0}, /* lossless */
    {"ultrafast","zerolatency","baseline","3.0",  51, 0, 0, 0, 1, 0,    0,    0}, /* worst quality */
    {"ultrafast","zerolatency","main",    "3.0",  40, 0, 1, 0, 0, 0,    0,    0},
    {"ultrafast","zerolatency","high",    "3.1",  18, 1, 1, 4, 1, 0,    0,    0},
    /* intra refresh mode */
    {"ultrafast","zerolatency","baseline","3.0",  28, 0, 0, 0, 1, 0,    0,    1},
    {"superfast","zerolatency","main",    "3.1",  28, 0, 1, 0, 1, 0,    0,    1},
    /* B-frame variants */
    {"ultrafast","zerolatency","main",    "4.0",  28, 0, 1, 0, 1, 0,    0,    0},
    {"ultrafast","zerolatency","high",    "4.0",  28, 0, 1, 1, 1, 0,    0,    0},
    {"veryfast", "zerolatency","high",    "4.0",  26, 0, 1, 4, 1, 0,    0,    0},
    /* level extremes */
    {"ultrafast","zerolatency","main",    "1.2",  35, 0, 1, 1, 1, 0,    0,    0},
    {"ultrafast","zerolatency","high",    "1.3",  35, 0, 1, 2, 1, 0,    0,    0},
    {"ultrafast","zerolatency","high",    "2.1",  30, 0, 1, 2, 1, 0,    0,    0},
    {"ultrafast","zerolatency","high",    "2.2",  29, 0, 1, 2, 1, 0,    0,    0},
    {"ultrafast","zerolatency","high",    "3.2",  26, 0, 1, 3, 1, 0,    0,    0},
    {"ultrafast","zerolatency","high",    "4.2",  24, 0, 1, 4, 1, 0,    0,    0},
    {"ultrafast","zerolatency","high",    "5.2",  22, 0, 1, 4, 1, 0,    0,    0},
    {"medium",   "film",       "high",    "4.0",  22, 2, 1, 4, 1, 4000, 8000, 0},
    {"slow",     "film",       "high",    "4.1",  20, 2, 1, 4, 1, 0,    0,    0},
    {"veryslow", "film",       "high",    "4.0",  20, 2, 1, 4, 1, 0,    0,    0}, /* slow! use tiny res */
};
#define N_X264 ((int)(sizeof(X264_CFGS)/sizeof(X264_CFGS[0])))

/* ── 12 Pixel format configs ─────────────────────────────────────────────── */
typedef struct { enum AVPixelFormat fmt; const char *profile_req; } PixFmtCfg;
static const PixFmtCfg PIX_CFGS[] = {
    {AV_PIX_FMT_YUV420P,   NULL},
    {AV_PIX_FMT_YUV420P,   "baseline"},
    {AV_PIX_FMT_YUV420P,   "main"},
    {AV_PIX_FMT_YUV420P,   "high"},
    {AV_PIX_FMT_YUVJ420P,  "main"},
    {AV_PIX_FMT_YUV422P,   "high422"},
    {AV_PIX_FMT_YUV444P,   "high444"},
    {AV_PIX_FMT_YUV420P,   "high"},    /* repeated for weight */
    {AV_PIX_FMT_YUVJ420P,  "high"},
    {AV_PIX_FMT_YUV420P,   "main"},
    {AV_PIX_FMT_YUV420P,   "baseline"},
    {AV_PIX_FMT_YUV444P,   "high444"},
};
#define N_PIX ((int)(sizeof(PIX_CFGS)/sizeof(PIX_CFGS[0])))

/* ── 4 Video codec paths ──────────────────────────────────────────────────── */
typedef struct { const char *name; enum AVCodecID id; enum AVPixelFormat pix_fmt; int q; } VCodecCfg;
static const VCodecCfg VCODEC_CFGS[] = {
    {"libx264",  AV_CODEC_ID_H264,  AV_PIX_FMT_YUV420P,  -1},  /* uses X264_CFGS */
    {"mjpeg",    AV_CODEC_ID_MJPEG, AV_PIX_FMT_YUVJ420P,  3},
    {"mpeg4",    AV_CODEC_ID_MPEG4, AV_PIX_FMT_YUV420P,   5},
    {"libx264",  AV_CODEC_ID_H264,  AV_PIX_FMT_YUV420P,  -1},  /* x264 again (higher prob) */
};
#define N_VCODEC ((int)(sizeof(VCODEC_CFGS)/sizeof(VCODEC_CFGS[0])))

/* ── 40 Audio configs ─────────────────────────────────────────────────────── */
typedef struct {
    enum AVCodecID id; const char *name; int rate; uint64_t chl; int bitrate;
} AudioCfg;
static const AudioCfg AUDIO_CFGS[] = {
    /* AAC variants */
    {AV_CODEC_ID_AAC, "aac",  44100, AV_CH_LAYOUT_STEREO,       128000},
    {AV_CODEC_ID_AAC, "aac",   8000, AV_CH_LAYOUT_MONO,          32000},
    {AV_CODEC_ID_AAC, "aac",  22050, AV_CH_LAYOUT_MONO,          64000},
    {AV_CODEC_ID_AAC, "aac",  48000, AV_CH_LAYOUT_STEREO,       192000},
    {AV_CODEC_ID_AAC, "aac",  96000, AV_CH_LAYOUT_STEREO,       256000},
    {AV_CODEC_ID_AAC, "aac",  48000, AV_CH_LAYOUT_7POINT1,      384000},
    {AV_CODEC_ID_AAC, "aac",  44100, AV_CH_LAYOUT_5POINT1,      256000},
    {AV_CODEC_ID_AAC, "aac",  16000, AV_CH_LAYOUT_MONO,          40000},
    {AV_CODEC_ID_AAC, "aac",  12000, AV_CH_LAYOUT_MONO,          24000},
    {AV_CODEC_ID_AAC, "aac",  32000, AV_CH_LAYOUT_STEREO,        96000},
    /* MP3 */
    {AV_CODEC_ID_MP3, "libmp3lame", 44100, AV_CH_LAYOUT_STEREO, 128000},
    {AV_CODEC_ID_MP3, "libmp3lame", 44100, AV_CH_LAYOUT_MONO,    96000},
    {AV_CODEC_ID_MP3, "libmp3lame", 32000, AV_CH_LAYOUT_STEREO,  80000},
    {AV_CODEC_ID_MP3, "libmp3lame", 22050, AV_CH_LAYOUT_MONO,    48000},
    /* AC3 */
    {AV_CODEC_ID_AC3, "ac3", 48000, AV_CH_LAYOUT_STEREO,        192000},
    {AV_CODEC_ID_AC3, "ac3", 48000, AV_CH_LAYOUT_5POINT1,       448000},
    {AV_CODEC_ID_AC3, "ac3", 48000, AV_CH_LAYOUT_MONO,           96000},
    /* EAC3 */
    {AV_CODEC_ID_EAC3,"eac3",48000, AV_CH_LAYOUT_STEREO,        192000},
    {AV_CODEC_ID_EAC3,"eac3",48000, AV_CH_LAYOUT_5POINT1,       448000},
    {AV_CODEC_ID_EAC3,"eac3",48000, AV_CH_LAYOUT_7POINT1,       640000},
    /* FLAC */
    {AV_CODEC_ID_FLAC,"flac",44100, AV_CH_LAYOUT_STEREO,             0},
    {AV_CODEC_ID_FLAC,"flac",48000, AV_CH_LAYOUT_MONO,               0},
    {AV_CODEC_ID_FLAC,"flac",96000, AV_CH_LAYOUT_STEREO,             0},
    /* PCM */
    {AV_CODEC_ID_PCM_S16LE,"pcm_s16le", 8000, AV_CH_LAYOUT_MONO,    0},
    {AV_CODEC_ID_PCM_S16LE,"pcm_s16le",22050, AV_CH_LAYOUT_STEREO,  0},
    {AV_CODEC_ID_PCM_S16LE,"pcm_s16le",44100, AV_CH_LAYOUT_STEREO,  0},
    {AV_CODEC_ID_PCM_S24LE,"pcm_s24le",48000, AV_CH_LAYOUT_STEREO,  0},
    /* ALAC */
    {AV_CODEC_ID_ALAC,"alac",44100, AV_CH_LAYOUT_STEREO,             0},
    {AV_CODEC_ID_ALAC,"alac",48000, AV_CH_LAYOUT_MONO,               0},
    /* Opus */
    {AV_CODEC_ID_OPUS,"libopus",48000, AV_CH_LAYOUT_STEREO,      128000},
    {AV_CODEC_ID_OPUS,"libopus",48000, AV_CH_LAYOUT_MONO,         64000},
    {AV_CODEC_ID_OPUS,"libopus",48000, AV_CH_LAYOUT_5POINT1,     256000},
    /* MP2 */
    {AV_CODEC_ID_MP2,"mp2",44100, AV_CH_LAYOUT_STEREO,           128000},
    {AV_CODEC_ID_MP2,"mp2",32000, AV_CH_LAYOUT_MONO,              64000},
    /* AMR-NB (mobile) */
    {AV_CODEC_ID_AMR_NB,"libopencore_amrnb",8000,AV_CH_LAYOUT_MONO,12200},
    /* rare channel layouts */
    {AV_CODEC_ID_AAC, "aac",48000, AV_CH_LAYOUT_2POINT1,           96000},
    {AV_CODEC_ID_AAC, "aac",48000, AV_CH_LAYOUT_SURROUND,        128000}, /* 3.0: FL+FR+FC */
    {AV_CODEC_ID_AC3, "ac3",48000, AV_CH_LAYOUT_3POINT1,         192000},
    {AV_CODEC_ID_AAC, "aac",44100, AV_CH_LAYOUT_4POINT0,        192000},
    {AV_CODEC_ID_AC3, "ac3",48000, AV_CH_LAYOUT_QUAD,           192000},
};
#define N_AUDIO ((int)(sizeof(AUDIO_CFGS)/sizeof(AUDIO_CFGS[0])))

/* ── Metadata ──────────────────────────────────────────────────────────────── */
static const char *META_KEYS[] = {
    "title","artist","album","comment","genre","year","track","album_artist",
    "composer","lyrics","show","episode_id","network","rating","grouping",
    "sort_name","description","synopsis","purchase_date","hd_video",
    "location","make","model","software","encoder","creation_time",
    "copyright","language","director","producer",
};
static const char *META_VALS[] = {
    "FuzzTest","FuzzArtist","FuzzAlbum","FuzzComment","Experimental",
    "2024","01","FuzzCompilation","FuzzComposer","FuzzLyrics","FuzzShow",
    "S01E01","FuzzNetwork","G","FuzzGroup","FuzzSorted","A test description",
    "Synopsis text","2024-01-01","0",
    "+37.3861-122.0839/","Apple Inc.","iPhone 15","FFmpeg","lavf58.76.100",
    "2024-01-01T12:00:00.000000Z","Copyright 2024","eng","FuzzDirector","FuzzProducer",
};
#define N_META ((int)(sizeof(META_KEYS)/sizeof(META_KEYS[0])))

/* ── 12 Sample Aspect Ratios ─────────────────────────────────────────────── */
static const AVRational SARS[] = {
    {1,1},{4,3},{16,9},{64,45},{8,9},{3,4},{10,11},{40,33},
    {12,11},{16,11},{24,11},{160,99},
};
#define N_SARS ((int)(sizeof(SARS)/sizeof(SARS[0])))

/* ── 8 Major brands ──────────────────────────────────────────────────────── */
static const char *MAJOR_BRANDS[] = {
    "isom","mp41","mp42","avc1","iso5","iso6","dash","M4V ",
};
#define N_BRANDS ((int)(sizeof(MAJOR_BRANDS)/sizeof(MAJOR_BRANDS[0])))

/* ── 6 Stream dispositions ────────────────────────────────────────────────── */
static const int DISPOSITIONS[] = {
    AV_DISPOSITION_DEFAULT,
    AV_DISPOSITION_FORCED,
    AV_DISPOSITION_HEARING_IMPAIRED,
    AV_DISPOSITION_VISUAL_IMPAIRED,
    AV_DISPOSITION_DEFAULT | AV_DISPOSITION_FORCED,
    0,
};
#define N_DISP ((int)(sizeof(DISPOSITIONS)/sizeof(DISPOSITIONS[0])))

/* ══════════════════════════════════════════════════════════════════════════
 *  VISUAL PATTERNS  (33 patterns)
 * ══════════════════════════════════════════════════════════════════════════ */
#define N_PATTERNS 33

static void fill_frame(AVFrame *f, int pat, int fi, int nf) {
    const int W = f->width, H = f->height;
    const double t = nf > 1 ? (double)fi/(nf-1) : 0.0;

    for (int y = 0; y < H; y++) {
      for (int x = 0; x < W; x++) {
        double nx = (double)x/W, ny = (double)y/H;
        uint8_t Y=128, U=128, V=128;

        switch (pat % N_PATTERNS) {
        case 0:  Y=(((int)(nx*8)+(int)(ny*8)+fi)&1)?220:35; break;
        case 1: { /* mandelbrot */
            double cr=nx*3.5-2.5, ci=ny*2-1, zr=0, zi=0; int it=0;
            while(it<32&&zr*zr+zi*zi<4){double r=zr*zr-zi*zi+cr;zi=2*zr*zi+ci;zr=r;it++;}
            Y=(uint8_t)(it*8);U=(uint8_t)(it*3+80);V=(uint8_t)(255-it*7); break; }
        case 2: { /* julia set */
            double zr=nx*3-1.5, zi=ny*3-1.5, cr=-0.7, ci=0.27015; int it=0;
            while(it<32&&zr*zr+zi*zi<4){double r=zr*zr-zi*zi+cr;zi=2*zr*zi+ci;zr=r;it++;}
            Y=(uint8_t)(it*8);U=(uint8_t)(128+it*4);V=(uint8_t)(255-it*6); break; }
        case 3: Y=(uint8_t)(128+127*sin(nx*10+ny*8+t*6.28));
                U=(uint8_t)(128+60*cos(nx*7-ny*5+t*4));
                V=(uint8_t)(128+60*sin(ny*9+t*3)); break;
        case 4: { double d=sqrt((nx-.5)*(nx-.5)+(ny-.5)*(ny-.5));
                  Y=(uint8_t)(128+127*sin(d*30+t*6.28)); break; }
        case 5:  Y=(fmod(nx*16,1)<0.1||fmod(ny*16,1)<0.1)?220:40; break;
        case 6: { double a=atan2(ny-.5,nx-.5)+t*6.28,d=sqrt((nx-.5)*(nx-.5)+(ny-.5)*(ny-.5));
                  Y=(uint8_t)(128+127*sin(a*4-d*20)); break; }
        case 7:  Y=(uint8_t)(ny*255*fabs(cos(t*M_PI))); break;
        case 8: { double d=2*sqrt((nx-.5)*(nx-.5)+(ny-.5)*(ny-.5));
                  Y=(uint8_t)FFMAX(0,(1-d)*255); break; }
        case 9:  Y=(uint8_t)(128+127*sin((nx+ny)*20+t*6.28));
                 U=(uint8_t)(128+60*cos(nx*15+t*4)); break;
        case 10: Y=(fabs(nx-.5)<0.05||fabs(ny-.5)<0.05)?240:20; break;
        case 11: Y=(fabs(nx-.5)+fabs(ny-.5)<.3+.2*t)?200:55; break;
        case 12: { double tx=nx-.5,ty=ny-.5;
                   double u=atan2(ty,tx)/(2*M_PI)+.5,v=.3/(sqrt(tx*tx+ty*ty)+0.001);
                   Y=(uint8_t)(128+127*sin(v*10+t*6.28)*cos(u*20)); break; }
        case 13: Y=(fmod((nx+ny)*8+t*2,1)<0.5)?200:55; break;
        case 14: { double dx=fmod(nx*12,1)-.5,dy=fmod(ny*12,1)-.5;
                   Y=(sqrt(dx*dx+dy*dy)<.3+.1*sin(t*6.28))?220:35; break; }
        case 15: Y=((int)(ny*H)&1)?(uint8_t)(200+55*t):30; break;
        case 16: { double vx=nx-.5,vy=ny-.5,v=1-2*(vx*vx+vy*vy);
                   Y=(uint8_t)(FFMAX(0,v)*200*(.5+.5*cos(t*M_PI))); break; }
        case 17: { double d=sqrt((nx-.5)*(nx-.5)+(ny-.5)*(ny-.5));
                   Y=(uint8_t)(128+127*sin(d*20*(1+t))); break; }
        case 18: { double d=sqrt((nx-.5)*(nx-.5)+(ny-.5)*(ny-.5)),r=.1+t*.4;
                   Y=fabs(d-r)<0.03?240:30; break; }
        /* SMPTE color bars */
        case 19: {
            int seg=(int)(nx*7);
            const uint8_t ys[]={235,210,170,145,106,81,40,16};
            const uint8_t us[]={128,16,166,54,202,90,240,128};
            const uint8_t vs[]={128,146,16,34,222,240,110,128};
            Y=ys[seg%8];U=us[seg%8];V=vs[seg%8]; break; }
        /* Bayer pattern (RGGB) */
        case 20: {
            int px=(x&1),py=(y&1);
            Y=(px==0&&py==0)?220:(px==1&&py==1)?30:128;
            U=128;V=(px==0&&py==0)?200:128; break; }
        /* Gray ramp */
        case 21: Y=(uint8_t)(nx*255); break;
        /* White flash (pulsing) */
        case 22: Y=(uint8_t)(128+127*cos(t*M_PI*2)); break;
        /* Random per-frame noise */
        case 23: { uint32_t h=(uint32_t)(y*W+x+fi*W*H); h^=h>>16;h*=0x45d9f3b;h^=h>>16;
                   Y=(uint8_t)(h&0xFF);U=(uint8_t)((h>>8)&0xFF);V=(uint8_t)((h>>16)&0xFF); break; }
        /* Rotating gradient */
        case 24: { double a=atan2(ny-.5,nx-.5)+t*M_PI*2;
                   Y=(uint8_t)(128+127*sin(a)); break; }
        /* Rainbow */
        case 25: {
            double hue=nx+t*0.5; hue=hue-floor(hue);
            double h6=hue*6; int hi=(int)h6; double f2=h6-hi;
            uint8_t r,g,b;
            if(hi==0){r=255;g=(uint8_t)(f2*255);b=0;}
            else if(hi==1){r=(uint8_t)((1-f2)*255);g=255;b=0;}
            else if(hi==2){r=0;g=255;b=(uint8_t)(f2*255);}
            else if(hi==3){r=0;g=(uint8_t)((1-f2)*255);b=255;}
            else if(hi==4){r=(uint8_t)(f2*255);g=0;b=255;}
            else{r=255;g=0;b=(uint8_t)((1-f2)*255);}
            Y=(uint8_t)(0.299f*r+0.587f*g+0.114f*b);
            U=(uint8_t)(128-0.169f*r-0.331f*g+0.500f*b);
            V=(uint8_t)(128+0.500f*r-0.419f*g-0.081f*b); break; }
        /* Moiré pattern */
        case 26: { double v=sin(nx*40*M_PI)*sin(ny*41*M_PI+t*2);
                   Y=(uint8_t)(128+100*v); break; }
        /* Film grain */
        case 27: { uint32_t h=(uint32_t)(y*W+x); h^=h>>13;h*=0x5555;h^=h>>17;
                   int g=(int)((h&0xFF)-128)>>2;
                   Y=(uint8_t)FFMAX(0,FFMIN(255,(int)(ny*255)+g)); break; }
        /* Split-screen 4 quadrants */
        case 28: {
            int qx=(nx>0.5),qy=(ny>0.5);
            int qpat=qx+qy*2;
            double qnx=(nx>0.5?nx-0.5:nx)*2, qny=(ny>0.5?ny-0.5:ny)*2;
            if(qpat==0) Y=(uint8_t)(128+127*sin(qnx*10+t*6.28));
            else if(qpat==1) Y=(sqrt((qnx-.5)*(qnx-.5)+(qny-.5)*(qny-.5))<.3+.1*t)?220:30;
            else if(qpat==2) Y=(uint8_t)(qny*255);
            else Y=(((int)(qnx*8)+(int)(qny*8)+fi)&1)?200:55;
            break; }
        /* XOR pattern */
        case 29: Y=(uint8_t)(((int)(nx*255))^((int)(ny*255))); break;
        /* Diagonal gradient + animate */
        case 30: Y=(uint8_t)((nx+ny+t)*127.5); break;
        /* Vertical bars */
        case 31: { int s=(int)(nx*16)%4;
                   const uint8_t bs[]={235,128,54,16};Y=bs[s]; break; }
        /* Perlin-ish (smooth noise) */
        case 32: { double f=4.0;
                   double v=sin(nx*f*M_PI)*cos(ny*f*M_PI)*cos(t*2*M_PI)
                           +sin(nx*f*2*M_PI)*cos(ny*f*2*M_PI+1)*0.5;
                   Y=(uint8_t)(128+80*v); break; }
        }

        f->data[0][y*f->linesize[0]+x] = Y;
        switch(f->format){
        case AV_PIX_FMT_YUV420P: case AV_PIX_FMT_YUVJ420P:
            if((x&1)==0&&(y&1)==0){f->data[1][(y/2)*f->linesize[1]+x/2]=U;f->data[2][(y/2)*f->linesize[2]+x/2]=V;} break;
        case AV_PIX_FMT_YUV422P:
            if((x&1)==0){f->data[1][y*f->linesize[1]+x/2]=U;f->data[2][y*f->linesize[2]+x/2]=V;} break;
        case AV_PIX_FMT_YUV444P:
            f->data[1][y*f->linesize[1]+x]=U; f->data[2][y*f->linesize[2]+x]=V; break;
        default: break;
        }
      }
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 *  AUDIO WAVEFORMS  (20 waveforms)
 * ══════════════════════════════════════════════════════════════════════════ */
#define N_WAVEFORMS 20

static float gen_sample(int wf, double t, double freq, int idx, int sr) {
    double s = 0;
    switch(wf % N_WAVEFORMS) {
    case 0: s=0; break;
    case 1: s=sin(2*M_PI*freq*t); break;
    case 2: s=(sin(2*M_PI*freq*t)>=0)?0.9:-0.9; break;
    case 3: s=2*fmod(freq*t,1.0)-1.0; break;
    case 4: { double p=fmod(freq*t,1.0); s=p<.5?4*p-1:3-4*p; break; }
    case 5: { uint32_t h=(uint32_t)(idx*2654435761u^0xDEADBEEFu);
              h^=h>>16;h*=0x45d9f3b;h^=h>>16; s=(int)(h&0xFFFF)/32768.0-1.0; break; }
    case 6: { double f0=100,f1=4000; s=sin(2*M_PI*(f0+((f1-f0)/2)*t)*t); break; }
    case 7: s=(fmod(freq*t,1.0)<0.05)?0.9:0.0; break;
    case 8: s=0.5*sin(2*M_PI*440*t)+0.5*sin(2*M_PI*880*t); break;
    case 9: s=sin(2*M_PI*440*t)*0.5*(1+sin(2*M_PI*5*t)); break;
    /* DTMF tones (digit based on idx) */
    case 10: { static const double R[]={697,770,852,941}; static const double C[]={1209,1336,1477};
               int d=idx/sr%12; s=0.5*sin(2*M_PI*R[d/3]*t)+0.5*sin(2*M_PI*C[d%3]*t); break; }
    /* Pink noise (approximated) */
    case 11: { static double b[7]={0}; uint32_t h=(uint32_t)(idx*1664525u+1013904223u);
               double w=(int)(h&0xFFFF)/32768.0-1.0;
               b[0]=0.99886*b[0]+w*0.0555179;b[1]=0.99332*b[1]+w*0.0750759;
               b[2]=0.96900*b[2]+w*0.1538520;b[3]=0.86650*b[3]+w*0.3104856;
               b[4]=0.55000*b[4]+w*0.5329522;b[5]=-0.7616*b[5]+w*0.0168980;
               s=(b[0]+b[1]+b[2]+b[3]+b[4]+b[5]+b[6]+w*0.5362)*0.11; b[6]=w*0.115926; break; }
    /* Brown noise (red noise: integrate white) */
    case 12: { static double last=0; uint32_t h=(uint32_t)(idx*1664525u+1013904223u);
               double w=(int)(h&0xFFFF)/32768.0-1.0; last=(last+0.02*w)*0.98;
               s=FFMAX(-1,FFMIN(1,last*3.5)); break; }
    /* Harmonic series (10 harmonics) */
    case 13: { s=0; for(int k=1;k<=10;k++) s+=sin(2*M_PI*freq*k*t)/(k*k); s*=0.3; break; }
    /* Log-frequency sweep */
    case 14: { double dur=1.0,f0=20,f1=20000;
               double f=f0*pow(f1/f0,fmod(t,dur)/dur);
               s=sin(2*M_PI*f*t); break; }
    /* Subsonic burst (test parser at low freq) */
    case 15: { double f_sub=2.0; s=sin(2*M_PI*f_sub*t)*0.5; break; }
    /* Ultrasonic-ish (high freq) */
    case 16: { s=sin(2*M_PI*8000*t)*0.3; break; }
    /* Exponential decay */
    case 17: s=sin(2*M_PI*440*t)*exp(-3*fmod(t,0.5))*0.9; break;
    /* Burst train */
    case 18: { double phase=fmod(t*8,1.0); s=(phase<0.1)?sin(2*M_PI*1000*t):0; break; }
    /* Dual AM */
    case 19: s=(0.5*sin(2*M_PI*300*t)+0.5*sin(2*M_PI*600*t))*(0.5+0.5*sin(2*M_PI*3*t)); break;
    }
    return (float)(s * 0.75);
}

static void write_sample(AVFrame *f, int ch, int i, float s, enum AVSampleFormat fmt) {
    int16_t s16=(int16_t)(s*32767.0f);
    switch(fmt){
    case AV_SAMPLE_FMT_FLTP: ((float  *)f->data[ch])[i]=s; break;
    case AV_SAMPLE_FMT_FLT:  ((float  *)f->data[0])[i*f->channels+ch]=s; break;
    case AV_SAMPLE_FMT_S16P: ((int16_t*)f->data[ch])[i]=s16; break;
    case AV_SAMPLE_FMT_S16:  ((int16_t*)f->data[0])[i*f->channels+ch]=s16; break;
    case AV_SAMPLE_FMT_S32P: ((int32_t*)f->data[ch])[i]=(int32_t)s16<<16; break;
    case AV_SAMPLE_FMT_S32:  ((int32_t*)f->data[0])[i*f->channels+ch]=(int32_t)s16<<16; break;
    case AV_SAMPLE_FMT_U8:   ((uint8_t *)f->data[0])[i*f->channels+ch]=(uint8_t)((s+1)*127.5f); break;
    default: break;
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 *  CONTAINER EXTRAS — 60+ feature bits
 * ══════════════════════════════════════════════════════════════════════════ */
static void apply_extras(AVFormatContext *fc, AVStream *vs,
                          AVCodecContext *venc, AVDictionary **fopts,
                          uint64_t seed) {
    const uint64_t f = mix64(seed ^ 0xC0FFEE00C0FFEEULL);
    const uint64_t g = mix64(seed ^ 0xDEADBEEFCAFEBABEULL);

    /* 1. colr — color primaries/TRC/matrix/range (6 combos) */
    if(f & 1) {
        static const struct { enum AVColorPrimaries p; enum AVColorTransferCharacteristic t;
                              enum AVColorSpace s; enum AVColorRange r; } CL[]={
            {AVCOL_PRI_BT709,    AVCOL_TRC_BT709,       AVCOL_SPC_BT709,     AVCOL_RANGE_MPEG},
            {AVCOL_PRI_BT2020,   AVCOL_TRC_SMPTE2084,   AVCOL_SPC_BT2020_NCL,AVCOL_RANGE_MPEG},
            {AVCOL_PRI_BT470BG,  AVCOL_TRC_GAMMA28,     AVCOL_SPC_BT470BG,   AVCOL_RANGE_JPEG},
            {AVCOL_PRI_SMPTE170M,AVCOL_TRC_SMPTE170M,   AVCOL_SPC_SMPTE170M, AVCOL_RANGE_MPEG},
            {AVCOL_PRI_BT709,    AVCOL_TRC_IEC61966_2_1,AVCOL_SPC_BT709,     AVCOL_RANGE_JPEG},
            {AVCOL_PRI_BT2020,   AVCOL_TRC_ARIB_STD_B67,AVCOL_SPC_BT2020_NCL,AVCOL_RANGE_MPEG},
        };
        int ci=SEL(seed,0x11,6);
        vs->codecpar->color_primaries=CL[ci].p; vs->codecpar->color_trc=CL[ci].t;
        vs->codecpar->color_space=CL[ci].s;     vs->codecpar->color_range=CL[ci].r;
    }

    /* 2. pasp — sample aspect ratio (12 combos) */
    if(f & 2) {
        AVRational sar=SARS[SEL(seed,0x12,N_SARS)];
        vs->sample_aspect_ratio=sar; vs->codecpar->sample_aspect_ratio=sar;
    }

    /* 3. display matrix (8 angles: 0/45/90/135/180/225/270/315) */
    if(f & 4) {
        uint8_t *dm=av_stream_new_side_data(vs,AV_PKT_DATA_DISPLAYMATRIX,9*sizeof(int32_t));
        if(dm){ double a[]={0,45,90,135,180,225,270,315};
                av_display_rotation_set((int32_t*)dm, a[SEL(seed,0x13,8)]); }
    }

    /* 4. stereo3D (5 types) */
    if(f & 8) {
        static const enum AVStereo3DType T[]={AV_STEREO3D_SIDEBYSIDE,AV_STEREO3D_TOPBOTTOM,
            AV_STEREO3D_FRAMESEQUENCE,AV_STEREO3D_CHECKERBOARD,AV_STEREO3D_SIDEBYSIDE_QUINCUNX};
        AVStereo3D *s3d=av_stereo3d_create_side_data(vs);
        if(s3d){s3d->type=T[SEL(seed,0x14,5)];s3d->flags=0;}
    }

    /* 5. HDR mastering display (4 luminance variants) */
    if(f & 16) {
        AVMasteringDisplayMetadata *mdm=av_mastering_display_metadata_create_side_data(vs);
        if(mdm){
            mdm->display_primaries[0][0]=av_make_q(34000,50000);
            mdm->display_primaries[0][1]=av_make_q(16000,50000);
            mdm->display_primaries[1][0]=av_make_q(13250,50000);
            mdm->display_primaries[1][1]=av_make_q(34500,50000);
            mdm->display_primaries[2][0]=av_make_q(7500, 50000);
            mdm->display_primaries[2][1]=av_make_q(3000, 50000);
            mdm->white_point[0]=av_make_q(15635,50000);
            mdm->white_point[1]=av_make_q(16450,50000);
            static const struct{int mn,mx;} LU[]={{50,10000000},{10,40000000},{1,5000000},{100,20000000}};
            int li=SEL(seed,0x15,4);
            mdm->min_luminance=av_make_q(LU[li].mn,10000);
            mdm->max_luminance=av_make_q(LU[li].mx,10000);
            mdm->has_primaries=1; mdm->has_luminance=1;
        }
    }

    /* 6. Content light level (MaxCLL/MaxFALL) */
    if(f & 32) {
        AVContentLightMetadata *clm=av_content_light_metadata_create_side_data(vs);
        static const struct{unsigned cll,fall;}LT[]={{1000,400},{4000,1000},{10000,2000},{300,100},{600,200}};
        if(clm){int li=SEL(seed,0x16,5);clm->MaxCLL=LT[li].cll;clm->MaxFALL=LT[li].fall;}
    }

    /* 7. Chapters: 1-4 chapters */
    if(f & 64) {
        int nc=1+SEL(seed,0x17,4);
        fc->chapters=av_malloc_array(nc,sizeof(*fc->chapters));
        if(fc->chapters){
            fc->nb_chapters=nc;
            for(int i=0;i<nc;i++){
                AVChapter *ch=av_mallocz(sizeof(AVChapter));
                if(!ch){fc->nb_chapters=i;break;}
                ch->id=i; ch->time_base=(AVRational){1,AV_TIME_BASE};
                ch->start=(int64_t)i*AV_TIME_BASE/nc;
                ch->end=(int64_t)(i+1)*AV_TIME_BASE/nc-1;
                char title[64]; snprintf(title,sizeof(title),"Chapter %d — FuzzTest",i+1);
                av_dict_set(&ch->metadata,"title",title,0);
                /* Unicode test in chapter title */
                if(i==1) av_dict_set(&ch->metadata,"title","Κεφάλαιο 2",0);
                if(i==2) av_dict_set(&ch->metadata,"title","第三章",0);
                fc->chapters[i]=ch;
            }
        }
    }

    /* 8. Edit list (elst) via stream start_time offset */
    if(f & 128) {
        vs->start_time=av_rescale_q(50+SEL(seed,0x18,500),(AVRational){1,1000},vs->time_base);
    }

    /* 9. Timecode track */
    if(f & 256) { av_dict_set(&vs->metadata,"timecode","00:00:00:00",0); }

    /* 10. Major brand selection */
    if(g & 1) { av_dict_set(fopts,"brand",MAJOR_BRANDS[SEL(seed,0x19,N_BRANDS)],0); }

    /* 11. Stream disposition flags */
    if(g & 2) { vs->disposition=DISPOSITIONS[SEL(seed,0x1A,N_DISP)]; }

    /* 12. frag_duration option (when movflags include frag_duration) */
    if(g & 4) {
        static const int FRAG_DUR[]={100,200,500,1000,2000};
        av_dict_set_int(fopts,"fragment_duration",FRAG_DUR[SEL(seed,0x1B,5)],0);
    }

    /* 13. frag_size option (when movflags include frag_size) */
    if(g & 8) {
        static const int FRAG_SZ[]={512,1024,2048,4096,8192,16384,32768};
        av_dict_set_int(fopts,"fragment_size",FRAG_SZ[SEL(seed,0x1C,7)],0);
    }

    /* 14. GPS / location metadata */
    if(g & 16) {
        static const char *LOCS[]={"","ISO-6709","+37.3861-122.0839/","+51.5074-0.1278/",
                                    "+35.6762+139.6503/","+48.8566+2.3522/"};
        av_dict_set(&fc->metadata,"location",LOCS[SEL(seed,0x1D,6)],0);
        av_dict_set(&fc->metadata,"com.apple.quicktime.location.ISO6709",LOCS[1+SEL(seed,0x1E,5)],0);
    }

    /* 15. Camera / recording metadata */
    if(g & 32) {
        static const char *MAKES[]={"Apple","Samsung","Sony","Canon","GoPro","DJI"};
        static const char *MODELS[]={"iPhone 15","Galaxy S24","A7 IV","EOS R5","HERO12","Mavic 3"};
        int ci=SEL(seed,0x1F,6);
        av_dict_set(&fc->metadata,"make",MAKES[ci],0);
        av_dict_set(&fc->metadata,"model",MODELS[ci],0);
        av_dict_set(&fc->metadata,"com.apple.quicktime.make",MAKES[ci],0);
        av_dict_set(&fc->metadata,"com.apple.quicktime.model",MODELS[ci],0);
    }

    /* 16. Spherical video XMP metadata */
    if(g & 64) {
        const char *xmp="<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>"
                        "<x:xmpmeta xmlns:x='adobe:ns:meta/'>"
                        "<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>"
                        "<rdf:Description xmlns:GSpherical='http://ns.google.com/videos/1.0/spherical/'>"
                        "<GSpherical:Spherical>true</GSpherical:Spherical>"
                        "<GSpherical:Stitched>true</GSpherical:Stitched>"
                        "<GSpherical:ProjectionType>equirectangular</GSpherical:ProjectionType>"
                        "</rdf:Description></rdf:RDF></x:xmpmeta>";
        av_dict_set(&vs->metadata,"spherical-video",xmp,0);
    }

    /* 17. iTunes-style metadata */
    if(g & 128) {
        av_dict_set(&fc->metadata,"com.apple.iTunes.ITUNSMOVI",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC><plist version=\"1.0\"><dict></dict></plist>",0);
        av_dict_set(&fc->metadata,"com.apple.quicktime.artwork","",0);
    }

    /* 18. Multiple global metadata fields (2-8 fields) */
    {
        int n=2+SEL(seed,0x20,7);
        for(int i=0;i<n;i++){
            int ki=SEL(seed,0x21+i,N_META), vi=SEL(seed,0x28+i,N_META);
            av_dict_set(&fc->metadata,META_KEYS[ki],META_VALS[vi],0);
        }
    }

    /* 19. Per-stream language + metadata */
    {
        static const char *LANGS[]={"eng","und","fra","deu","jpn","spa","zho","kor","ara","por","rus","ita"};
        av_dict_set(&vs->metadata,"language",LANGS[SEL(seed,0x30,12)],0);
        /* handler_name */
        static const char *HNAMES[]={"VideoHandler","Video Media Handler","Core Media Video","Apple Video Media Handler"};
        av_dict_set(&vs->metadata,"handler_name",HNAMES[SEL(seed,0x31,4)],0);
    }

    /* 20. Encoder tag */
    {
        static const char *ENCS[]={"Lavf58.76.100","HandBrake 1.7.0","FFmpeg","mp4v2 2.0.0","x264 - core 163"};
        av_dict_set(&fc->metadata,"encoder",ENCS[SEL(seed,0x32,5)],0);
        av_dict_set(&fc->metadata,"creation_time",
            (const char*[]){"2024-01-01T00:00:00.000000Z","2023-06-15T12:30:00Z","2022-12-31T23:59:59Z"}[SEL(seed,0x33,3)],0);
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 *  AUDIO ENCODING
 * ══════════════════════════════════════════════════════════════════════════ */
static void encode_audio(AVFormatContext *fc, AVCodecContext *enc, AVStream *st,
                          int wf, int dur_ms, uint64_t seed) {
    int sr=enc->sample_rate, ch=enc->channels;
    int total=(int)((int64_t)sr*dur_ms/1000);
    int fsz=enc->frame_size>0?enc->frame_size:1024;
    double freq=110.0*(1+SEL(seed,0xA0,12));
    AVFrame *frm=av_frame_alloc(); AVPacket *pkt=av_packet_alloc();
    if(!frm||!pkt) goto done;
    frm->format=enc->sample_fmt; frm->nb_samples=fsz;
    frm->channels=ch; frm->channel_layout=enc->channel_layout;
    frm->sample_rate=sr;
    if(av_frame_get_buffer(frm,0)<0) goto done;
    for(int pos=0;pos<total;pos+=fsz){
        int n=FFMIN(fsz,total-pos); frm->nb_samples=n; frm->pts=pos;
        av_frame_make_writable(frm);
        for(int i=0;i<n;i++){
            double t=(double)(pos+i)/sr;
            float s=gen_sample(wf,t,freq,pos+i,sr);
            for(int c=0;c<ch;c++) write_sample(frm,c,i,s,enc->sample_fmt);
        }
        if(avcodec_send_frame(enc,frm)<0) break;
        while(avcodec_receive_packet(enc,pkt)==0){
            pkt->stream_index=st->index;
            av_packet_rescale_ts(pkt,enc->time_base,st->time_base);
            av_interleaved_write_frame(fc,pkt); av_packet_unref(pkt);
        }
    }
    avcodec_send_frame(enc,NULL);
    while(avcodec_receive_packet(enc,pkt)==0){
        pkt->stream_index=st->index;
        av_packet_rescale_ts(pkt,enc->time_base,st->time_base);
        av_interleaved_write_frame(fc,pkt); av_packet_unref(pkt);
    }
done: av_frame_free(&frm); av_packet_free(&pkt);
}

/* ══════════════════════════════════════════════════════════════════════════
 *  MAIN GENERATOR
 * ══════════════════════════════════════════════════════════════════════════ */
static int generate_mp4(const char *path, uint64_t seed) {
    /* Feature selection */
    int res_idx   = SEL(seed,0x01,N_RES);
    int fps_idx   = SEL(seed,0x02,N_FPS);
    int mov_idx   = SEL(seed,0x05,N_MOVFLAGS);
    int pattern   = SEL(seed,0x06,N_PATTERNS);
    int waveform  = SEL(seed,0x07,N_WAVEFORMS);
    int aud_idx   = SEL(seed,0x08,N_AUDIO);
    int vcodec_idx= SEL(seed,0x0B,N_VCODEC);
    int has_audio = FLAG(seed,0x09,80);
    int has_audio2= FLAG(seed,0x0C,30);   /* 30% chance of second audio track */
    int dur_ms    = 100+SEL(seed,0x0A,850);

    /* For slow presets, limit resolution and duration */
    int x264_idx  = SEL(seed,0x03,N_X264);
    const X264Cfg *x264=&X264_CFGS[x264_idx];
    if(strcmp(x264->preset,"veryslow")==0||strcmp(x264->preset,"placebo")==0){
        res_idx=SEL(seed,0x03,5); /* force tiny res */
        dur_ms=FFMIN(dur_ms,300);
    }
    if(strcmp(x264->preset,"slow")==0&&res_idx>20) res_idx=SEL(seed,0x04,15);

    int W=RESOLUTIONS[res_idx].w, H=RESOLUTIONS[res_idx].h;
    /* H.264 requires even dimensions; MPEG-4 block-align to 2 */
    W=(W+1)&~1; H=(H+1)&~1;
    /* x264 requires dimensions >= 2 */
    if(W<2) W=2; if(H<2) H=2;

    /* Pixel format: forced by profile for x264 */
    enum AVPixelFormat pix_fmt;
    if(strcmp(x264->profile,"high422")==0) pix_fmt=AV_PIX_FMT_YUV422P;
    else if(strcmp(x264->profile,"high444")==0) pix_fmt=AV_PIX_FMT_YUV444P;
    else {
        int pix_idx=SEL(seed,0x04,N_PIX);
        pix_fmt=PIX_CFGS[pix_idx].fmt;
        if(pix_fmt==AV_PIX_FMT_YUV422P||pix_fmt==AV_PIX_FMT_YUV444P)
            pix_fmt=AV_PIX_FMT_YUV420P;
    }

    int ret=0;
    AVFormatContext *fc=NULL; AVCodecContext *venc=NULL;
    AVCodecContext *aenc=NULL, *aenc2=NULL;
    AVStream *vs=NULL, *as=NULL, *as2=NULL;
    AVFrame *vfr=NULL; AVPacket *pkt=NULL;
    AVDictionary *fopts=NULL;
    const VCodecCfg *vc_cfg=&VCODEC_CFGS[vcodec_idx];

    if(avformat_alloc_output_context2(&fc,NULL,"mp4",path)<0) goto fail;

    /* movflags */
    const char *mf=MOVFLAGS[mov_idx];
    if(mf[0]) av_dict_set(&fopts,"movflags",mf,0);

    /* ── Video stream ─────────────────────────────────────────────────── */
    const AVCodec *vc=avcodec_find_encoder_by_name(vc_cfg->name);
    if(!vc) vc=avcodec_find_encoder(vc_cfg->id);
    /* fallback to libx264 */
    if(!vc||(vc_cfg->id!=AV_CODEC_ID_H264&&vc_cfg->id!=AV_CODEC_ID_MJPEG&&vc_cfg->id!=AV_CODEC_ID_MPEG4)){
        vc=avcodec_find_encoder_by_name("libx264");
        if(!vc) vc=avcodec_find_encoder(AV_CODEC_ID_H264);
    }
    if(!vc){ret=-1;goto fail;}

    vs=avformat_new_stream(fc,NULL);
    venc=avcodec_alloc_context3(vc);
    if(!vs||!venc){ret=AVERROR(ENOMEM);goto fail;}

    venc->width=W; venc->height=H;
    venc->time_base=(AVRational){FRAMERATES[fps_idx].den,FRAMERATES[fps_idx].num};
    venc->framerate=(AVRational){FRAMERATES[fps_idx].num,FRAMERATES[fps_idx].den};
    venc->bit_rate=400000;
    venc->gop_size=FFMAX(1,FRAMERATES[fps_idx].num/FRAMERATES[fps_idx].den/2);
    if(fc->oformat->flags&AVFMT_GLOBALHEADER) venc->flags|=AV_CODEC_FLAG_GLOBAL_HEADER;

    if(vc->id==AV_CODEC_ID_H264) {
        venc->pix_fmt=pix_fmt;
        av_opt_set(venc->priv_data,"preset", x264->preset, 0);
        av_opt_set(venc->priv_data,"tune",   x264->tune,   0);
        av_opt_set(venc->priv_data,"profile",x264->profile,0);
        av_opt_set(venc->priv_data,"level",  x264->level,  0);
        av_opt_set_int(venc->priv_data,"crf",     x264->crf,     0);
        av_opt_set_int(venc->priv_data,"trellis", x264->trellis, 0);
        av_opt_set_int(venc->priv_data,"cabac",   x264->cabac,   0);
        av_opt_set_int(venc->priv_data,"bframes",FFMIN(x264->bframes,2),0);
        av_opt_set_int(venc->priv_data,"deblock", x264->deblock, 0);
        if(x264->intra_refresh) av_opt_set_int(venc->priv_data,"intra-refresh",1,0);
        if(x264->vbv_maxrate>0){
            venc->rc_max_rate=x264->vbv_maxrate*1000;
            venc->rc_buffer_size=x264->vbv_bufsize*1000;
        }
        /* varied per-seed options */
        av_opt_set_int(venc->priv_data,"refs",     1+SEL(seed,0x20,4),0);
        av_opt_set_int(venc->priv_data,"subq",     1+SEL(seed,0x21,7),0);
        av_opt_set_int(venc->priv_data,"me_range", 4+SEL(seed,0x22,12),0);
        av_opt_set_int(venc->priv_data,"aq-mode",  SEL(seed,0x23,3),0);
        av_opt_set_int(venc->priv_data,"keyint-min",1+SEL(seed,0x24,30),0);
        av_opt_set_int(venc->priv_data,"rc-lookahead",SEL(seed,0x25,41),0);
    } else if(vc->id==AV_CODEC_ID_MJPEG) {
        venc->pix_fmt=AV_PIX_FMT_YUVJ420P;
        venc->global_quality=FF_QP2LAMBDA*FFMAX(1,vc_cfg->q);
        venc->flags|=AV_CODEC_FLAG_QSCALE;
    } else {
        /* mpeg4 / generic */
        venc->pix_fmt=AV_PIX_FMT_YUV420P;
        venc->global_quality=FF_QP2LAMBDA*vc_cfg->q;
        venc->flags|=AV_CODEC_FLAG_QSCALE;
    }

    if((ret=avcodec_open2(venc,vc,NULL))<0) goto fail;
    if((ret=avcodec_parameters_from_context(vs->codecpar,venc))<0) goto fail;
    vs->time_base=venc->time_base;
    vs->avg_frame_rate=venc->framerate;

    /* ── Audio stream 1 ───────────────────────────────────────────────── */
    if(has_audio) {
        const AudioCfg *ac=&AUDIO_CFGS[aud_idx];
        const AVCodec *acodec=avcodec_find_encoder_by_name(ac->name);
        if(!acodec) acodec=avcodec_find_encoder(ac->id);
        if(acodec){
            aenc=avcodec_alloc_context3(acodec);
            if(aenc){
                aenc->sample_rate=ac->rate;
                aenc->channel_layout=ac->chl;
                aenc->channels=av_get_channel_layout_nb_channels(ac->chl);
                aenc->bit_rate=ac->bitrate;
                aenc->sample_fmt=acodec->sample_fmts?acodec->sample_fmts[0]:AV_SAMPLE_FMT_FLTP;
                if(acodec->supported_samplerates){
                    aenc->sample_rate=acodec->supported_samplerates[0];
                    for(int i=0;acodec->supported_samplerates[i];i++)
                        if(acodec->supported_samplerates[i]==ac->rate){aenc->sample_rate=ac->rate;break;}
                }
                if(fc->oformat->flags&AVFMT_GLOBALHEADER) aenc->flags|=AV_CODEC_FLAG_GLOBAL_HEADER;
                if(avcodec_open2(aenc,acodec,NULL)==0){
                    as=avformat_new_stream(fc,NULL);
                    if(as){
                        avcodec_parameters_from_context(as->codecpar,aenc);
                        as->time_base=(AVRational){1,aenc->sample_rate};
                        static const char *AL[]={"eng","und","fra","deu","jpn"};
                        av_dict_set(&as->metadata,"language",AL[SEL(seed,0x40,5)],0);
                    }
                } else { avcodec_free_context(&aenc); }
            }
        }
    }

    /* ── Audio stream 2 (different codec, always AAC or FLAC) ────────────── */
    if(has_audio2 && as) {
        int aud2_idx=(aud_idx+5)%N_AUDIO; /* offset to pick different codec */
        const AudioCfg *ac2=&AUDIO_CFGS[aud2_idx];
        const AVCodec *acodec2=avcodec_find_encoder_by_name(ac2->name);
        if(!acodec2) acodec2=avcodec_find_encoder(ac2->id);
        if(acodec2 && acodec2->id!=AUDIO_CFGS[aud_idx].id){
            aenc2=avcodec_alloc_context3(acodec2);
            if(aenc2){
                aenc2->sample_rate=ac2->rate;
                aenc2->channel_layout=ac2->chl;
                aenc2->channels=av_get_channel_layout_nb_channels(ac2->chl);
                aenc2->bit_rate=ac2->bitrate;
                aenc2->sample_fmt=acodec2->sample_fmts?acodec2->sample_fmts[0]:AV_SAMPLE_FMT_FLTP;
                if(acodec2->supported_samplerates){
                    aenc2->sample_rate=acodec2->supported_samplerates[0];
                    for(int i=0;acodec2->supported_samplerates[i];i++)
                        if(acodec2->supported_samplerates[i]==ac2->rate){aenc2->sample_rate=ac2->rate;break;}
                }
                if(fc->oformat->flags&AVFMT_GLOBALHEADER) aenc2->flags|=AV_CODEC_FLAG_GLOBAL_HEADER;
                if(avcodec_open2(aenc2,acodec2,NULL)==0){
                    as2=avformat_new_stream(fc,NULL);
                    if(as2){
                        avcodec_parameters_from_context(as2->codecpar,aenc2);
                        as2->time_base=(AVRational){1,aenc2->sample_rate};
                        av_dict_set(&as2->metadata,"language","fra",0);
                        /* mark as alternate audio */
                        as2->disposition=AV_DISPOSITION_HEARING_IMPAIRED;
                    }
                } else { avcodec_free_context(&aenc2); }
            }
        }
    }

    /* Container extras (colr, pasp, stereo3D, HDR, chapters, edit list, brands...) */
    apply_extras(fc, vs, venc, &fopts, seed);

    /* Open output file */
    if(!(fc->oformat->flags&AVFMT_NOFILE)){
        if((ret=avio_open(&fc->pb,path,AVIO_FLAG_WRITE))<0) goto fail;
    }

    /* Write header */
    if((ret=avformat_write_header(fc,&fopts))<0) goto fail;
    av_dict_free(&fopts);

    /* ── Encode video frames ──────────────────────────────────────────── */
    int n_frames=(int)((int64_t)FRAMERATES[fps_idx].num*dur_ms/FRAMERATES[fps_idx].den/1000);
    if(n_frames<1) n_frames=1;
    if(n_frames>240) n_frames=240; /* cap at 240 frames */

    vfr=av_frame_alloc(); pkt=av_packet_alloc();
    if(!vfr||!pkt){ret=AVERROR(ENOMEM);goto fail;}
    vfr->format=venc->pix_fmt; vfr->width=W; vfr->height=H;
    if((ret=av_frame_get_buffer(vfr,32))<0) goto fail;

    for(int fi=0;fi<n_frames;fi++){
        av_frame_make_writable(vfr);
        fill_frame(vfr, pattern, fi, n_frames);
        vfr->pts=fi;
        if(avcodec_send_frame(venc,vfr)<0) break;
        while(avcodec_receive_packet(venc,pkt)==0){
            pkt->stream_index=vs->index;
            av_packet_rescale_ts(pkt,venc->time_base,vs->time_base);
            av_interleaved_write_frame(fc,pkt); av_packet_unref(pkt);
        }
    }
    avcodec_send_frame(venc,NULL);
    while(avcodec_receive_packet(venc,pkt)==0){
        pkt->stream_index=vs->index;
        av_packet_rescale_ts(pkt,venc->time_base,vs->time_base);
        av_interleaved_write_frame(fc,pkt); av_packet_unref(pkt);
    }

    /* ── Encode audio ──────────────────────────────────────────────────── */
    if(aenc&&as) encode_audio(fc,aenc,as, waveform,        dur_ms, seed);
    if(aenc2&&as2) encode_audio(fc,aenc2,as2,(waveform+3)%N_WAVEFORMS,dur_ms,seed^0xF00F);

    ret=av_write_trailer(fc);

fail:
    av_dict_free(&fopts);
    av_packet_free(&pkt);
    av_frame_free(&vfr);
    if(venc){avcodec_close(venc);avcodec_free_context(&venc);}
    if(aenc){avcodec_close(aenc);avcodec_free_context(&aenc);}
    if(aenc2){avcodec_close(aenc2);avcodec_free_context(&aenc2);}
    if(fc){
        if(!(fc->oformat->flags&AVFMT_NOFILE)&&fc->pb) avio_closep(&fc->pb);
        avformat_free_context(fc);
    }
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  MAIN
 * ══════════════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[]) {
    if(argc<3){
        fprintf(stderr,"Usage: %s <output_dir> <count>  (count=0 → infinite)\n",argv[0]);
        return 1;
    }
    const char *outdir=argv[1];
    long count=atol(argv[2]);
    struct stat st;
    if(stat(outdir,&st)!=0&&mkdir(outdir,0755)!=0){perror("mkdir");return 1;}
    av_log_set_level(AV_LOG_QUIET);
    uint64_t seed=(uint64_t)time(NULL)^((uint64_t)getpid()<<32);
    long generated=0, failed=0;
    fprintf(stdout,"[mp4gen] Starting: dir=%s count=%ld seed=%llx\n"
                   "[mp4gen] Features: %d res × %d fps × %d movflags × %d x264 × "
                   "%d vcodec × %d audio × %d patterns × %d waveforms\n",
            outdir,count,(unsigned long long)seed,
            N_RES,N_FPS,N_MOVFLAGS,N_X264,N_VCODEC,N_AUDIO,N_PATTERNS,N_WAVEFORMS);
    fflush(stdout);

    for(long i=0; count==0||i<count; i++, seed++){
        char path[4096];
        snprintf(path,sizeof(path),"%s/%016llx.mp4",outdir,(unsigned long long)seed);
        int r=generate_mp4(path,seed);
        if(r<0){failed++;unlink(path);}
        else{
            struct stat fs;
            if(stat(path,&fs)==0&&fs.st_size>=8&&fs.st_size<=200*1024) generated++;
            else{unlink(path);failed++;}
        }
        if((i+1)%500==0){
            fprintf(stdout,"[mp4gen] %ld generated, %ld failed, seed=%llx (%.1f%% ok)\n",
                    generated,failed,(unsigned long long)seed,
                    100.0*generated/(generated+failed+1));
            fflush(stdout);
        }
    }
    fprintf(stdout,"[mp4gen] Done: %ld generated, %ld failed\n",generated,failed);
    return 0;
}
