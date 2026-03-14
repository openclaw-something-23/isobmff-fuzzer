/*
 * mp4gen.c — ISOBMFF corpus generator using FFmpeg libav* API (v4.4)
 *
 * Generates diverse MP4 files for AFL++ fuzzing. Features:
 *   - 20 resolutions (portrait/square/landscape/tiny/odd)
 *   - 20 frame rates (3..60fps + NTSC drop-frame)
 *   - 23 movflags combos (faststart, frag_keyframe, empty_moov, etc.)
 *   - 20 x264 presets/tunes/profiles/levels
 *   - 6 pixel formats (yuv420p/422p/444p/j420p/422p10le/444p10le)
 *   - 20 audio configs (AAC/MP3/AC3/FLAC/PCM/EAC3/ALAC, 8k-96kHz, mono-7.1)
 *   - 10 audio waveforms (silence/sine/square/saw/triangle/noise/chirp/pulse/dual/AM)
 *   - 18 visual patterns (Mandelbrot/plasma/rings/spiral/tunnel/vignette/etc.)
 *   - Container extras: colr, pasp, display matrix, stereo3D, HDR, chapters, edit list
 *   - 20 metadata keys
 *
 * Usage: mp4gen <output_dir> <count>   (count=0 → infinite)
 *
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

/* ── Pseudo-random mixing ────────────────────────────────────────────────── */
static uint64_t mix64(uint64_t h) {
    h ^= h >> 33; h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}
#define SEL(seed, salt, n)  ((int)(mix64((seed) ^ (uint64_t)(salt)) % (unsigned)(n)))
#define FLAG(seed, salt, p) (mix64((seed) ^ (uint64_t)(salt)) % 100 < (unsigned)(p))

/* ── Feature tables ──────────────────────────────────────────────────────── */

typedef struct { int w, h; } Res;
static const Res RESOLUTIONS[] = {
    /* tiny */  {32,32}, {48,48}, {64,64}, {72,72}, {96,96},
    /* square */  {128,128}, {200,200}, {320,320},
    /* portrait */ {144,256}, {180,320}, {240,426},
    /* QCIF/CIF */ {176,144}, {352,288}, {160,120},
    /* ultrawide */ {256,64}, {512,128},
    /* standard */ {320,240}, {426,240}, {640,360}, {640,480},
};
#define N_RES ((int)(sizeof(RESOLUTIONS)/sizeof(RESOLUTIONS[0])))

typedef struct { int num, den; } FPS;
static const FPS FRAMERATES[] = {
    {1,1}, {2,1}, {3,1}, {4,1}, {6,1}, {7,1}, {8,1}, {9,1},
    {10,1}, {12,1}, {15,1}, {16,1}, {18,1}, {20,1}, {24,1},
    {25,1}, {30,1}, {48,1}, {50,1}, {60,1},
    {24000,1001}, {30000,1001},
};
#define N_FPS ((int)(sizeof(FRAMERATES)/sizeof(FRAMERATES[0])))

/* movflags — all verified to work with mp4 muxer without extra options */
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
};
#define N_MOVFLAGS ((int)(sizeof(MOVFLAGS)/sizeof(MOVFLAGS[0])))

/* x264 configurations */
typedef struct {
    const char *preset, *tune, *profile, *level;
    int crf;
} X264Cfg;
static const X264Cfg X264_CFGS[] = {
    {"ultrafast","zerolatency","baseline","3.0", 28},
    {"ultrafast","zerolatency","main",    "3.1", 28},
    {"ultrafast","fastdecode", "high",    "4.0", 28},
    {"superfast","zerolatency","baseline","2.1", 30},
    {"superfast","fastdecode", "main",    "3.1", 28},
    {"veryfast", "zerolatency","main",    "4.0", 26},
    {"veryfast", "animation",  "high",    "4.1", 25},
    {"faster",   "grain",      "high",    "4.0", 27},
    {"fast",     "film",       "high",    "4.1", 24},
    {"medium",   "zerolatency","main",    "4.0", 26},
    {"ultrafast","psnr",       "high",    "4.0", 28},
    {"ultrafast","ssim",       "main",    "3.0", 28},
    {"superfast","zerolatency","high422", "4.2", 28},
    {"superfast","zerolatency","high444", "4.2", 28},
    {"ultrafast","zerolatency","baseline","1.0", 35},
    {"ultrafast","zerolatency","baseline","1.1", 35},
    {"ultrafast","zerolatency","main",    "2.0", 32},
    {"ultrafast","zerolatency","main",    "5.0", 24},
    {"ultrafast","zerolatency","high",    "5.1", 22},
    {"slow",     "zerolatency","high",    "4.2", 22},
};
#define N_X264 ((int)(sizeof(X264_CFGS)/sizeof(X264_CFGS[0])))

/* pixel format + compatible x264 profile (in order of reliability) */
typedef struct { enum AVPixelFormat fmt; const char *profile_required; } PixFmtCfg;
static const PixFmtCfg PIX_CFGS[] = {
    {AV_PIX_FMT_YUV420P,  NULL},
    {AV_PIX_FMT_YUVJ420P, "main"},
    {AV_PIX_FMT_YUV420P,  "baseline"},
    {AV_PIX_FMT_YUV422P,  "high422"},
    {AV_PIX_FMT_YUV444P,  "high444"},
    {AV_PIX_FMT_YUV420P,  "high"},
};
#define N_PIX ((int)(sizeof(PIX_CFGS)/sizeof(PIX_CFGS[0])))

/* audio codec configs */
typedef struct {
    enum AVCodecID id;
    const char    *encoder_name;
    int            sample_rate;
    uint64_t       ch_layout;
    int            bitrate;
} AudioCfg;
static const AudioCfg AUDIO_CFGS[] = {
    {AV_CODEC_ID_AAC,       "aac",        44100, AV_CH_LAYOUT_STEREO,         128000},
    {AV_CODEC_ID_AAC,       "aac",         8000, AV_CH_LAYOUT_MONO,            32000},
    {AV_CODEC_ID_AAC,       "aac",        22050, AV_CH_LAYOUT_MONO,            64000},
    {AV_CODEC_ID_AAC,       "aac",        48000, AV_CH_LAYOUT_STEREO,         192000},
    {AV_CODEC_ID_AAC,       "aac",        96000, AV_CH_LAYOUT_STEREO,         256000},
    {AV_CODEC_ID_AAC,       "aac",        48000, AV_CH_LAYOUT_7POINT1,        384000},
    {AV_CODEC_ID_MP3,       "libmp3lame", 44100, AV_CH_LAYOUT_STEREO,         128000},
    {AV_CODEC_ID_MP3,       "libmp3lame", 44100, AV_CH_LAYOUT_MONO,            96000},
    {AV_CODEC_ID_AC3,       "ac3",        48000, AV_CH_LAYOUT_STEREO,         192000},
    {AV_CODEC_ID_AC3,       "ac3",        48000, AV_CH_LAYOUT_5POINT1,        448000},
    {AV_CODEC_ID_FLAC,      "flac",       44100, AV_CH_LAYOUT_STEREO,              0},
    {AV_CODEC_ID_FLAC,      "flac",       48000, AV_CH_LAYOUT_MONO,                0},
    {AV_CODEC_ID_PCM_S16LE, "pcm_s16le",  8000,  AV_CH_LAYOUT_MONO,                0},
    {AV_CODEC_ID_PCM_S16LE, "pcm_s16le",  22050, AV_CH_LAYOUT_STEREO,              0},
    {AV_CODEC_ID_PCM_S24LE, "pcm_s24le",  48000, AV_CH_LAYOUT_STEREO,              0},
    {AV_CODEC_ID_ALAC,      "alac",       44100, AV_CH_LAYOUT_STEREO,              0},
    {AV_CODEC_ID_EAC3,      "eac3",       48000, AV_CH_LAYOUT_STEREO,         192000},
    {AV_CODEC_ID_EAC3,      "eac3",       48000, AV_CH_LAYOUT_5POINT1,        448000},
    {AV_CODEC_ID_OPUS,      "libopus",    48000, AV_CH_LAYOUT_STEREO,         128000},
    {AV_CODEC_ID_OPUS,      "libopus",    48000, AV_CH_LAYOUT_MONO,            64000},
};
#define N_AUDIO ((int)(sizeof(AUDIO_CFGS)/sizeof(AUDIO_CFGS[0])))

/* metadata fields */
static const char *META_KEYS[]   = {"title","artist","album","comment","genre","year",
    "track","album_artist","composer","lyrics","show","episode_id","network","rating",
    "grouping","sort_name","description","synopsis","purchase_date","hd_video"};
static const char *META_VALS[]   = {"FuzzTest","FuzzArtist","FuzzAlbum","FuzzComment",
    "Experimental","2024","01","FuzzCompilation","FuzzComposer","FuzzLyrics","FuzzShow",
    "S01E01","FuzzNetwork","G","FuzzGroup","FuzzSorted","A test","Synopsis","2024-01-01","0"};
#define N_META ((int)(sizeof(META_KEYS)/sizeof(META_KEYS[0])))

/* sample aspect ratios */
static const AVRational SARS[] = {{1,1},{4,3},{16,9},{64,45},{8,9},{3,4},{10,11},{40,33}};
#define N_SARS ((int)(sizeof(SARS)/sizeof(SARS[0])))

/* ── Visual pattern generator ────────────────────────────────────────────── */
#define N_PATTERNS 18

static void fill_frame(AVFrame *f, int pat, int fi, int nf) {
    const int W = f->width, H = f->height;
    const double t = nf > 1 ? (double)fi / (nf - 1) : 0.0;

    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            double nx = (double)x / W, ny = (double)y / H;
            uint8_t Y=128, U=128, V=128;

            switch (pat % N_PATTERNS) {
            case 0: /* checkerboard */
                Y = (((int)(nx*8)+(int)(ny*8)+fi)&1) ? 220 : 35; break;

            case 1: { /* mandelbrot */
                double cr=nx*3.5-2.5, ci=ny*2-1, zr=0, zi=0; int it=0;
                while (it<32 && zr*zr+zi*zi<4) { double r=zr*zr-zi*zi+cr; zi=2*zr*zi+ci; zr=r; it++; }
                Y=(uint8_t)(it*8); U=(uint8_t)(it*3+80); V=(uint8_t)(255-it*7);
                break; }

            case 2: /* plasma */
                Y=(uint8_t)(128+127*sin(nx*10+ny*8+t*6.28));
                U=(uint8_t)(128+60*cos(nx*7-ny*5+t*4));
                V=(uint8_t)(128+60*sin(ny*9+t*3)); break;

            case 3: /* concentric rings */
                { double d=sqrt((nx-.5)*(nx-.5)+(ny-.5)*(ny-.5));
                  Y=(uint8_t)(128+127*sin(d*30+t*6.28)); break; }

            case 4: /* grid */
                Y=(fmod(nx*16,1)<0.1||fmod(ny*16,1)<0.1) ? 220 : 40; break;

            case 5: /* spiral */
                { double a=atan2(ny-.5,nx-.5)+t*6.28, d=sqrt((nx-.5)*(nx-.5)+(ny-.5)*(ny-.5));
                  Y=(uint8_t)(128+127*sin(a*4-d*20)); break; }

            case 6: /* vertical gradient */
                Y=(uint8_t)(ny*255*fabs(cos(t*M_PI))); break;

            case 7: /* radial gradient */
                { double d=2*sqrt((nx-.5)*(nx-.5)+(ny-.5)*(ny-.5));
                  Y=(uint8_t)FFMAX(0,(1-d)*255); break; }

            case 8: /* diagonal sine wave */
                Y=(uint8_t)(128+127*sin((nx+ny)*20+t*6.28));
                U=(uint8_t)(128+60*cos(nx*15+t*4)); break;

            case 9: /* cross */
                Y=(fabs(nx-.5)<0.05||fabs(ny-.5)<0.05) ? 240 : 20; break;

            case 10: /* diamond */
                Y=(fabs(nx-.5)+fabs(ny-.5)<.3+.2*t) ? 200 : 55; break;

            case 11: /* tunnel */
                { double tx=nx-.5, ty=ny-.5;
                  double u=atan2(ty,tx)/(2*M_PI)+.5, v=.3/(sqrt(tx*tx+ty*ty)+0.001);
                  Y=(uint8_t)(128+127*sin(v*10+t*6.28)*cos(u*20)); break; }

            case 12: /* diagonal stripes */
                Y=(fmod((nx+ny)*8+t*2,1)<0.5) ? 200 : 55; break;

            case 13: /* dots */
                { double dx=fmod(nx*12,1)-.5, dy=fmod(ny*12,1)-.5;
                  Y=(sqrt(dx*dx+dy*dy)<.3+.1*sin(t*6.28)) ? 220 : 35; break; }

            case 14: /* scanlines */
                Y=((int)(ny*H)&1) ? (uint8_t)(200+55*t) : 30; break;

            case 15: /* vignette */
                { double vx=nx-.5, vy=ny-.5, v=1-2*(vx*vx+vy*vy);
                  Y=(uint8_t)(FFMAX(0,v)*200*(.5+.5*cos(t*M_PI))); break; }

            case 16: /* zoom pulse */
                { double d=sqrt((nx-.5)*(nx-.5)+(ny-.5)*(ny-.5));
                  Y=(uint8_t)(128+127*sin(d*20*(1+t))); break; }

            case 17: /* pulse ring */
                { double d=sqrt((nx-.5)*(nx-.5)+(ny-.5)*(ny-.5)), r=.1+t*.4;
                  Y=fabs(d-r)<0.03 ? 240 : 30; break; }
            }

            /* Write luma */
            f->data[0][y*f->linesize[0]+x] = Y;

            /* Write chroma based on pixel format */
            switch (f->format) {
            case AV_PIX_FMT_YUV420P:
            case AV_PIX_FMT_YUVJ420P:
                if ((x&1)==0 && (y&1)==0) {
                    f->data[1][(y/2)*f->linesize[1]+x/2] = U;
                    f->data[2][(y/2)*f->linesize[2]+x/2] = V;
                } break;
            case AV_PIX_FMT_YUV422P:
                if ((x&1)==0) {
                    f->data[1][y*f->linesize[1]+x/2] = U;
                    f->data[2][y*f->linesize[2]+x/2] = V;
                } break;
            case AV_PIX_FMT_YUV444P:
                f->data[1][y*f->linesize[1]+x] = U;
                f->data[2][y*f->linesize[2]+x] = V;
                break;
            default: break;
            }
        }
    }
}

/* ── Audio waveform generator ────────────────────────────────────────────── */
#define N_WAVEFORMS 10

static float gen_sample(int wf, double t, double freq, int idx) {
    double s = 0;
    switch (wf % N_WAVEFORMS) {
    case 0:  s = 0; break;
    case 1:  s = sin(2*M_PI*freq*t); break;
    case 2:  s = sin(2*M_PI*freq*t) >= 0 ? 0.9 : -0.9; break;
    case 3:  s = 2*fmod(freq*t,1.0)-1.0; break;
    case 4:  { double p=fmod(freq*t,1.0); s=p<.5?4*p-1:3-4*p; break; }
    case 5:  { uint32_t h=(uint32_t)(idx*2654435761u^0xDEADBEEFu); h^=h>>16; h*=0x45d9f3b; h^=h>>16;
               s=(int)(h&0xFFFF)/32768.0-1.0; break; }
    case 6:  { double f0=100,f1=4000; s=sin(2*M_PI*(f0+((f1-f0)/2)*t)*t); break; }
    case 7:  s=(fmod(freq*t,1.0)<0.05)?0.9:0.0; break;
    case 8:  s=0.5*sin(2*M_PI*440*t)+0.5*sin(2*M_PI*880*t); break;
    case 9:  s=sin(2*M_PI*440*t)*0.5*(1+sin(2*M_PI*5*t)); break;
    }
    return (float)(s * 0.75);
}

/* Write one sample to frame buffer for any common format */
static void write_sample(AVFrame *f, int ch, int idx, float s, enum AVSampleFormat fmt) {
    int16_t s16 = (int16_t)(s * 32767.0f);
    switch (fmt) {
    case AV_SAMPLE_FMT_FLTP: ((float  *)f->data[ch])[idx] = s;   break;
    case AV_SAMPLE_FMT_FLT:  ((float  *)f->data[0])[idx*f->channels+ch] = s; break;
    case AV_SAMPLE_FMT_S16P: ((int16_t*)f->data[ch])[idx] = s16; break;
    case AV_SAMPLE_FMT_S16:  ((int16_t*)f->data[0])[idx*f->channels+ch] = s16; break;
    case AV_SAMPLE_FMT_S32P: ((int32_t*)f->data[ch])[idx] = (int32_t)s16<<16; break;
    case AV_SAMPLE_FMT_S32:  ((int32_t*)f->data[0])[idx*f->channels+ch] = (int32_t)s16<<16; break;
    case AV_SAMPLE_FMT_U8:   ((uint8_t *)f->data[0])[idx*f->channels+ch] = (uint8_t)((s+1)*127.5f); break;
    default: break;
    }
}

/* ── Container extras ────────────────────────────────────────────────────── */
static void apply_extras(AVFormatContext *fc, AVStream *vs, uint64_t seed) {
    const uint64_t feat = mix64(seed ^ 0xC0FFEE00C0FFEEULL);

    /* colr — color primaries, transfer, matrix, range */
    if (feat & 1) {
        static const struct {
            enum AVColorPrimaries         prim;
            enum AVColorTransferCharacteristic trc;
            enum AVColorSpace             spc;
            enum AVColorRange             range;
        } COLS[] = {
            {AVCOL_PRI_BT709,    AVCOL_TRC_BT709,     AVCOL_SPC_BT709,     AVCOL_RANGE_MPEG},
            {AVCOL_PRI_BT2020,   AVCOL_TRC_SMPTE2084, AVCOL_SPC_BT2020_NCL,AVCOL_RANGE_MPEG},
            {AVCOL_PRI_BT470BG,  AVCOL_TRC_GAMMA28,   AVCOL_SPC_BT470BG,   AVCOL_RANGE_JPEG},
            {AVCOL_PRI_SMPTE170M,AVCOL_TRC_SMPTE170M, AVCOL_SPC_SMPTE170M, AVCOL_RANGE_MPEG},
            {AVCOL_PRI_BT709,    AVCOL_TRC_IEC61966_2_1,AVCOL_SPC_BT709,   AVCOL_RANGE_JPEG},
            {AVCOL_PRI_BT2020,   AVCOL_TRC_ARIB_STD_B67,AVCOL_SPC_BT2020_NCL,AVCOL_RANGE_MPEG},
        };
        int ci = SEL(seed, 0x11, 6);
        vs->codecpar->color_primaries = COLS[ci].prim;
        vs->codecpar->color_trc       = COLS[ci].trc;
        vs->codecpar->color_space     = COLS[ci].spc;
        vs->codecpar->color_range     = COLS[ci].range;
    }

    /* pasp — sample aspect ratio */
    if (feat & 2) {
        AVRational sar = SARS[SEL(seed, 0x12, N_SARS)];
        vs->sample_aspect_ratio = sar;
        vs->codecpar->sample_aspect_ratio = sar;
    }

    /* Display matrix (rotation: 0/90/180/270°) */
    if (feat & 4) {
        uint8_t *dm = av_stream_new_side_data(vs, AV_PKT_DATA_DISPLAYMATRIX, 9*sizeof(int32_t));
        if (dm) {
            double angles[] = {0.0, 90.0, 180.0, 270.0};
            av_display_rotation_set((int32_t*)dm, angles[SEL(seed, 0x13, 4)]);
        }
    }

    /* stereo3D */
    if (feat & 8) {
        static const enum AVStereo3DType TYPES[] = {
            AV_STEREO3D_SIDEBYSIDE, AV_STEREO3D_TOPBOTTOM,
            AV_STEREO3D_FRAMESEQUENCE, AV_STEREO3D_CHECKERBOARD,
            AV_STEREO3D_SIDEBYSIDE_QUINCUNX,
        };
        AVStereo3D *s3d = av_stereo3d_create_side_data(vs);
        if (s3d) { s3d->type = TYPES[SEL(seed,0x14,5)]; s3d->flags = 0; }
    }

    /* HDR mastering display metadata */
    if (feat & 16) {
        AVMasteringDisplayMetadata *mdm = av_mastering_display_metadata_create_side_data(vs);
        if (mdm) {
            /* Rec. 2020 primaries */
            mdm->display_primaries[0][0] = av_make_q(34000,50000);  /* R x */
            mdm->display_primaries[0][1] = av_make_q(16000,50000);  /* R y */
            mdm->display_primaries[1][0] = av_make_q(13250,50000);  /* G x */
            mdm->display_primaries[1][1] = av_make_q(34500,50000);  /* G y */
            mdm->display_primaries[2][0] = av_make_q( 7500,50000);  /* B x */
            mdm->display_primaries[2][1] = av_make_q( 3000,50000);  /* B y */
            mdm->white_point[0] = av_make_q(15635,50000);
            mdm->white_point[1] = av_make_q(16450,50000);
            static const struct { int min, max; } LUMS[] =
                {{50,10000000},{10,40000000},{1,5000000},{100,20000000}};
            int li = SEL(seed,0x15,4);
            mdm->min_luminance = av_make_q(LUMS[li].min,10000);
            mdm->max_luminance = av_make_q(LUMS[li].max,10000);
            mdm->has_primaries = 1; mdm->has_luminance = 1;
        }
    }

    /* Content light level metadata */
    if (feat & 32) {
        AVContentLightMetadata *clm = av_content_light_metadata_create_side_data(vs);
        if (clm) {
            static const struct { unsigned cll, fall; } LIGHTS[] =
                {{1000,400},{4000,1000},{10000,2000},{300,100},{600,200}};
            int li = SEL(seed,0x16,5);
            clm->MaxCLL  = LIGHTS[li].cll;
            clm->MaxFALL = LIGHTS[li].fall;
        }
    }

    /* Chapters (chpl) — 1 to 4 chapters */
    if (feat & 64) {
        int nc = 1 + SEL(seed, 0x17, 4);
        fc->chapters = av_malloc_array(nc, sizeof(*fc->chapters));
        if (fc->chapters) {
            fc->nb_chapters = nc;
            for (int i = 0; i < nc; i++) {
                AVChapter *ch = av_mallocz(sizeof(AVChapter));
                if (!ch) { fc->nb_chapters = i; break; }
                ch->id = i;
                ch->time_base = (AVRational){1, AV_TIME_BASE};
                ch->start = (int64_t)i * AV_TIME_BASE / nc;
                ch->end   = (int64_t)(i+1) * AV_TIME_BASE / nc - 1;
                char title[32]; snprintf(title, sizeof(title), "Chapter %d", i+1);
                av_dict_set(&ch->metadata, "title", title, 0);
                fc->chapters[i] = ch;
            }
        }
    }

    /* Edit list via non-zero stream start_time */
    if (feat & 128) {
        vs->start_time = av_rescale_q(100+SEL(seed,0x18,400),
                                      (AVRational){1,1000}, vs->time_base);
    }

    /* Timecode track (via metadata) */
    if (feat & 256) {
        av_dict_set(&vs->metadata, "timecode", "00:00:00:00", 0);
    }

    /* Per-stream language */
    {
        static const char *LANGS[] = {"eng","und","fra","deu","jpn","spa","zho","kor","ara","por"};
        av_dict_set(&vs->metadata, "language", LANGS[SEL(seed,0x19,10)], 0);
    }

    /* Global metadata (2-8 random fields) */
    {
        int n = 2 + SEL(seed, 0x1A, 7);
        for (int i = 0; i < n; i++) {
            int ki = SEL(seed, 0x1B+i, N_META);
            int vi = SEL(seed, 0x1C+i, N_META);
            av_dict_set(&fc->metadata, META_KEYS[ki], META_VALS[vi], 0);
        }
    }
}

/* ── Encode audio stream ─────────────────────────────────────────────────── */
static void encode_audio_stream(AVFormatContext *fc, AVCodecContext *enc,
                                 AVStream *st, int wf, int dur_ms, uint64_t seed) {
    int sr = enc->sample_rate;
    int ch = enc->channels;
    int total = (int)((int64_t)sr * dur_ms / 1000);
    int fsz   = enc->frame_size > 0 ? enc->frame_size : 1024;
    double freq = 110.0 * (1 + SEL(seed, 0xA0, 12));

    AVFrame *frm = av_frame_alloc();
    AVPacket *pkt = av_packet_alloc();
    if (!frm || !pkt) goto done;

    frm->format      = enc->sample_fmt;
    frm->nb_samples  = fsz;
    frm->channels    = ch;
    frm->channel_layout = enc->channel_layout;
    frm->sample_rate = sr;
    if (av_frame_get_buffer(frm, 0) < 0) goto done;

    for (int pos = 0; pos < total; pos += fsz) {
        int n = FFMIN(fsz, total - pos);
        frm->nb_samples = n;
        frm->pts = pos;
        av_frame_make_writable(frm);
        for (int i = 0; i < n; i++) {
            double t = (double)(pos+i) / sr;
            float s = gen_sample(wf, t, freq, pos+i);
            for (int c = 0; c < ch; c++)
                write_sample(frm, c, i, s * (0.8f + 0.2f*c), enc->sample_fmt);
        }
        if (avcodec_send_frame(enc, frm) < 0) break;
        while (avcodec_receive_packet(enc, pkt) == 0) {
            pkt->stream_index = st->index;
            av_packet_rescale_ts(pkt, enc->time_base, st->time_base);
            av_interleaved_write_frame(fc, pkt);
            av_packet_unref(pkt);
        }
    }
    /* flush */
    avcodec_send_frame(enc, NULL);
    while (avcodec_receive_packet(enc, pkt) == 0) {
        pkt->stream_index = st->index;
        av_packet_rescale_ts(pkt, enc->time_base, st->time_base);
        av_interleaved_write_frame(fc, pkt);
        av_packet_unref(pkt);
    }
done:
    av_frame_free(&frm);
    av_packet_free(&pkt);
}

/* ── Main file generator ─────────────────────────────────────────────────── */
static int generate_mp4(const char *path, uint64_t seed) {
    /* Feature selection */
    int res_idx  = SEL(seed, 0x01, N_RES);
    int fps_idx  = SEL(seed, 0x02, N_FPS);
    int x264_idx = SEL(seed, 0x03, N_X264);
    int pix_idx  = SEL(seed, 0x04, N_PIX);
    int mov_idx  = SEL(seed, 0x05, N_MOVFLAGS);
    int pattern  = SEL(seed, 0x06, N_PATTERNS);
    int waveform = SEL(seed, 0x07, N_WAVEFORMS);
    int aud_idx  = SEL(seed, 0x08, N_AUDIO);
    int has_audio = FLAG(seed, 0x09, 80);       /* 80% have audio */
    int dur_ms    = 100 + SEL(seed, 0x0A, 850); /* 100-950ms */

    int W = RESOLUTIONS[res_idx].w;
    int H = RESOLUTIONS[res_idx].h;
    W = (W+1)&~1; H = (H+1)&~1;  /* must be even for H.264 */

    const X264Cfg *x264 = &X264_CFGS[x264_idx];

    /* Pixel format: force compatibility with x264 profile */
    enum AVPixelFormat pix_fmt;
    if      (strcmp(x264->profile,"high422")==0) pix_fmt = AV_PIX_FMT_YUV422P;
    else if (strcmp(x264->profile,"high444")==0) pix_fmt = AV_PIX_FMT_YUV444P;
    else if (PIX_CFGS[pix_idx].profile_required &&
             strcmp(PIX_CFGS[pix_idx].profile_required,x264->profile)!=0)
        pix_fmt = AV_PIX_FMT_YUV420P;
    else
        pix_fmt = PIX_CFGS[pix_idx].fmt;

    int ret = 0;
    AVFormatContext  *fc   = NULL;
    AVCodecContext   *venc = NULL;
    AVCodecContext   *aenc = NULL;
    AVStream         *vs   = NULL;
    AVStream         *as   = NULL;
    AVFrame          *vfr  = NULL;
    AVPacket         *pkt  = NULL;
    AVDictionary     *fopts= NULL;

    /* Output context */
    if (avformat_alloc_output_context2(&fc, NULL, "mp4", path) < 0) goto fail;

    /* movflags */
    const char *mf = MOVFLAGS[mov_idx];
    if (mf[0]) av_dict_set(&fopts, "movflags", mf, 0);

    /* ── Video stream ── */
    const AVCodec *vc = avcodec_find_encoder_by_name("libx264");
    if (!vc) vc = avcodec_find_encoder(AV_CODEC_ID_H264);
    if (!vc) { ret=-1; goto fail; }

    vs   = avformat_new_stream(fc, NULL);
    venc = avcodec_alloc_context3(vc);
    if (!vs || !venc) { ret=AVERROR(ENOMEM); goto fail; }

    venc->width     = W;
    venc->height    = H;
    venc->pix_fmt   = pix_fmt;
    venc->time_base = (AVRational){FRAMERATES[fps_idx].den, FRAMERATES[fps_idx].num};
    venc->framerate = (AVRational){FRAMERATES[fps_idx].num, FRAMERATES[fps_idx].den};
    venc->bit_rate  = 400000;
    venc->gop_size  = FFMAX(1, FRAMERATES[fps_idx].num / FRAMERATES[fps_idx].den / 2);
    if (fc->oformat->flags & AVFMT_GLOBALHEADER) venc->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

    av_opt_set    (venc->priv_data, "preset",  x264->preset,  0);
    av_opt_set    (venc->priv_data, "tune",    x264->tune,    0);
    av_opt_set    (venc->priv_data, "profile", x264->profile, 0);
    av_opt_set    (venc->priv_data, "level",   x264->level,   0);
    av_opt_set_int(venc->priv_data, "crf",     x264->crf,     0);
    /* Extra x264 options for diversity */
    av_opt_set_int(venc->priv_data, "refs",      1+SEL(seed,0x20,4), 0);
    av_opt_set_int(venc->priv_data, "subq",      1+SEL(seed,0x21,7), 0);
    av_opt_set_int(venc->priv_data, "me_range",  4+SEL(seed,0x22,12),0);
    av_opt_set_int(venc->priv_data, "aq-mode",   SEL(seed,0x23,3),   0);
    av_opt_set_int(venc->priv_data, "keyint-min",1+SEL(seed,0x24,25),0);

    if ((ret = avcodec_open2(venc, vc, NULL)) < 0) goto fail;
    if ((ret = avcodec_parameters_from_context(vs->codecpar, venc)) < 0) goto fail;
    vs->time_base = venc->time_base;
    vs->avg_frame_rate = venc->framerate;

    /* ── Audio stream (optional) ── */
    if (has_audio) {
        const AudioCfg *ac = &AUDIO_CFGS[aud_idx];
        const AVCodec  *acodec = avcodec_find_encoder_by_name(ac->encoder_name);
        if (!acodec) acodec = avcodec_find_encoder(ac->id);
        if (acodec) {
            aenc = avcodec_alloc_context3(acodec);
            if (aenc) {
                aenc->sample_rate   = ac->sample_rate;
                aenc->channel_layout= ac->ch_layout;
                aenc->channels      = av_get_channel_layout_nb_channels(ac->ch_layout);
                aenc->bit_rate      = ac->bitrate;
                /* pick first supported sample format */
                aenc->sample_fmt = acodec->sample_fmts ? acodec->sample_fmts[0]
                                                       : AV_SAMPLE_FMT_FLTP;
                /* pick compatible sample rate */
                if (acodec->supported_samplerates) {
                    aenc->sample_rate = acodec->supported_samplerates[0];
                    for (int i = 0; acodec->supported_samplerates[i]; i++)
                        if (acodec->supported_samplerates[i] == ac->sample_rate) {
                            aenc->sample_rate = ac->sample_rate; break;
                        }
                }
                if (fc->oformat->flags & AVFMT_GLOBALHEADER)
                    aenc->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
                if (avcodec_open2(aenc, acodec, NULL) == 0) {
                    as = avformat_new_stream(fc, NULL);
                    if (as) {
                        avcodec_parameters_from_context(as->codecpar, aenc);
                        as->time_base = (AVRational){1, aenc->sample_rate};
                        av_dict_set(&as->metadata, "language",
                            (const char*[]){"eng","und","fra"}[SEL(seed,0x30,3)], 0);
                    }
                } else {
                    avcodec_free_context(&aenc);
                }
            }
        }
    }

    /* Container extras (colr, pasp, stereo3D, HDR, chapters, edit list...) */
    apply_extras(fc, vs, seed);

    /* Open output file */
    if (!(fc->oformat->flags & AVFMT_NOFILE)) {
        if ((ret = avio_open(&fc->pb, path, AVIO_FLAG_WRITE)) < 0) goto fail;
    }

    /* Write header */
    if ((ret = avformat_write_header(fc, &fopts)) < 0) goto fail;
    av_dict_free(&fopts);

    /* ── Encode video ── */
    int n_frames = (int)((int64_t)FRAMERATES[fps_idx].num * dur_ms
                         / FRAMERATES[fps_idx].den / 1000);
    if (n_frames < 1) n_frames = 1;
    if (n_frames > 120) n_frames = 120;

    vfr = av_frame_alloc();
    pkt = av_packet_alloc();
    if (!vfr || !pkt) { ret=AVERROR(ENOMEM); goto fail; }

    vfr->format = venc->pix_fmt;
    vfr->width  = W;
    vfr->height = H;
    if ((ret = av_frame_get_buffer(vfr, 32)) < 0) goto fail;

    for (int fi = 0; fi < n_frames; fi++) {
        av_frame_make_writable(vfr);
        fill_frame(vfr, pattern, fi, n_frames);
        vfr->pts = fi;
        if (avcodec_send_frame(venc, vfr) < 0) break;
        while (avcodec_receive_packet(venc, pkt) == 0) {
            pkt->stream_index = vs->index;
            av_packet_rescale_ts(pkt, venc->time_base, vs->time_base);
            av_interleaved_write_frame(fc, pkt);
            av_packet_unref(pkt);
        }
    }
    /* flush video */
    avcodec_send_frame(venc, NULL);
    while (avcodec_receive_packet(venc, pkt) == 0) {
        pkt->stream_index = vs->index;
        av_packet_rescale_ts(pkt, venc->time_base, vs->time_base);
        av_interleaved_write_frame(fc, pkt);
        av_packet_unref(pkt);
    }

    /* ── Encode audio ── */
    if (aenc && as) encode_audio_stream(fc, aenc, as, waveform, dur_ms, seed);

    ret = av_write_trailer(fc);

fail:
    av_dict_free(&fopts);
    av_packet_free(&pkt);
    av_frame_free(&vfr);
    if (venc) { avcodec_close(venc); avcodec_free_context(&venc); }
    if (aenc) { avcodec_close(aenc); avcodec_free_context(&aenc); }
    if (fc) {
        if (!(fc->oformat->flags & AVFMT_NOFILE) && fc->pb) avio_closep(&fc->pb);
        avformat_free_context(fc);
    }
    return ret;
}

/* ── main ────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <output_dir> <count>  (count=0 → infinite)\n", argv[0]);
        return 1;
    }
    const char *outdir = argv[1];
    long count = atol(argv[2]);

    struct stat st;
    if (stat(outdir, &st) != 0 && mkdir(outdir, 0755) != 0) {
        perror("mkdir"); return 1;
    }

    av_log_set_level(AV_LOG_QUIET);

    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    long generated = 0, failed = 0;

    printf("[mp4gen] Starting: dir=%s count=%ld initial_seed=%llx\n",
           outdir, count, (unsigned long long)seed);
    fflush(stdout);

    for (long i = 0; count == 0 || i < count; i++, seed++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%016llx.mp4", outdir, (unsigned long long)seed);

        int ret = generate_mp4(path, seed);
        if (ret < 0) {
            unlink(path);
            failed++;
        } else {
            struct stat fs;
            if (stat(path, &fs) == 0 && fs.st_size >= 8 && fs.st_size <= 200*1024) {
                generated++;
            } else {
                unlink(path);
                failed++;
            }
        }

        if ((i+1) % 500 == 0) {
            printf("[mp4gen] %ld generated, %ld failed, seed=%llx (%.1f%% ok)\n",
                   generated, failed, (unsigned long long)seed,
                   100.0*generated/(generated+failed+1));
            fflush(stdout);
        }
    }

    printf("[mp4gen] Done: %ld generated, %ld failed\n", generated, failed);
    return 0;
}
