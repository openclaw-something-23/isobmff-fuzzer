/*
 * isobmff_mutator.c — AFL++ custom mutator for ISOBMFF / MP4 / HEIF
 *
 * Structure-aware mutations that understand the box-container hierarchy.
 *
 * Strategies:
 *  ── Box structure ──────────────────────────────────────────────────────────
 *   1. box_type_swap      — replace box FourCC with a random known-valid type
 *   2. size_edge          — set box size to 0,1,8,max32 or random small value
 *   3. box_duplicate      — copy a random top-level box and append it
 *   4. box_insert         — insert a synthetic minimal box between existing boxes
 *   5. box_delete         — remove a random top-level box
 *   6. box_truncate       — shrink a random box to test partial-parse paths
 *   7. box_reorder        — swap two adjacent boxes
 *   8. size_overflow      — write size > remaining to trigger bounds checks
 *   9. nested_inject      — inject a child box inside a container box
 *  10. large_box_flood    — insert many tiny boxes (stress box-count limits)
 *  ── FullBox fields ─────────────────────────────────────────────────────────
 *  11. field_overflow     — smash version/flags bytes with 0x00/0xFF/0x7F
 *  12. version_flags      — inject known-bad version+flags combos
 *  ── Sample table ───────────────────────────────────────────────────────────
 *  13. stts_corrupt       — corrupt time-to-sample table (count/delta → edges)
 *  14. stsz_corrupt       — corrupt sample size table (OOB read triggers)
 *  15. stco_overflow      — set chunk offsets to huge values
 *  16. stsc_corrupt       — corrupt sample-to-chunk table
 *  17. ctts_negative      — inject negative/large composition offsets
 *  ── ftyp / brands ──────────────────────────────────────────────────────────
 *  18. ftyp_brand_fuzz    — replace major_brand or insert weird compat brands
 *  ── Video codec boxes ──────────────────────────────────────────────────────
 *  19. nal_length_corrupt — corrupt AVC/HEVC NAL-length prefix in mdat-like data
 *  20. codec_box_corrupt  — corrupt inner codec config boxes (avcC/hvcC/av1C)
 *  ── Edit list ──────────────────────────────────────────────────────────────
 *  21. elst_corrupt       — corrupt edit list entries (duration/media_time)
 *  ── Crossover / splice ─────────────────────────────────────────────────────
 *  22. splice_boxes       — take boxes from crossover input and append
 *  ── Chained / fallback ─────────────────────────────────────────────────────
 *  23. double_mutate      — apply two strategies in sequence
 *  24. random_byte        — flip a random byte (fallback)
 *
 * Build: afl-clang-fast -shared -fPIC -O2 isobmff_mutator.c -o isobmff_mutator.so
 * Use:   AFL_CUSTOM_MUTATOR_LIBRARY=/path/isobmff_mutator.so afl-fuzz ...
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

typedef struct {
    uint32_t seed;
    uint8_t *scratch;
    size_t   scratch_size;
} my_state_t;

/* ── Known-valid ISOBMFF FourCCs ─────────────────────────────────────────── */
static const char *KNOWN_BOXES[] = {
    /* basic */ "ftyp","moov","mdat","free","skip","wide","pdin",
    /* movie */ "mvhd","udta","meta","ilst","mean","name","data",
    /* track */ "trak","tkhd","edts","elst","tref","load",
    /* media */ "mdia","mdhd","hdlr","minf","vmhd","smhd","hmhd","nmhd",
    /* data  */ "dinf","dref","url ","urn ",
    /* sample table */ "stbl","stsd","stts","ctts","cslg","stsc","stsz","stz2",
                       "stco","co64","stss","stsh","sdtp","sbgp","sgpd","subs",
    /* video codecs */ "avc1","avc2","avc3","avc4","hvc1","hev1","vp09","av01",
                       "mp4v","dvh1","dvhe","dvav","dva1",
    /* codec config */ "avcC","hvcC","vpcC","av1C","dvcC","dvvC",
    /* audio codecs */ "mp4a","ac-3","ec-3","Opus","flac","dtsc","dtse","dtsh",
    /* audio config */ "esds","dac3","dec3","dOps","dfLa",
    /* visual      */ "btrt","colr","pasp","clap","fiel","gama","chrm","mdcv","clli",
    /* movie ext   */ "mvex","mehd","trex","leva",
    /* fragments   */ "moof","mfhd","traf","tfhd","tfdt","trun","mfra","mfro","tfra",
    /* protection  */ "pssh","sinf","frma","schm","schi","tenc","senc","saiz","saio",
    /* HEIF/AVIF   */ "pict","idat","iref","iprp","ipco","ipma","iinf","infe",
                      "iloc","ispe","pixi","irot","imir","av1C","colr","pasp",
    /* thumbnails  */ "pitm","grpl","grid","iovl","iden",
};
#define N_BOXES (sizeof(KNOWN_BOXES)/sizeof(KNOWN_BOXES[0]))

/* ── Known ftyp brands ───────────────────────────────────────────────────── */
static const char *BRANDS[] = {
    "isom","iso2","iso4","iso5","iso6","iso7","iso8","iso9",
    "mp41","mp42","M4V ","M4A ","M4P ","M4B ",
    "avc1","hvc1","hev1","av01",
    "heic","heif","mif1","msf1","heis","avci","avcs","avis",
    "dash","iso6","msdh","dsms","lmsg",
    "qt  ","MSNV","NDAS","NDSC","NDSH","NDSM","NDSP","NDSS","NDXC",
    "F4V ","F4P ","arri","niko","CAEP","caqv",
    "\x00\x00\x00\x00","????","XXXX",       /* intentionally invalid */
};
#define N_BRANDS (sizeof(BRANDS)/sizeof(BRANDS[0]))

/* ── LCG RNG ─────────────────────────────────────────────────────────────── */
static uint32_t lcg(my_state_t *s) {
    s->seed = s->seed * 1664525u + 1013904223u;
    return s->seed;
}
static uint32_t rng_range(my_state_t *s, uint32_t n) {
    return n ? lcg(s) % n : 0;
}

/* ── Big-endian helpers ──────────────────────────────────────────────────── */
static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void write_u32(uint8_t *p, uint32_t v) {
    p[0]=v>>24; p[1]=(v>>16)&0xFF; p[2]=(v>>8)&0xFF; p[3]=v&0xFF;
}
static uint64_t read_u64(const uint8_t *p) {
    return ((uint64_t)read_u32(p)<<32)|read_u32(p+4);
}
static void write_u64(uint8_t *p, uint64_t v) {
    write_u32(p,(uint32_t)(v>>32)); write_u32(p+4,(uint32_t)v);
}

/* ── Box scanner ─────────────────────────────────────────────────────────── */
static int count_boxes(const uint8_t *buf, size_t len,
                       uint32_t *offsets, int max) {
    int n = 0;
    size_t off = 0;
    while (off + 8 <= len && n < max) {
        uint32_t sz = read_u32(buf + off);
        if (sz == 0) sz = (uint32_t)(len - off);
        if (sz < 8 || off + sz > len) break;
        offsets[n++] = (uint32_t)off;
        off += sz;
    }
    return n;
}

/* Find a box with matching type; returns offset or -1 */
static int32_t find_box(const uint8_t *buf, size_t len, const char *type) {
    uint32_t offs[256]; int n = count_boxes(buf, len, offs, 256);
    for (int i = 0; i < n; i++) {
        if (memcmp(buf + offs[i] + 4, type, 4) == 0)
            return (int32_t)offs[i];
    }
    return -1;
}

/* ── AFL++ API ───────────────────────────────────────────────────────────── */
void *afl_custom_init(void *afl, unsigned int seed) {
    my_state_t *s = calloc(1, sizeof(my_state_t));
    if (!s) return NULL;
    s->seed = seed ^ (uint32_t)(uintptr_t)afl ^ (uint32_t)time(NULL);
    s->scratch_size = 4 << 20; /* 4MB scratch */
    s->scratch = malloc(s->scratch_size);
    if (!s->scratch) { free(s); return NULL; }
    return s;
}

void afl_custom_deinit(void *data) {
    my_state_t *s = data;
    if (s) { free(s->scratch); free(s); }
}

/* Forward declaration for double_mutate */
static size_t do_mutate(my_state_t *s,
                        uint8_t *buf, size_t buf_size,
                        uint8_t *add_buf, size_t add_buf_size,
                        size_t max_size, int strategy);

size_t afl_custom_fuzz(void *data,
                       uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

    my_state_t *s = data;
    if (!s || !buf || buf_size < 8) return 0;
    if (buf_size > s->scratch_size - 1024) return 0;

    memcpy(s->scratch, buf, buf_size);

    /* Weighted strategy selection (out of 100) */
    int strategy = (int)rng_range(s, 100);
    size_t out_size = do_mutate(s, buf, buf_size, add_buf, add_buf_size,
                                max_size, strategy);
    if (out_size < 8) return 0;
    *out_buf = s->scratch;
    return out_size;
}

/* ── Core mutation logic ─────────────────────────────────────────────────── */
static size_t do_mutate(my_state_t *s,
                        uint8_t *buf, size_t buf_size,
                        uint8_t *add_buf, size_t add_buf_size,
                        size_t max_size, int strategy) {

    size_t out_size = buf_size;
    uint32_t box_offs[256];
    int n = count_boxes(buf, buf_size, box_offs, 256);
    if (n == 0) return 0;

    /* ── Strategy 1: box_type_swap (8%) ─────────────────────────────────── */
    if (strategy < 8) {
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        const char *new_type = KNOWN_BOXES[rng_range(s, N_BOXES)];
        memcpy(s->scratch + off + 4, new_type, 4);

    /* ── Strategy 2: size_edge (5%) ─────────────────────────────────────── */
    } else if (strategy < 13) {
        static const uint32_t EDGE_SIZES[] = {0,1,2,8,9,16,0xFFFFFFFF,
                                               0x80000000,0x100,0x1000,7};
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        write_u32(s->scratch + off, EDGE_SIZES[rng_range(s, 11)]);

    /* ── Strategy 3: box_duplicate (7%) ─────────────────────────────────── */
    } else if (strategy < 20) {
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t box_sz = read_u32(buf + off);
        if (box_sz == 0) box_sz = (uint32_t)(buf_size - off);
        if (box_sz < 8 || box_sz > 8192 ||
            out_size + box_sz > s->scratch_size ||
            out_size + box_sz > max_size) return out_size;
        memcpy(s->scratch + out_size, buf + off, box_sz);
        out_size += box_sz;

    /* ── Strategy 4: box_insert (7%) ────────────────────────────────────── */
    } else if (strategy < 27) {
        if (out_size + 8 >= max_size || out_size + 8 >= s->scratch_size)
            return out_size;
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        const char *btype = KNOWN_BOXES[rng_range(s, N_BOXES)];
        uint8_t newbox[8]; write_u32(newbox, 8); memcpy(newbox + 4, btype, 4);
        memmove(s->scratch + off + 8, s->scratch + off, out_size - off);
        memcpy(s->scratch + off, newbox, 8);
        out_size += 8;

    /* ── Strategy 5: box_delete (5%) ────────────────────────────────────── */
    } else if (strategy < 32 && n > 1) {
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t box_sz = read_u32(buf + off);
        if (box_sz == 0) box_sz = (uint32_t)(buf_size - off);
        if (box_sz < 8 || off + box_sz > buf_size) return out_size;
        memmove(s->scratch + off, s->scratch + off + box_sz,
                out_size - off - box_sz);
        out_size -= box_sz;

    /* ── Strategy 6: box_truncate (4%) ──────────────────────────────────── */
    } else if (strategy < 36) {
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t box_sz = read_u32(buf + off);
        if (box_sz == 0) box_sz = (uint32_t)(buf_size - off);
        if (box_sz < 16) return out_size;
        uint32_t new_sz = 8 + rng_range(s, box_sz - 8);
        write_u32(s->scratch + off, new_sz);
        if (off + box_sz == out_size) out_size = off + new_sz;

    /* ── Strategy 7: box_reorder (4%) ───────────────────────────────────── */
    } else if (strategy < 40 && n >= 2) {
        int idx = rng_range(s, n - 1);
        uint32_t off_a = box_offs[idx], off_b = box_offs[idx + 1];
        uint32_t sz_a = read_u32(buf + off_a), sz_b = read_u32(buf + off_b);
        if (!sz_a || !sz_b || sz_a < 8 || sz_b < 8) return out_size;
        if (off_a + sz_a + sz_b > out_size || sz_a + sz_b > 131072) return out_size;
        uint8_t *tmp = malloc(sz_a);
        if (!tmp) return out_size;
        memcpy(tmp, s->scratch + off_a, sz_a);
        memmove(s->scratch + off_a, s->scratch + off_b, sz_b);
        memcpy(s->scratch + off_a + sz_b, tmp, sz_a);
        free(tmp);

    /* ── Strategy 8: size_overflow (3%) ─────────────────────────────────── */
    } else if (strategy < 43) {
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t rem = (uint32_t)(out_size - off);
        uint32_t delta = 8 + rng_range(s, 4096);
        write_u32(s->scratch + off, rem + delta);

    /* ── Strategy 9: nested_inject (5%) ─────────────────────────────────── */
    } else if (strategy < 48) {
        if (out_size + 8 >= max_size || out_size + 8 >= s->scratch_size)
            return out_size;
        static const char *CONTAINERS[] = {
            "moov","trak","mdia","minf","dinf","stbl","udta","ilst",
            "moof","traf","mvex","iprp","ipco","iinf","meta"
        };
        int found = -1;
        for (int i = 0; i < n && found < 0; i++) {
            const uint8_t *t = buf + box_offs[i] + 4;
            for (int j = 0; j < 15; j++)
                if (memcmp(t, CONTAINERS[j], 4) == 0) { found = i; break; }
        }
        if (found < 0) found = rng_range(s, n);
        uint32_t off = box_offs[found];
        uint32_t box_sz = read_u32(buf + off);
        if (box_sz == 0) box_sz = (uint32_t)(buf_size - off);
        if (box_sz < 16) return out_size;
        uint32_t insert_at = off + box_sz;
        if (insert_at > out_size) return out_size;
        const char *child_type = KNOWN_BOXES[rng_range(s, N_BOXES)];
        uint8_t child[8]; write_u32(child, 8); memcpy(child + 4, child_type, 4);
        memmove(s->scratch + insert_at + 8, s->scratch + insert_at,
                out_size - insert_at);
        memcpy(s->scratch + insert_at, child, 8);
        out_size += 8;
        write_u32(s->scratch + off, box_sz + 8);

    /* ── Strategy 10: large_box_flood (3%) ──────────────────────────────── */
    } else if (strategy < 51) {
        /* Insert N empty free/skip boxes — stress box-count limits */
        uint32_t count = 8 + rng_range(s, 120); /* 8..127 boxes */
        for (uint32_t i = 0; i < count; i++) {
            if (out_size + 8 >= max_size || out_size + 8 >= s->scratch_size)
                break;
            const char *bt = (rng_range(s, 2) == 0) ? "free" : "skip";
            uint8_t box[8]; write_u32(box, 8); memcpy(box + 4, bt, 4);
            memcpy(s->scratch + out_size, box, 8);
            out_size += 8;
        }

    /* ── Strategy 11: field_overflow (5%) ───────────────────────────────── */
    } else if (strategy < 56) {
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t box_sz = read_u32(buf + off);
        if (box_sz >= 12) {
            static const uint8_t FILL[] = {0xFF,0x00,0x80,0x7F,0x01,0xFE};
            uint8_t fill = FILL[rng_range(s, 6)];
            memset(s->scratch + off + 8, fill, 4);
        }

    /* ── Strategy 12: version_flags (4%) ────────────────────────────────── */
    } else if (strategy < 60) {
        static const uint8_t VF[][4] = {
            {0x00,0x00,0x00,0x00},  /* v0, flags=0       */
            {0x01,0x00,0x00,0x00},  /* v1, flags=0       */
            {0x02,0x00,0x00,0x00},  /* v2, invalid most  */
            {0xFF,0xFF,0xFF,0xFF},  /* all-ones          */
            {0x00,0x00,0x00,0x01},  /* v0, track_enabled */
            {0x00,0x00,0x00,0x0f},  /* v0, all flags     */
            {0x01,0x00,0x00,0x01},  /* v1+flag           */
            {0x00,0x80,0x00,0x00},  /* unknown high flag */
            {0x00,0x00,0x01,0x00},  /* flag bit 8        */
            {0x7F,0xFF,0xFF,0xFF},  /* max positive      */
            {0x80,0x00,0x00,0x00},  /* sign bit          */
        };
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        if (read_u32(buf + off) >= 12)
            memcpy(s->scratch + off + 8, VF[rng_range(s, 11)], 4);

    /* ── Strategy 13: stts_corrupt (4%) ─────────────────────────────────── */
    } else if (strategy < 64) {
        /*
         * stts box layout (v0):
         *   [4 size][4 "stts"][1 ver][3 flags][4 entry_count]
         *   [ {4 sample_count, 4 sample_delta} × entry_count ]
         * Corrupt entry_count or individual delta values.
         */
        int32_t stts_off = find_box(buf, buf_size, "stts");
        if (stts_off < 0 || (uint32_t)stts_off + 16 > buf_size)
            return out_size;
        uint32_t entry_count = read_u32(buf + stts_off + 12);
        uint32_t box_sz = read_u32(buf + stts_off);
        int sub = rng_range(s, 3);
        if (sub == 0) {
            /* Corrupt entry_count to huge value → parser OOM/loop */
            static const uint32_t BAD_COUNTS[] = {
                0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x00010000, 0
            };
            write_u32(s->scratch + stts_off + 12,
                      BAD_COUNTS[rng_range(s, 5)]);
        } else if (sub == 1 && entry_count > 0 && box_sz > 16) {
            /* Corrupt a random delta to 0 or UINT32_MAX */
            uint32_t entry_idx = rng_range(s, entry_count);
            uint32_t entry_off = stts_off + 16 + entry_idx * 8;
            if (entry_off + 8 <= buf_size) {
                static const uint32_t BAD[] = {0,1,0xFFFFFFFF,0x80000000};
                write_u32(s->scratch + entry_off + 4, BAD[rng_range(s, 4)]);
            }
        } else {
            /* Corrupt sample_count to 0 */
            if (entry_count > 0 && stts_off + 16 + 8 <= (int32_t)buf_size)
                write_u32(s->scratch + stts_off + 16, 0);
        }

    /* ── Strategy 14: stsz_corrupt (4%) ─────────────────────────────────── */
    } else if (strategy < 68) {
        /*
         * stsz: [4 size]["stsz"][1v][3f][4 sample_size][4 sample_count]
         *        [4 entry_size × sample_count]
         * Corrupt sample_count or individual sizes → OOB read in demuxer.
         */
        int32_t stsz_off = find_box(buf, buf_size, "stsz");
        if (stsz_off < 0 || (uint32_t)stsz_off + 20 > buf_size)
            return out_size;
        int sub = rng_range(s, 3);
        if (sub == 0) {
            /* Corrupt sample_count */
            static const uint32_t BAD[] = {0xFFFFFFFF,0x80000000,0,0x10000000};
            write_u32(s->scratch + stsz_off + 16, BAD[rng_range(s, 4)]);
        } else if (sub == 1) {
            /* Set uniform sample_size to huge value */
            static const uint32_t BAD[] = {0xFFFFFFFF,0x80000000,0x7FFFFFFF,1};
            write_u32(s->scratch + stsz_off + 12, BAD[rng_range(s, 4)]);
        } else {
            /* Corrupt a random entry in the size table */
            uint32_t sc = read_u32(buf + stsz_off + 16);
            if (sc == 0 || sc > 65536) return out_size;
            uint32_t ei = rng_range(s, sc);
            uint32_t eo = stsz_off + 20 + ei * 4;
            if (eo + 4 <= buf_size) {
                static const uint32_t BAD[] = {0,0xFFFFFFFF,0x80000000,0x7FFFFFFF};
                write_u32(s->scratch + eo, BAD[rng_range(s, 4)]);
            }
        }

    /* ── Strategy 15: stco_overflow (4%) ────────────────────────────────── */
    } else if (strategy < 72) {
        /* stco: chunk offsets → set to huge values forces out-of-bounds seek */
        int32_t stco_off = find_box(buf, buf_size, "stco");
        if (stco_off < 0) stco_off = find_box(buf, buf_size, "co64");
        if (stco_off < 0 || (uint32_t)stco_off + 16 > buf_size)
            return out_size;
        uint32_t ec = read_u32(buf + stco_off + 12);
        if (ec == 0 || ec > 65536) return out_size;
        int is64 = (memcmp(buf + stco_off + 4, "co64", 4) == 0);
        uint32_t entry_sz = is64 ? 8 : 4;
        uint32_t ei = rng_range(s, ec);
        uint32_t eo = stco_off + 16 + ei * entry_sz;
        if (eo + entry_sz > buf_size) return out_size;
        if (is64)
            write_u64(s->scratch + eo, (uint64_t)0xFFFFFFFFFFFFFFFFULL);
        else
            write_u32(s->scratch + eo, 0xFFFFFFFF);

    /* ── Strategy 16: stsc_corrupt (3%) ─────────────────────────────────── */
    } else if (strategy < 75) {
        /* stsc: sample-to-chunk; corrupt first_chunk/samples_per_chunk */
        int32_t stsc_off = find_box(buf, buf_size, "stsc");
        if (stsc_off < 0 || (uint32_t)stsc_off + 16 > buf_size)
            return out_size;
        uint32_t ec = read_u32(buf + stsc_off + 12);
        if (ec == 0 || ec > 65536) return out_size;
        uint32_t ei = rng_range(s, ec);
        uint32_t eo = stsc_off + 16 + ei * 12; /* {first_chunk, spc, sdi} */
        if (eo + 12 > buf_size) return out_size;
        /* Corrupt samples_per_chunk to 0 or huge */
        static const uint32_t BAD[] = {0, 0xFFFFFFFF, 0x80000000, 1};
        write_u32(s->scratch + eo + 4, BAD[rng_range(s, 4)]);

    /* ── Strategy 17: ctts_negative (3%) ────────────────────────────────── */
    } else if (strategy < 78) {
        /* ctts: composition time offset; inject large/negative offsets */
        int32_t ctts_off = find_box(buf, buf_size, "ctts");
        if (ctts_off < 0 || (uint32_t)ctts_off + 16 > buf_size)
            return out_size;
        uint32_t ec = read_u32(buf + ctts_off + 12);
        if (ec == 0 || ec > 65536) return out_size;
        uint32_t ei = rng_range(s, ec);
        uint32_t eo = ctts_off + 16 + ei * 8;
        if (eo + 8 > buf_size) return out_size;
        /* Inject negative-as-uint32 or huge offset */
        static const uint32_t BAD[] = {
            0xFFFFFFFF, 0x80000000, 0x7FFFFFFF,
            0xFF000000, 0, 1
        };
        write_u32(s->scratch + eo + 4, BAD[rng_range(s, 6)]);

    /* ── Strategy 18: ftyp_brand_fuzz (3%) ──────────────────────────────── */
    } else if (strategy < 81) {
        /* ftyp: [4 size]["ftyp"][4 major_brand][4 minor_version][compat brands...] */
        int32_t ftyp_off = find_box(buf, buf_size, "ftyp");
        if (ftyp_off < 0 || (uint32_t)ftyp_off + 16 > buf_size)
            return out_size;
        int sub = rng_range(s, 3);
        if (sub == 0) {
            /* Replace major_brand */
            const char *b = BRANDS[rng_range(s, N_BRANDS)];
            memcpy(s->scratch + ftyp_off + 8, b, 4);
        } else if (sub == 1) {
            /* Append a weird compat brand */
            uint32_t ftyp_sz = read_u32(buf + ftyp_off);
            if (ftyp_sz == 0) ftyp_sz = (uint32_t)(buf_size - ftyp_off);
            if (ftyp_off + ftyp_sz + 4 > s->scratch_size ||
                out_size + 4 > max_size) return out_size;
            const char *b = BRANDS[rng_range(s, N_BRANDS)];
            uint32_t ins = ftyp_off + ftyp_sz;
            memmove(s->scratch + ins + 4, s->scratch + ins, out_size - ins);
            memcpy(s->scratch + ins, b, 4);
            write_u32(s->scratch + ftyp_off, ftyp_sz + 4);
            out_size += 4;
        } else {
            /* Corrupt minor_version */
            write_u32(s->scratch + ftyp_off + 12, 0xFFFFFFFF);
        }

    /* ── Strategy 19: nal_length_corrupt (3%) ───────────────────────────── */
    } else if (strategy < 84) {
        /*
         * In AVC/HEVC, video data in mdat uses length-prefixed NAL units:
         *   [4-byte big-endian length][NAL data]
         * We scan for avc1/hvc1/avc2/hev1 boxes and corrupt the length.
         * We also just corrupt random 4-byte sequences that look like NAL
         * lengths in any large mdat section.
         */
        int32_t mdat_off = find_box(buf, buf_size, "mdat");
        if (mdat_off < 0 || (uint32_t)mdat_off + 16 > buf_size)
            return out_size;
        uint32_t mdat_sz = read_u32(buf + mdat_off);
        if (mdat_sz == 0) mdat_sz = (uint32_t)(buf_size - mdat_off);
        if (mdat_sz < 16) return out_size;
        /* Pick a random offset within mdat payload and write a bad NAL length */
        uint32_t payload_sz = mdat_sz - 8;
        uint32_t rand_off = mdat_off + 8 + rng_range(s, payload_sz > 4 ? payload_sz - 4 : 1);
        static const uint32_t BAD_NAL[] = {
            0xFFFFFFFF, 0x80000000, 0, 1, 0x7FFFFFFF,
            0x00000001,  /* MPEG-4 start code — wrong for AVCC mode */
        };
        write_u32(s->scratch + rand_off, BAD_NAL[rng_range(s, 6)]);

    /* ── Strategy 20: codec_box_corrupt (3%) ────────────────────────────── */
    } else if (strategy < 87) {
        /* Corrupt inner codec config boxes */
        static const char *CODEC_BOXES[] = {"avcC","hvcC","av1C","vpcC","dvcC","esds"};
        for (int attempt = 0; attempt < 6; attempt++) {
            const char *target = CODEC_BOXES[rng_range(s, 6)];
            int32_t box_off = find_box(buf, buf_size, target);
            if (box_off < 0) continue;
            uint32_t sz = read_u32(buf + box_off);
            if (sz < 10 || (uint32_t)box_off + sz > buf_size) continue;
            /* Corrupt a random byte in the codec config */
            uint32_t rand_byte = box_off + 8 + rng_range(s, sz - 8);
            s->scratch[rand_byte] ^= (uint8_t)(lcg(s) & 0xFF);
            break;
        }

    /* ── Strategy 21: elst_corrupt (3%) ─────────────────────────────────── */
    } else if (strategy < 90) {
        /*
         * elst: edit list
         *   v0: {4 segment_duration, 4 media_time, 4 media_rate}
         *   v1: {8 segment_duration, 8 media_time, 4 media_rate}
         */
        int32_t elst_off = find_box(buf, buf_size, "elst");
        if (elst_off < 0 || (uint32_t)elst_off + 16 > buf_size)
            return out_size;
        uint8_t ver = buf[elst_off + 8];
        uint32_t ec  = read_u32(buf + elst_off + 12);
        if (ec == 0 || ec > 1024) return out_size;
        uint32_t entry_sz = (ver == 1) ? 20 : 12;
        uint32_t ei = rng_range(s, ec);
        uint32_t eo = elst_off + 16 + ei * entry_sz;
        if (eo + entry_sz > buf_size) return out_size;
        int sub = rng_range(s, 3);
        if (sub == 0) {
            /* Corrupt segment_duration */
            if (ver == 1) write_u64(s->scratch + eo, 0xFFFFFFFFFFFFFFFFULL);
            else write_u32(s->scratch + eo, 0xFFFFFFFF);
        } else if (sub == 1) {
            /* Corrupt media_time to -1 (empty edit) or huge */
            uint32_t mt_off = eo + ((ver == 1) ? 8 : 4);
            if (ver == 1) write_u64(s->scratch + mt_off, 0xFFFFFFFFFFFFFFFFULL);
            else write_u32(s->scratch + mt_off, 0xFFFFFFFF);
        } else {
            /* Corrupt media_rate (fixed-point 16.16) to 0 or huge */
            uint32_t mr_off = eo + ((ver == 1) ? 16 : 8);
            if (mr_off + 4 <= buf_size) {
                static const uint32_t BAD[] = {0,0xFFFF0000,0x00010000,0x80000000};
                write_u32(s->scratch + mr_off, BAD[rng_range(s, 4)]);
            }
        }

    /* ── Strategy 22: splice_boxes (5%) ─────────────────────────────────── */
    } else if (strategy < 95 && add_buf && add_buf_size >= 8) {
        uint32_t add_offs[64];
        int add_n = count_boxes(add_buf, add_buf_size, add_offs, 64);
        if (add_n == 0) return out_size;
        int idx = rng_range(s, add_n);
        uint32_t src_off = add_offs[idx];
        uint32_t src_sz  = read_u32(add_buf + src_off);
        if (src_sz == 0) src_sz = (uint32_t)(add_buf_size - src_off);
        if (src_sz < 8 || src_sz > 8192) return out_size;
        if (out_size + src_sz > s->scratch_size ||
            out_size + src_sz > max_size) return out_size;
        memcpy(s->scratch + out_size, add_buf + src_off, src_sz);
        out_size += src_sz;

    /* ── Strategy 23: double_mutate (3%) ────────────────────────────────── */
    } else if (strategy < 98) {
        /* Apply two independent mutations sequentially */
        int s1 = rng_range(s, 94); /* avoid recursive double_mutate */
        out_size = do_mutate(s, buf, buf_size, add_buf, add_buf_size,
                             max_size, s1);
        if (out_size >= 8) {
            /* Make a temp copy for second pass */
            uint8_t *tmp = malloc(out_size);
            if (tmp) {
                memcpy(tmp, s->scratch, out_size);
                int s2 = rng_range(s, 94);
                size_t new_sz = do_mutate(s, tmp, out_size,
                                          add_buf, add_buf_size, max_size, s2);
                if (new_sz >= 8) out_size = new_sz;
                free(tmp);
            }
        }

    /* ── Strategy 24: random_byte fallback (2%) ─────────────────────────── */
    } else {
        uint32_t byte_idx = rng_range(s, (uint32_t)out_size);
        s->scratch[byte_idx] ^= (uint8_t)(lcg(s) & 0xFF);
    }

    return (out_size < 8) ? 0 : out_size;
}

/* AFL++ trim + queue hooks (let AFL++ handle these natively) */
uint8_t afl_custom_queue_new_entry(void *data,
                                   const uint8_t *fn_new,
                                   const uint8_t *fn_orig) {
    (void)data; (void)fn_new; (void)fn_orig;
    return 0;
}
