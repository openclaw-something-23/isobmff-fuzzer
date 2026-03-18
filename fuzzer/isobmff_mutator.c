/*
 * isobmff_mutator.c — AFL++ custom mutator for ISOBMFF / MP4 / HEIF
 *
 * ── v3 improvements over v2 ───────────────────────────────────────────────
 *
 * CRITICAL BUG FIX (v2 was broken):
 *   v2 used count_boxes() which scans ONLY top-level boxes (depth 0).
 *   In real MP4 files, stts/stsz/stco/stsc/ctts/elst live at depth 5:
 *     moov→trak→mdia→minf→stbl→stts
 *   So v2 strategies 13-17 and 21 returned out_size unchanged on every
 *   real corpus file — they were dead code. Fixed with recursive scanner.
 *
 * Structural improvements:
 *   1. Recursive box scanner (box_t flat list with depth + parent tracking)
 *   2. find_box_r() — find any box type at any nesting level
 *   3. find_boxes_r() — find all instances of a box type
 *
 * Adaptive strategy weights:
 *   - Each strategy starts with weight 1.0
 *   - afl_custom_queue_new_entry() credits the last-used strategy
 *   - Weights decay slowly; hot strategies get called more often
 *   - afl_custom_fuzz_count() returns adjusted call count
 *
 * New strategies (v3):
 *  25. cross_table_mismatch  — make stts entry_count ≠ stsz sample_count
 *  26. timescale_attack      — set mdhd/mvhd timescale to 0,1,MAX → divide-by-zero
 *  27. duration_overflow     — set moov/track duration so mvhd×timescale overflows
 *  28. iloc_corrupt          — HEIF: corrupt item extent offsets + lengths in iloc
 *  29. trun_corrupt          — fragmented MP4: corrupt trun sample_count + entries
 *  30. nal_unit_type         — parse NAL length-prefixed units, corrupt type byte
 *  31. matrix_corrupt        — corrupt 3×3 transformation matrix in tkhd/mvhd
 *  32. esds_tag_corrupt      — corrupt ES_Descriptor tag bytes in esds
 *  33. version_upgrade       — flip v0→v1 in boxes where this changes field sizes
 *  34. box_payload_havoc     — random bytes in a box's payload (targets unknown boxes)
 *  35. stsd_entry_corrupt    — corrupt codec-specific fields in stsd entries
 *  36. infe_type_inject      — HEIF: inject unusual item_type in infe boxes
 *
 * Build (MUST use gcc/clang, NOT afl-clang-fast — .so must not reference
 *        __afl_area_ptr which is only in the AFL++ binary):
 *   gcc -shared -fPIC -O2 isobmff_mutator.c -o isobmff_mutator.so
 * Use:
 *   AFL_CUSTOM_MUTATOR_LIBRARY=/path/isobmff_mutator.so afl-fuzz ...
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ── Box descriptor (recursive scan result) ─────────────────────────────── */
typedef struct {
    uint32_t off;       /* byte offset in the original buffer */
    uint32_t sz;        /* declared box size (already validated) */
    uint32_t depth;     /* nesting depth (0 = top-level) */
    uint32_t parent;    /* offset of parent box (0 if top-level) */
    char     type[4];   /* FourCC (not NUL-terminated) */
} box_t;

#define MAX_BOXES 1024

/* ── Mutator version ────────────────────────────────────────────────────── */
#ifndef MUTATOR_BUILD_DATE
#define MUTATOR_BUILD_DATE __DATE__
#endif
#define MUTATOR_VERSION "isobmff_v3"

/* ── Mutator state ──────────────────────────────────────────────────────── */
#define N_STRATEGIES 36

typedef struct {
    uint32_t  seed;
    uint8_t  *scratch;
    size_t    scratch_size;

    /* Flat box list (rebuilt each call) */
    box_t     boxes[MAX_BOXES];
    int       n_boxes;

    /* Adaptive weights */
    float     weights[N_STRATEGIES];   /* higher = called more often */
    uint32_t  calls[N_STRATEGIES];     /* call count per strategy */
    uint32_t  hits[N_STRATEGIES];      /* new-queue-entry credits */
    int       last_strategy;           /* strategy used in last call */
} my_state_t;

/* ── Known ISOBMFF FourCCs ─────────────────────────────────────────────── */
static const char *KNOWN_BOXES[] = {
    "ftyp","moov","mdat","free","skip","wide","pdin",
    "mvhd","udta","meta","ilst","mean","name","data",
    "trak","tkhd","edts","elst","tref","load",
    "mdia","mdhd","hdlr","minf","vmhd","smhd","hmhd","nmhd",
    "dinf","dref","url ","urn ",
    "stbl","stsd","stts","ctts","cslg","stsc","stsz","stz2",
    "stco","co64","stss","stsh","sdtp","sbgp","sgpd","subs",
    "avc1","avc2","avc3","hvc1","hev1","vp09","av01","mp4v",
    "dvh1","dvhe","dvav","dva1",
    "avcC","hvcC","vpcC","av1C","dvcC","dvvC",
    "mp4a","ac-3","ec-3","Opus","flac","dtsc","dtse","dtsh",
    "esds","dac3","dec3","dOps","dfLa",
    "btrt","colr","pasp","clap","fiel","gama","chrm","mdcv","clli",
    "mvex","mehd","trex","leva",
    "moof","mfhd","traf","tfhd","tfdt","trun","mfra","mfro","tfra",
    "pssh","sinf","frma","schm","schi","tenc","senc","saiz","saio",
    "pict","idat","iref","iprp","ipco","ipma","iinf","infe",
    "iloc","ispe","pixi","irot","imir","pitm","grpl","grid","iovl",
};
#define N_BOXES (sizeof(KNOWN_BOXES)/sizeof(KNOWN_BOXES[0]))

static const char *BRANDS[] = {
    "isom","iso2","iso4","iso6","mp41","mp42",
    "M4V ","M4A ","heic","heif","mif1","msf1","avis","avci",
    "dash","msdh","qt  ","MSNV",
    "\x00\x00\x00\x00","????",
};
#define N_BRANDS (sizeof(BRANDS)/sizeof(BRANDS[0]))

/* Container box types (have children) */
static const char *CONTAINERS[] = {
    "moov","trak","mdia","minf","dinf","stbl","edts","udta",
    "ilst","moof","traf","mvex","meta","iprp","ipco","iinf",
    "sinf","schi","tref",
};
#define N_CONTAINERS (sizeof(CONTAINERS)/sizeof(CONTAINERS[0]))

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

/* ── Recursive box scanner ───────────────────────────────────────────────── */
/*
 * Scan boxes within [buf+base, buf+base+len), recording each in boxes[].
 * Returns number of boxes added to *n_out.
 *
 * Recurses into known container boxes (up to depth 8 to avoid explosions).
 */
static void scan_boxes_r(const uint8_t *buf, size_t buf_len,
                         uint32_t base, uint32_t span,
                         uint32_t depth, uint32_t parent_off,
                         box_t *boxes, int *n_out) {

    if (depth > 8 || base >= buf_len) return;
    uint32_t end = base + span;
    if (end > (uint32_t)buf_len) end = (uint32_t)buf_len;

    uint32_t off = base;
    while (off + 8 <= end && *n_out < MAX_BOXES) {
        uint32_t sz = read_u32(buf + off);
        /* sz==0 means "extends to EOF", sz==1 means 64-bit largesize */
        if (sz == 1) {
            /* 64-bit largesize: [4 sz=1][4 type][8 largesize] */
            if (off + 16 > end) break;
            uint64_t lsz = read_u64(buf + off + 8);
            if (lsz < 16 || lsz > (uint64_t)(end - off)) break;
            sz = (lsz > 0xFFFFFFFFu) ? 0 : (uint32_t)lsz;
            if (!sz) break;
        } else if (sz == 0) {
            sz = end - off;
        }
        if (sz < 8 || off + sz > end) break;

        box_t *b = &boxes[*n_out];
        b->off    = off;
        b->sz     = sz;
        b->depth  = depth;
        b->parent = parent_off;
        memcpy(b->type, buf + off + 4, 4);
        (*n_out)++;

        /* Recurse into containers */
        int is_container = 0;
        for (int i = 0; i < (int)N_CONTAINERS; i++) {
            if (memcmp(b->type, CONTAINERS[i], 4) == 0) {
                is_container = 1;
                break;
            }
        }
        /* meta has a 4-byte version+flags before children */
        uint32_t child_base = off + 8;
        uint32_t child_span = sz - 8;
        if (memcmp(b->type, "meta", 4) == 0 && sz > 12) {
            child_base += 4; child_span -= 4;
        }
        if (is_container && child_span >= 8) {
            scan_boxes_r(buf, buf_len, child_base, child_span,
                         depth + 1, off, boxes, n_out);
        }

        off += sz;
    }
}

/* Build flat box list for the whole buffer */
static void build_box_list(my_state_t *s, const uint8_t *buf, size_t len) {
    s->n_boxes = 0;
    scan_boxes_r(buf, len, 0, (uint32_t)len, 0, 0, s->boxes, &s->n_boxes);
}

/* Find first box of given type (any depth); returns index or -1 */
static int find_box_r(my_state_t *s, const char *type) {
    for (int i = 0; i < s->n_boxes; i++)
        if (memcmp(s->boxes[i].type, type, 4) == 0)
            return i;
    return -1;
}

/* Fill out[] with indices of all boxes of given type; return count */
static int find_boxes_r(my_state_t *s, const char *type,
                        int *out, int max_out) {
    int n = 0;
    for (int i = 0; i < s->n_boxes && n < max_out; i++)
        if (memcmp(s->boxes[i].type, type, 4) == 0)
            out[n++] = i;
    return n;
}

/* ── Adaptive weight selection ──────────────────────────────────────────── */
static int pick_strategy(my_state_t *s) {
    /* Compute total weight */
    float total = 0;
    for (int i = 0; i < N_STRATEGIES; i++) total += s->weights[i];
    /* Weighted random */
    float r = ((float)(lcg(s) & 0xFFFF) / 65536.0f) * total;
    float acc = 0;
    for (int i = 0; i < N_STRATEGIES; i++) {
        acc += s->weights[i];
        if (r < acc) return i;
    }
    return N_STRATEGIES - 1;
}

static void credit_strategy(my_state_t *s, int strat) {
    if (strat < 0 || strat >= N_STRATEGIES) return;
    s->hits[strat]++;
    s->weights[strat] *= 1.3f;   /* boost successful strategy */
    if (s->weights[strat] > 10.0f) s->weights[strat] = 10.0f;
}

static void decay_weights(my_state_t *s) {
    for (int i = 0; i < N_STRATEGIES; i++) {
        s->weights[i] *= 0.999f;
        if (s->weights[i] < 0.2f) s->weights[i] = 0.2f;
    }
}

/* ── Common "interesting" integer values ────────────────────────────────── */
static const uint32_t BAD32[] = {
    0, 1, 2, 7, 8, 0xFF, 0x100, 0x7FFF, 0x8000,
    0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
};
#define N_BAD32 (sizeof(BAD32)/sizeof(BAD32[0]))

static const uint64_t BAD64[] = {
    0, 1, 0xFFFFFFFF, 0x100000000ULL,
    0x7FFFFFFFFFFFFFFFULL, 0x8000000000000000ULL,
    0xFFFFFFFFFFFFFFFFULL,
};
#define N_BAD64 (sizeof(BAD64)/sizeof(BAD64[0]))

/* ── AFL++ API ───────────────────────────────────────────────────────────── */
void *afl_custom_init(void *afl, unsigned int seed) {
    my_state_t *s = calloc(1, sizeof(my_state_t));
    if (!s) return NULL;
    s->seed = seed ^ (uint32_t)(uintptr_t)afl ^ (uint32_t)time(NULL);
    s->scratch_size = 4 << 20;
    s->scratch = malloc(s->scratch_size);
    if (!s->scratch) { free(s); return NULL; }
    for (int i = 0; i < N_STRATEGIES; i++) s->weights[i] = 1.0f;
    s->last_strategy = -1;
    return s;
}

void afl_custom_deinit(void *data) {
    my_state_t *s = data;
    if (s) { free(s->scratch); free(s); }
}

/* Tell AFL++ to call us N times per input (vary based on how useful we are) */
uint32_t afl_custom_fuzz_count(void *data,
                                const uint8_t *buf, size_t buf_size) {
    (void)buf; (void)buf_size;
    my_state_t *s = data;
    /* Base 6 calls; if we're finding new paths, increase to 12 */
    uint32_t total_hits = 0;
    for (int i = 0; i < N_STRATEGIES; i++) total_hits += s->hits[i];
    return (total_hits > 20) ? 12 : 6;
}

/* ── Individual strategy implementations ────────────────────────────────── */

/* Strategy 0: box_type_swap */
static size_t s_box_type_swap(my_state_t *s, uint8_t *buf, size_t buf_sz,
                               size_t out_sz) {
    if (s->n_boxes == 0) return 0;
    int idx = rng_range(s, s->n_boxes);
    box_t *b = &s->boxes[idx];
    const char *new_type = KNOWN_BOXES[rng_range(s, N_BOXES)];
    memcpy(s->scratch + b->off + 4, new_type, 4);
    return out_sz;
}

/* Strategy 1: size_edge */
static size_t s_size_edge(my_state_t *s, uint8_t *buf, size_t buf_sz,
                           size_t out_sz) {
    if (s->n_boxes == 0) return 0;
    int idx = rng_range(s, s->n_boxes);
    box_t *b = &s->boxes[idx];
    write_u32(s->scratch + b->off, BAD32[rng_range(s, N_BAD32)]);
    return out_sz;
}

/* Strategy 2: box_duplicate */
static size_t s_box_duplicate(my_state_t *s, uint8_t *buf, size_t buf_sz,
                               size_t out_sz, size_t max_sz) {
    /* prefer top-level boxes for duplication */
    int top[64]; int n_top = 0;
    for (int i = 0; i < s->n_boxes && n_top < 64; i++)
        if (s->boxes[i].depth == 0) top[n_top++] = i;
    if (n_top == 0 && s->n_boxes == 0) return 0;
    int idx = (n_top > 0) ? s->boxes[top[rng_range(s, n_top)]].off
                           : (int)s->boxes[rng_range(s, s->n_boxes)].off;
    box_t *b = &s->boxes[(n_top > 0) ? top[rng_range(s, n_top)] : rng_range(s, s->n_boxes)];
    if (b->sz > 8192 || out_sz + b->sz > s->scratch_size || out_sz + b->sz > max_sz)
        return 0;
    memcpy(s->scratch + out_sz, buf + b->off, b->sz);
    return out_sz + b->sz;
}

/* Strategy 3: box_insert */
static size_t s_box_insert(my_state_t *s, uint8_t *buf, size_t buf_sz,
                            size_t out_sz, size_t max_sz) {
    if (out_sz + 8 >= max_sz || out_sz + 8 >= s->scratch_size) return 0;
    /* Insert before a random box */
    int idx = rng_range(s, s->n_boxes > 0 ? s->n_boxes : 1);
    uint32_t ins = (s->n_boxes > 0) ? s->boxes[idx].off : (uint32_t)out_sz;
    const char *bt = KNOWN_BOXES[rng_range(s, N_BOXES)];
    uint8_t newbox[8]; write_u32(newbox, 8); memcpy(newbox + 4, bt, 4);
    memmove(s->scratch + ins + 8, s->scratch + ins, out_sz - ins);
    memcpy(s->scratch + ins, newbox, 8);
    return out_sz + 8;
}

/* Strategy 4: box_delete */
static size_t s_box_delete(my_state_t *s, uint8_t *buf, size_t buf_sz,
                            size_t out_sz) {
    /* Only delete top-level boxes (deleting nested ones breaks the parent) */
    int top[64]; int n_top = 0;
    for (int i = 0; i < s->n_boxes && n_top < 64; i++)
        if (s->boxes[i].depth == 0) top[n_top++] = i;
    if (n_top < 2) return 0; /* keep at least one */
    box_t *b = &s->boxes[top[rng_range(s, n_top)]];
    if (b->sz < 8 || b->off + b->sz > out_sz) return 0;
    memmove(s->scratch + b->off, s->scratch + b->off + b->sz,
            out_sz - b->off - b->sz);
    return out_sz - b->sz;
}

/* Strategy 5: box_truncate */
static size_t s_box_truncate(my_state_t *s, uint8_t *buf, size_t buf_sz,
                              size_t out_sz) {
    if (s->n_boxes == 0) return 0;
    int idx = rng_range(s, s->n_boxes);
    box_t *b = &s->boxes[idx];
    if (b->sz < 16) return 0;
    uint32_t new_sz = 8 + rng_range(s, b->sz - 8);
    write_u32(s->scratch + b->off, new_sz);
    /* If last top-level box, shrink output */
    if (b->depth == 0 && b->off + b->sz == out_sz)
        return b->off + new_sz;
    return out_sz;
}

/* Strategy 6: box_reorder (top-level only) */
static size_t s_box_reorder(my_state_t *s, uint8_t *buf, size_t buf_sz,
                              size_t out_sz) {
    int top[64]; int n_top = 0;
    for (int i = 0; i < s->n_boxes && n_top < 64; i++)
        if (s->boxes[i].depth == 0) top[n_top++] = i;
    if (n_top < 2) return 0;
    int ti = rng_range(s, n_top - 1);
    box_t *a = &s->boxes[top[ti]];
    box_t *b = &s->boxes[top[ti + 1]];
    if (a->sz + b->sz > 131072) return 0;
    if (a->off + a->sz + b->sz > out_sz) return 0;
    uint8_t *tmp = malloc(a->sz);
    if (!tmp) return 0;
    memcpy(tmp, s->scratch + a->off, a->sz);
    memmove(s->scratch + a->off, s->scratch + b->off, b->sz);
    memcpy(s->scratch + a->off + b->sz, tmp, a->sz);
    free(tmp);
    return out_sz;
}

/* Strategy 7: size_overflow */
static size_t s_size_overflow(my_state_t *s, uint8_t *buf, size_t buf_sz,
                               size_t out_sz) {
    if (s->n_boxes == 0) return 0;
    int idx = rng_range(s, s->n_boxes);
    box_t *b = &s->boxes[idx];
    uint32_t rem = (uint32_t)(out_sz - b->off);
    write_u32(s->scratch + b->off, rem + 8 + rng_range(s, 1024));
    return out_sz;
}

/* Strategy 8: nested_inject */
static size_t s_nested_inject(my_state_t *s, uint8_t *buf, size_t buf_sz,
                               size_t out_sz, size_t max_sz) {
    if (out_sz + 8 >= max_sz || out_sz + 8 >= s->scratch_size) return 0;
    /* Find a container box */
    int found = -1;
    for (int i = 0; i < s->n_boxes && found < 0; i++)
        for (int j = 0; j < (int)N_CONTAINERS; j++)
            if (memcmp(s->boxes[i].type, CONTAINERS[j], 4) == 0) { found = i; break; }
    if (found < 0) return 0;
    box_t *b = &s->boxes[found];
    if (b->sz < 16) return 0;
    uint32_t ins = b->off + b->sz; /* insert after box (as sibling) */
    if (ins > out_sz) return 0;
    const char *ct = KNOWN_BOXES[rng_range(s, N_BOXES)];
    uint8_t child[8]; write_u32(child, 8); memcpy(child + 4, ct, 4);
    memmove(s->scratch + ins + 8, s->scratch + ins, out_sz - ins);
    memcpy(s->scratch + ins, child, 8);
    return out_sz + 8;
}

/* Strategy 9: large_box_flood */
static size_t s_large_box_flood(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                 size_t out_sz, size_t max_sz) {
    uint32_t count = 8 + rng_range(s, 120);
    for (uint32_t i = 0; i < count; i++) {
        if (out_sz + 8 >= max_sz || out_sz + 8 >= s->scratch_size) break;
        const char *bt = (rng_range(s, 2) == 0) ? "free" : "skip";
        uint8_t box[8]; write_u32(box, 8); memcpy(box + 4, bt, 4);
        memcpy(s->scratch + out_sz, box, 8);
        out_sz += 8;
    }
    return out_sz;
}

/* Strategy 10: field_overflow (FullBox version+flags) */
static size_t s_field_overflow(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                size_t out_sz) {
    if (s->n_boxes == 0) return 0;
    int idx = rng_range(s, s->n_boxes);
    box_t *b = &s->boxes[idx];
    if (b->sz >= 12) {
        static const uint8_t FILL[] = {0xFF,0x00,0x80,0x7F,0x01,0xFE};
        memset(s->scratch + b->off + 8, FILL[rng_range(s, 6)], 4);
    }
    return out_sz;
}

/* Strategy 11: version_flags (known-bad combos) */
static size_t s_version_flags(my_state_t *s, uint8_t *buf, size_t buf_sz,
                               size_t out_sz) {
    if (s->n_boxes == 0) return 0;
    static const uint8_t VF[][4] = {
        {0x00,0x00,0x00,0x00}, {0x01,0x00,0x00,0x00},
        {0x02,0x00,0x00,0x00}, {0xFF,0xFF,0xFF,0xFF},
        {0x00,0x00,0x00,0x0f}, {0x01,0x00,0x00,0x01},
        {0x00,0x80,0x00,0x00}, {0x7F,0xFF,0xFF,0xFF},
    };
    int idx = rng_range(s, s->n_boxes);
    box_t *b = &s->boxes[idx];
    if (b->sz >= 12)
        memcpy(s->scratch + b->off + 8, VF[rng_range(s, 8)], 4);
    return out_sz;
}

/* Strategy 12: splice_boxes (crossover) */
static size_t s_splice_boxes(my_state_t *s, uint8_t *buf, size_t buf_sz,
                              uint8_t *add_buf, size_t add_buf_sz,
                              size_t out_sz, size_t max_sz) {
    if (!add_buf || add_buf_sz < 8) return 0;
    /* Quick top-level scan of add_buf */
    uint32_t aoffs[64]; int an = 0;
    uint32_t aoff = 0;
    while (aoff + 8 <= (uint32_t)add_buf_sz && an < 64) {
        uint32_t asq = read_u32(add_buf + aoff);
        if (!asq) asq = (uint32_t)(add_buf_sz - aoff);
        if (asq < 8 || aoff + asq > (uint32_t)add_buf_sz) break;
        aoffs[an++] = aoff; aoff += asq;
    }
    if (!an) return 0;
    uint32_t src = aoffs[rng_range(s, an)];
    uint32_t ssz = read_u32(add_buf + src);
    if (!ssz) ssz = (uint32_t)(add_buf_sz - src);
    if (ssz < 8 || ssz > 8192) return 0;
    if (out_sz + ssz > s->scratch_size || out_sz + ssz > max_sz) return 0;
    memcpy(s->scratch + out_sz, add_buf + src, ssz);
    return out_sz + ssz;
}

/* Strategy 13: stts_corrupt — NOW WORKS (recursive scan finds it) */
static size_t s_stts_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                              size_t out_sz) {
    int idx = find_box_r(s, "stts");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    if (b->off + 16 > buf_sz || b->sz < 16) return 0;
    uint32_t ec = read_u32(buf + b->off + 12);
    int sub = rng_range(s, 4);
    if (sub == 0) {
        /* Corrupt entry_count → OOM / infinite loop */
        write_u32(s->scratch + b->off + 12, BAD32[rng_range(s, N_BAD32)]);
    } else if (sub == 1 && ec > 0 && ec < 65536) {
        /* Corrupt a random delta to 0 or MAX */
        uint32_t ei = rng_range(s, ec);
        uint32_t eo = b->off + 16 + ei * 8 + 4;
        if (eo + 4 <= buf_sz)
            write_u32(s->scratch + eo, BAD32[rng_range(s, N_BAD32)]);
    } else if (sub == 2 && ec > 0) {
        /* Set first sample_count to 0 → edge case in parser */
        if (b->off + 16 + 4 <= buf_sz)
            write_u32(s->scratch + b->off + 16, 0);
    } else if (sub == 3) {
        /* Corrupt box size to make it appear to have more entries */
        write_u32(s->scratch + b->off, b->sz + 8 * (rng_range(s, 100) + 1));
    }
    return out_sz;
}

/* Strategy 14: stsz_corrupt */
static size_t s_stsz_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                              size_t out_sz) {
    int idx = find_box_r(s, "stsz");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    if (b->off + 20 > buf_sz) return 0;
    uint32_t sc = read_u32(buf + b->off + 16);
    int sub = rng_range(s, 3);
    if (sub == 0) {
        write_u32(s->scratch + b->off + 16, BAD32[rng_range(s, N_BAD32)]);
    } else if (sub == 1) {
        /* uniform sample_size → huge → any code computing total size overflows */
        write_u32(s->scratch + b->off + 12, BAD32[rng_range(s, N_BAD32)]);
    } else if (sc > 0 && sc < 65536) {
        uint32_t ei = rng_range(s, sc);
        uint32_t eo = b->off + 20 + ei * 4;
        if (eo + 4 <= buf_sz)
            write_u32(s->scratch + eo, BAD32[rng_range(s, N_BAD32)]);
    }
    return out_sz;
}

/* Strategy 15: stco_overflow */
static size_t s_stco_overflow(my_state_t *s, uint8_t *buf, size_t buf_sz,
                               size_t out_sz) {
    int idx = find_box_r(s, "stco");
    int is64 = 0;
    if (idx < 0) { idx = find_box_r(s, "co64"); is64 = 1; }
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    if (b->off + 16 > buf_sz) return 0;
    uint32_t ec = read_u32(buf + b->off + 12);
    if (ec == 0 || ec > 65536) {
        /* just corrupt the count */
        write_u32(s->scratch + b->off + 12, BAD32[rng_range(s, N_BAD32)]);
        return out_sz;
    }
    uint32_t ei = rng_range(s, ec);
    uint32_t eo = b->off + 16 + ei * (is64 ? 8 : 4);
    if (eo + (is64 ? 8u : 4u) > buf_sz) return 0;
    if (is64)
        write_u64(s->scratch + eo, BAD64[rng_range(s, N_BAD64)]);
    else
        write_u32(s->scratch + eo, BAD32[rng_range(s, N_BAD32)]);
    return out_sz;
}

/* Strategy 16: stsc_corrupt */
static size_t s_stsc_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                              size_t out_sz) {
    int idx = find_box_r(s, "stsc");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    if (b->off + 16 > buf_sz) return 0;
    uint32_t ec = read_u32(buf + b->off + 12);
    if (ec == 0) {
        write_u32(s->scratch + b->off + 12, BAD32[rng_range(s, N_BAD32)]);
        return out_sz;
    }
    if (ec > 65536) return 0;
    uint32_t ei = rng_range(s, ec);
    uint32_t eo = b->off + 16 + ei * 12;
    if (eo + 12 > buf_sz) return 0;
    /* Corrupt samples_per_chunk (field[1]) to 0 → division by zero */
    write_u32(s->scratch + eo + 4, BAD32[rng_range(s, N_BAD32)]);
    return out_sz;
}

/* Strategy 17: ctts_negative */
static size_t s_ctts_negative(my_state_t *s, uint8_t *buf, size_t buf_sz,
                               size_t out_sz) {
    int idx = find_box_r(s, "ctts");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    if (b->off + 16 > buf_sz) return 0;
    uint32_t ec = read_u32(buf + b->off + 12);
    if (ec == 0 || ec > 65536) {
        write_u32(s->scratch + b->off + 12, BAD32[rng_range(s, N_BAD32)]);
        return out_sz;
    }
    uint32_t ei = rng_range(s, ec);
    uint32_t eo = b->off + 16 + ei * 8 + 4;
    if (eo + 4 > buf_sz) return 0;
    write_u32(s->scratch + eo, BAD32[rng_range(s, N_BAD32)]);
    return out_sz;
}

/* Strategy 18: ftyp_brand_fuzz */
static size_t s_ftyp_brand_fuzz(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                 size_t out_sz, size_t max_sz) {
    int idx = find_box_r(s, "ftyp");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    if (b->off + 16 > buf_sz) return 0;
    int sub = rng_range(s, 3);
    if (sub == 0) {
        memcpy(s->scratch + b->off + 8, BRANDS[rng_range(s, N_BRANDS)], 4);
    } else if (sub == 1 && out_sz + 4 <= max_sz && out_sz + 4 <= s->scratch_size) {
        uint32_t ins = b->off + b->sz;
        if (ins <= out_sz) {
            memmove(s->scratch + ins + 4, s->scratch + ins, out_sz - ins);
            memcpy(s->scratch + ins, BRANDS[rng_range(s, N_BRANDS)], 4);
            write_u32(s->scratch + b->off, b->sz + 4);
            return out_sz + 4;
        }
    } else {
        write_u32(s->scratch + b->off + 12, BAD32[rng_range(s, N_BAD32)]);
    }
    return out_sz;
}

/* Strategy 19: nal_length_corrupt */
static size_t s_nal_length_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                    size_t out_sz) {
    int idx = find_box_r(s, "mdat");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    if (b->sz < 16 || b->off + b->sz > buf_sz) return 0;
    uint32_t payload = b->sz - 8;
    if (payload < 4) return 0;
    uint32_t rand_off = b->off + 8 + rng_range(s, payload - 4);
    /* Pick a bad NAL length */
    static const uint32_t BAD_NAL[] = {
        0xFFFFFFFF, 0x80000000, 0, 1, 0x7FFFFFFF,
        0x00000001,  /* SC — wrong for AVCC mode */
        0x00000003,  /* emulation prevention byte */
    };
    write_u32(s->scratch + rand_off, BAD_NAL[rng_range(s, 7)]);
    return out_sz;
}

/* Strategy 20: codec_box_corrupt */
static size_t s_codec_box_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                   size_t out_sz) {
    static const char *CODEC_BOXES[] = {"avcC","hvcC","av1C","vpcC","esds","dvcC"};
    for (int a = 0; a < 6; a++) {
        int idx = find_box_r(s, CODEC_BOXES[a]);
        if (idx < 0) continue;
        box_t *b = &s->boxes[idx];
        if (b->sz < 10 || b->off + b->sz > buf_sz) continue;
        uint32_t roff = b->off + 8 + rng_range(s, b->sz - 8);
        s->scratch[roff] ^= (uint8_t)(lcg(s) & 0xFF);
        return out_sz;
    }
    return 0;
}

/* Strategy 21: elst_corrupt — NOW WORKS */
static size_t s_elst_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                              size_t out_sz) {
    int idx = find_box_r(s, "elst");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    if (b->off + 16 > buf_sz) return 0;
    uint8_t ver = buf[b->off + 8];
    uint32_t ec  = read_u32(buf + b->off + 12);
    if (ec == 0 || ec > 1024) {
        write_u32(s->scratch + b->off + 12, BAD32[rng_range(s, N_BAD32)]);
        return out_sz;
    }
    uint32_t esz = (ver == 1) ? 20 : 12;
    uint32_t ei = rng_range(s, ec);
    uint32_t eo = b->off + 16 + ei * esz;
    if (eo + esz > buf_sz) return 0;
    int field = rng_range(s, 3);
    if (field == 0) {
        if (ver == 1) write_u64(s->scratch + eo, BAD64[rng_range(s, N_BAD64)]);
        else          write_u32(s->scratch + eo, BAD32[rng_range(s, N_BAD32)]);
    } else if (field == 1) {
        uint32_t mto = eo + ((ver == 1) ? 8 : 4);
        if (ver == 1) write_u64(s->scratch + mto, BAD64[rng_range(s, N_BAD64)]);
        else          write_u32(s->scratch + mto, BAD32[rng_range(s, N_BAD32)]);
    } else {
        uint32_t mro = eo + ((ver == 1) ? 16 : 8);
        if (mro + 4 <= buf_sz) {
            static const uint32_t MR[] = {0,0xFFFF0000,0x00010000,0x80000000};
            write_u32(s->scratch + mro, MR[rng_range(s, 4)]);
        }
    }
    return out_sz;
}

/* Strategy 22: double_mutate */
static size_t s_double_mutate(my_state_t *s, uint8_t *buf, size_t buf_sz,
                               uint8_t *add_buf, size_t add_buf_sz,
                               size_t out_sz, size_t max_sz);

/* ── NEW STRATEGIES (v3) ─────────────────────────────────────────────────── */

/* Strategy 23: random_byte */
static size_t s_random_byte(my_state_t *s, uint8_t *buf, size_t buf_sz,
                             size_t out_sz) {
    s->scratch[rng_range(s, (uint32_t)out_sz)] ^= (uint8_t)(lcg(s) & 0xFF);
    return out_sz;
}

/* Strategy 24: cross_table_mismatch
 * Make stts entry_count inconsistent with stsz sample_count.
 * Many parsers compute timeline from stts then index stsz[i] — mismatch = OOB.
 */
static size_t s_cross_table_mismatch(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                      size_t out_sz) {
    int si = find_box_r(s, "stts");
    int zi = find_box_r(s, "stsz");
    if (si < 0 || zi < 0) return 0;
    box_t *stts = &s->boxes[si];
    box_t *stsz = &s->boxes[zi];
    if (stts->off + 16 > buf_sz || stsz->off + 20 > buf_sz) return 0;

    uint32_t stts_ec = read_u32(buf + stts->off + 12);
    uint32_t stsz_sc = read_u32(buf + stsz->off + 16);
    int sub = rng_range(s, 3);

    if (sub == 0 && stsz_sc > 0) {
        /* Make stts claim more samples than stsz has entries */
        write_u32(s->scratch + stts->off + 12, stsz_sc + 1 + rng_range(s, 100));
    } else if (sub == 1 && stts_ec > 0) {
        /* Make stsz claim fewer samples than stts total */
        uint32_t stts_total = 0;
        for (uint32_t e = 0; e < stts_ec && e < 256; e++) {
            uint32_t eo = stts->off + 16 + e * 8;
            if (eo + 8 > buf_sz) break;
            stts_total += read_u32(buf + eo); /* sum of sample_counts */
        }
        if (stts_total > 1)
            write_u32(s->scratch + stsz->off + 16,
                      stts_total - 1 - rng_range(s, stts_total / 2));
    } else {
        /* Corrupt stco entry_count to 0 while stsc still references chunks */
        int ci = find_box_r(s, "stco");
        if (ci >= 0 && s->boxes[ci].off + 16 <= buf_sz)
            write_u32(s->scratch + s->boxes[ci].off + 12, 0);
    }
    return out_sz;
}

/* Strategy 25: timescale_attack
 * Set mdhd or mvhd timescale to 0 or 1.
 * timescale=0 → division by zero in PTS/DTS calculations.
 * timescale=1 → duration values overflow when converted to ns.
 */
static size_t s_timescale_attack(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                  size_t out_sz) {
    /* Try mdhd first, then mvhd */
    static const char *TARGETS[] = {"mdhd","mvhd"};
    for (int t = 0; t < 2; t++) {
        int idx = find_box_r(s, TARGETS[t]);
        if (idx < 0) continue;
        box_t *b = &s->boxes[idx];
        if (b->off + 12 > buf_sz) continue;
        uint8_t ver = buf[b->off + 8];
        /*
         * mdhd/mvhd layout:
         *   v0: [4 sz][4 type][1 v][3 f][4 ctime][4 mtime][4 timescale][4 dur]
         *   v1: [4 sz][4 type][1 v][3 f][8 ctime][8 mtime][4 timescale][8 dur]
         */
        uint32_t ts_off = b->off + 12 + ((ver == 1) ? 16 : 8);
        if (ts_off + 4 > buf_sz) continue;
        static const uint32_t BAD_TS[] = {0, 1, 0xFFFFFFFF, 0x80000000, 1000000000u};
        write_u32(s->scratch + ts_off, BAD_TS[rng_range(s, 5)]);
        return out_sz;
    }
    return 0;
}

/* Strategy 26: duration_overflow
 * Set mvhd/mdhd duration to MAX while keeping a small timescale.
 * Parsers that compute duration_ns = duration * 1e9 / timescale will overflow.
 */
static size_t s_duration_overflow(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                   size_t out_sz) {
    static const char *TARGETS[] = {"mvhd","mdhd","tkhd"};
    for (int t = 0; t < 3; t++) {
        int boxes_idx[16]; int nb = find_boxes_r(s, TARGETS[t], boxes_idx, 16);
        for (int j = 0; j < nb; j++) {
            box_t *b = &s->boxes[boxes_idx[j]];
            if (b->off + 12 > buf_sz) continue;
            uint8_t ver = buf[b->off + 8];
            /* duration field offset */
            uint32_t dur_off;
            if (strcmp(TARGETS[t], "tkhd") == 0)
                dur_off = b->off + 12 + ((ver == 1) ? 20 : 12);
            else
                dur_off = b->off + 12 + ((ver == 1) ? 20 : 12);
            if (dur_off + 4 > buf_sz) continue;
            if (ver == 1 && dur_off + 8 <= buf_sz)
                write_u64(s->scratch + dur_off, BAD64[rng_range(s, N_BAD64)]);
            else
                write_u32(s->scratch + dur_off, BAD32[rng_range(s, N_BAD32)]);
            return out_sz;
        }
    }
    return 0;
}

/* Strategy 27: iloc_corrupt
 * HEIF/AVIF: corrupt item location extents.
 * iloc layout (simplified, v0/v1):
 *   [4 sz]["iloc"][1 v][3 f]
 *   [1 offset_size/length_size nibbles][1 base_offset/index_size nibbles]
 *   [2 item_count]
 *   for each item: [2 item_id][2 extent_count]
 *     for each extent: [offset_size bytes][length_size bytes]
 * We directly corrupt random bytes in the extent data.
 */
static size_t s_iloc_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                              size_t out_sz) {
    int idx = find_box_r(s, "iloc");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    if (b->off + 16 > buf_sz || b->sz < 16) return 0;

    uint8_t ver = buf[b->off + 8];
    /* offset_size is high nibble of byte 12, length_size is low nibble */
    uint8_t sizes = buf[b->off + 12];
    uint8_t offset_sz = (sizes >> 4) & 0xF;
    uint8_t length_sz =  sizes       & 0xF;
    /* Clamp to valid values (0,4,8) */
    if (offset_sz != 4 && offset_sz != 8) offset_sz = 4;
    if (length_sz != 4 && length_sz != 8) length_sz = 4;

    int sub = rng_range(s, 3);
    if (sub == 0) {
        /* Corrupt offset_size/length_size nibble byte */
        static const uint8_t BAD_SIZES[] = {0x00,0x44,0x48,0x84,0x88,0xFF,0x40,0x04};
        s->scratch[b->off + 12] = BAD_SIZES[rng_range(s, 8)];
    } else if (sub == 1) {
        /* Corrupt item_count to huge */
        uint32_t ic_off = b->off + 14;
        if (ic_off + 2 > buf_sz) return 0;
        uint16_t bad_ic = (uint16_t)BAD32[rng_range(s, N_BAD32)];
        s->scratch[ic_off]     = bad_ic >> 8;
        s->scratch[ic_off + 1] = bad_ic & 0xFF;
    } else {
        /* Corrupt a random byte in the extent payload */
        if (b->sz < 20) return 0;
        uint32_t roff = b->off + 16 + rng_range(s, b->sz - 16);
        if (roff < buf_sz) {
            if (offset_sz > 0 && rng_range(s, 2)) {
                /* Write a huge offset (file offset beyond file size) */
                if (offset_sz == 8 && roff + 8 <= buf_sz)
                    write_u64(s->scratch + roff, BAD64[rng_range(s, N_BAD64)]);
                else if (roff + 4 <= buf_sz)
                    write_u32(s->scratch + roff, BAD32[rng_range(s, N_BAD32)]);
            } else {
                s->scratch[roff] ^= (uint8_t)(lcg(s) & 0xFF);
            }
        }
    }
    return out_sz;
}

/* Strategy 28: trun_corrupt
 * Fragmented MP4: corrupt trun (Track Run) entries.
 * trun: [4 sz]["trun"][1 v][3 flags][4 sample_count][4? data_offset]
 *       [sample_count × variable entry]
 * flags bits: 0x100=data_offset, 0x200=first_sample_flags,
 *             0x400=sample_duration, 0x800=sample_size,
 *             0x1000=sample_flags, 0x2000=composition_time_offset
 */
static size_t s_trun_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                              size_t out_sz) {
    int boxes_idx[16]; int nb = find_boxes_r(s, "trun", boxes_idx, 16);
    if (nb == 0) return 0;
    box_t *b = &s->boxes[boxes_idx[rng_range(s, nb)]];
    if (b->off + 16 > buf_sz) return 0;

    uint32_t flags = read_u32(buf + b->off + 8) & 0xFFFFFF;
    int sub = rng_range(s, 3);
    if (sub == 0) {
        /* Corrupt sample_count → parser iterates wrong number of entries */
        write_u32(s->scratch + b->off + 12, BAD32[rng_range(s, N_BAD32)]);
    } else if (sub == 1 && (flags & 0x100)) {
        /* Corrupt data_offset → points outside mdat */
        uint32_t do_off = b->off + 16;
        if (do_off + 4 <= buf_sz)
            write_u32(s->scratch + do_off, BAD32[rng_range(s, N_BAD32)]);
    } else {
        /* Inject weird flags combination */
        uint32_t bad_flags = (read_u32(buf + b->off + 8) & 0xFF000000) |
                             (uint32_t)(rng_range(s, 0x4000));
        write_u32(s->scratch + b->off + 8, bad_flags);
    }
    return out_sz;
}

/* Strategy 29: nal_unit_type
 * Parse NAL length-prefixed units in mdat (AVCC/HVCC mode).
 * Corrupt the NAL unit type byte (first byte after length prefix).
 * Interesting NAL types: SEI (6), SPS (7), PPS (8), IDR (5), non-IDR (1),
 * reserved (0), unspecified (0xFF).
 */
static size_t s_nal_unit_type(my_state_t *s, uint8_t *buf, size_t buf_sz,
                               size_t out_sz) {
    int idx = find_box_r(s, "mdat");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    if (b->sz < 16 || b->off + b->sz > buf_sz) return 0;

    /* Walk NAL length-prefixed units */
    uint32_t pos = b->off + 8;
    uint32_t end = b->off + b->sz;
    int found = 0;
    int target_nal = rng_range(s, 16); /* walk to the Nth NAL */
    while (pos + 4 < end) {
        uint32_t nal_len = read_u32(buf + pos);
        if (nal_len == 0 || pos + 4 + nal_len > end) break;
        if (found == target_nal) {
            /* Corrupt the NAL unit type byte */
            static const uint8_t BAD_TYPES[] = {
                0x00, 0x01, 0x05, 0x06, 0x07, 0x08,
                0x0C, 0x0D, 0x0E, 0x0F,   /* reserved */
                0x1F,                       /* unspecified */
                0x40, 0x60, 0x7E, 0xFF,    /* HEVC/weird */
            };
            s->scratch[pos + 4] = BAD_TYPES[rng_range(s, 14)];
            return out_sz;
        }
        pos += 4 + nal_len;
        found++;
    }
    return 0;
}

/* Strategy 30: matrix_corrupt
 * Corrupt the 3×3 transformation matrix in tkhd or mvhd.
 * Matrix is 9 × 4-byte fixed-point values.
 * Identity: [0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000]
 * Some parsers use these for dimensions — corrupt → weird allocations.
 */
static size_t s_matrix_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                size_t out_sz) {
    static const char *TARGETS[] = {"tkhd","mvhd"};
    for (int t = 0; t < 2; t++) {
        int idx = find_box_r(s, TARGETS[t]);
        if (idx < 0) continue;
        box_t *b = &s->boxes[idx];
        if (b->off + 12 > buf_sz) continue;
        uint8_t ver = buf[b->off + 8];
        /* Matrix starts at:
         *   tkhd v0: offset 12+8+8+4+4 = 36, v1: 12+16+16+4+4 = 52
         *   mvhd v0: offset 12+8+8+4+4+4+4+4+4 = 44, v1: 12+16+16+4+8+... = 68 */
        uint32_t mat_off;
        if (memcmp(TARGETS[t], "tkhd", 4) == 0)
            mat_off = b->off + 12 + ((ver == 1) ? 40 : 24);
        else
            mat_off = b->off + 12 + ((ver == 1) ? 56 : 36);
        if (mat_off + 36 > buf_sz) continue;
        /* Corrupt one matrix element */
        uint32_t elem = rng_range(s, 9);
        write_u32(s->scratch + mat_off + elem * 4, BAD32[rng_range(s, N_BAD32)]);
        return out_sz;
    }
    return 0;
}

/* Strategy 31: esds_tag_corrupt
 * esds contains ES_Descriptor, a tag-length-value structure.
 * Tag bytes: 0x03=ES_Descriptor, 0x04=DecoderConfigDescriptor,
 *            0x05=DecoderSpecificInfo, 0x06=SLConfigDescriptor.
 * Corrupt tag type, length, or objectTypeIndication.
 */
static size_t s_esds_tag_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                  size_t out_sz) {
    int idx = find_box_r(s, "esds");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    /* esds payload starts at off+12 (after size+type+version+flags) */
    if (b->off + 16 > buf_sz || b->sz < 16) return 0;
    uint32_t payload_start = b->off + 12;
    uint32_t payload_end   = b->off + b->sz;
    int sub = rng_range(s, 3);
    if (sub == 0) {
        /* Corrupt first tag byte */
        static const uint8_t BAD_TAGS[] = {0x00,0x01,0x03,0x04,0x05,0x06,0xFF,0x80};
        s->scratch[payload_start] = BAD_TAGS[rng_range(s, 8)];
    } else if (sub == 1) {
        /* Corrupt the length field after first tag */
        if (payload_start + 5 < payload_end) {
            /* ES_Descriptor length: up to 4 bytes (with 0x80 continuation) */
            /* Just write a huge simple length */
            s->scratch[payload_start + 1] = 0xFF;
            s->scratch[payload_start + 2] = 0xFF;
        }
    } else {
        /* Corrupt objectTypeIndication in DecoderConfigDescriptor */
        /* Scan for tag 0x04 */
        for (uint32_t p = payload_start; p + 6 < payload_end; p++) {
            if (buf[p] == 0x04) {
                s->scratch[p + 5] ^= (uint8_t)(lcg(s) & 0xFF);
                break;
            }
        }
    }
    return out_sz;
}

/* Strategy 32: version_upgrade
 * Flip version byte from 0 to 1 (or 1 to 0) in FullBoxes.
 * In mvhd/mdhd/tkhd: v1 uses 64-bit timestamps instead of 32-bit.
 * Flipping this without adjusting field sizes confuses parsers that
 * expect the payload size to match the version.
 */
static size_t s_version_upgrade(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                 size_t out_sz) {
    static const char *VERSION_BOXES[] = {
        "mvhd","mdhd","tkhd","tfdt","mehd","elst","ctts","stts","stsz"
    };
    int found = -1;
    for (int t = 0; t < 9 && found < 0; t++) {
        int idx = find_box_r(s, VERSION_BOXES[t]);
        if (idx >= 0 && s->boxes[idx].off + 9 <= buf_sz) found = idx;
    }
    if (found < 0) {
        /* Fallback: any box with sz >= 12 */
        for (int i = 0; i < s->n_boxes; i++) {
            if (s->boxes[i].sz >= 12 && s->boxes[i].off + 9 <= buf_sz) {
                found = i; break;
            }
        }
    }
    if (found < 0) return 0;
    box_t *b = &s->boxes[found];
    /* Toggle version byte */
    s->scratch[b->off + 8] = (buf[b->off + 8] == 0) ? 1 : 0;
    return out_sz;
}

/* Strategy 33: box_payload_havoc
 * Pick a random box and corrupt a random range of its payload bytes.
 * Good for finding off-by-one errors in fixed-size field parsers.
 */
static size_t s_box_payload_havoc(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                   size_t out_sz) {
    if (s->n_boxes == 0) return 0;
    int idx = rng_range(s, s->n_boxes);
    box_t *b = &s->boxes[idx];
    if (b->sz < 12 || b->off + b->sz > buf_sz) return 0;
    uint32_t payload_start = b->off + 8;
    uint32_t payload_end   = b->off + b->sz;
    uint32_t len = payload_end - payload_start;
    /* Corrupt 1–16 random bytes */
    uint32_t n = 1 + rng_range(s, 15);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t roff = payload_start + rng_range(s, len);
        s->scratch[roff] ^= (uint8_t)(lcg(s) & 0xFF);
    }
    return out_sz;
}

/* Strategy 34: stsd_entry_corrupt
 * stsd contains codec-specific entries. Each has:
 *   [4 sz][4 type][6 reserved][2 data_ref_index][codec-specific...]
 * Corrupt the codec-specific fields (width/height, sample_rate, channel_count…)
 */
static size_t s_stsd_entry_corrupt(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                    size_t out_sz) {
    int idx = find_box_r(s, "stsd");
    if (idx < 0) return 0;
    box_t *b = &s->boxes[idx];
    /* stsd: [4 sz]["stsd"][1v][3f][4 entry_count][entries...] */
    if (b->off + 16 > buf_sz) return 0;
    uint32_t entry_start = b->off + 16;
    if (entry_start + 8 > buf_sz) return 0;
    uint32_t esz = read_u32(buf + entry_start);
    if (esz < 24 || entry_start + esz > buf_sz) return 0;
    /* offset into codec-specific data (after [4sz][4type][6res][2dri]) */
    uint32_t codec_off = entry_start + 16;
    uint32_t codec_len = entry_start + esz - codec_off;
    if (codec_len < 4) return 0;
    int sub = rng_range(s, 3);
    if (sub == 0) {
        /* Corrupt width/height (common visual sample entry fields) */
        if (codec_off + 8 <= buf_sz) {
            write_u32(s->scratch + codec_off,     BAD32[rng_range(s, N_BAD32)]);
            write_u32(s->scratch + codec_off + 4, BAD32[rng_range(s, N_BAD32)]);
        }
    } else if (sub == 1) {
        /* Corrupt channel_count / sample_size (audio) */
        if (codec_off + 4 <= buf_sz) {
            s->scratch[codec_off + 0] = 0; s->scratch[codec_off + 1] = 0; /* channels=0 */
            s->scratch[codec_off + 2] = (uint8_t)(rng_range(s,2)?0:0xFF);
            s->scratch[codec_off + 3] = (uint8_t)(rng_range(s,2)?0:0xFF);
        }
    } else {
        /* Corrupt a random field */
        uint32_t roff = codec_off + rng_range(s, codec_len);
        if (roff + 4 <= buf_sz)
            write_u32(s->scratch + roff, BAD32[rng_range(s, N_BAD32)]);
    }
    return out_sz;
}

/* Strategy 35: infe_type_inject
 * HEIF: infe (item info entry) boxes describe items.
 * Corrupt item_type or inject known-unusual types.
 */
static size_t s_infe_type_inject(my_state_t *s, uint8_t *buf, size_t buf_sz,
                                  size_t out_sz) {
    int boxes_idx[32]; int nb = find_boxes_r(s, "infe", boxes_idx, 32);
    if (nb == 0) return 0;
    box_t *b = &s->boxes[boxes_idx[rng_range(s, nb)]];
    if (b->off + 12 > buf_sz) return 0;
    uint8_t ver = buf[b->off + 8];
    /*
     * infe v0/v1: [4sz]["infe"][1v][3f][2 item_id][2 item_prot_index][NULL-term name][NULL-term mime]
     * infe v2+:   [4sz]["infe"][1v][3f][2/4 item_id][2 item_prot_index][4 item_type][NULL-term name]
     */
    if (ver >= 2) {
        uint32_t type_off = b->off + 12 + ((ver >= 3) ? 6 : 4) + 2;
        if (type_off + 4 <= buf_sz) {
            static const char *INFE_TYPES[] = {
                "hvc1","av01","avc1","jpeg","png ","exif","mime",
                "thmb","cdsc","grid","iovl","iden",
                "\x00\x00\x00\x00","????",
            };
            memcpy(s->scratch + type_off, INFE_TYPES[rng_range(s, 14)], 4);
        }
    } else {
        /* v0/v1: just corrupt random bytes in the name field */
        uint32_t name_off = b->off + 16;
        if (name_off + 2 <= buf_sz)
            s->scratch[name_off] ^= (uint8_t)(lcg(s) & 0xFF);
    }
    return out_sz;
}

/* ── double_mutate (forward ref impl) ─────────────────────────────────────── */
static size_t do_one_mutate(my_state_t *s, uint8_t *buf, size_t buf_sz,
                             uint8_t *add_buf, size_t add_buf_sz,
                             size_t out_sz, size_t max_sz, int strat);

static size_t s_double_mutate(my_state_t *s, uint8_t *buf, size_t buf_sz,
                               uint8_t *add_buf, size_t add_buf_sz,
                               size_t out_sz, size_t max_sz) {
    /* pick two different strategies, excluding double_mutate itself */
    int s1 = rng_range(s, N_STRATEGIES - 1); /* 0..34 */
    out_sz = do_one_mutate(s, buf, buf_sz, add_buf, add_buf_sz, out_sz, max_sz, s1);
    if (out_sz < 8) return 0;
    /* Make a snapshot so second mutation sees the result of the first */
    uint8_t *snap = malloc(out_sz);
    if (!snap) return out_sz;
    memcpy(snap, s->scratch, out_sz);
    int s2 = rng_range(s, N_STRATEGIES - 1);
    /* rebuild box list from mutated buffer */
    build_box_list(s, snap, out_sz);
    size_t new_sz = do_one_mutate(s, snap, out_sz, add_buf, add_buf_sz, out_sz, max_sz, s2);
    free(snap);
    return (new_sz >= 8) ? new_sz : out_sz;
}

/* ── Dispatch table ──────────────────────────────────────────────────────── */
static size_t do_one_mutate(my_state_t *s, uint8_t *buf, size_t buf_sz,
                              uint8_t *add_buf, size_t add_buf_sz,
                              size_t out_sz, size_t max_sz, int strat) {
    size_t r = 0;
    switch (strat % N_STRATEGIES) {
        case  0: r = s_box_type_swap(s, buf, buf_sz, out_sz); break;
        case  1: r = s_size_edge(s, buf, buf_sz, out_sz); break;
        case  2: r = s_box_duplicate(s, buf, buf_sz, out_sz, max_sz); break;
        case  3: r = s_box_insert(s, buf, buf_sz, out_sz, max_sz); break;
        case  4: r = s_box_delete(s, buf, buf_sz, out_sz); break;
        case  5: r = s_box_truncate(s, buf, buf_sz, out_sz); break;
        case  6: r = s_box_reorder(s, buf, buf_sz, out_sz); break;
        case  7: r = s_size_overflow(s, buf, buf_sz, out_sz); break;
        case  8: r = s_nested_inject(s, buf, buf_sz, out_sz, max_sz); break;
        case  9: r = s_large_box_flood(s, buf, buf_sz, out_sz, max_sz); break;
        case 10: r = s_field_overflow(s, buf, buf_sz, out_sz); break;
        case 11: r = s_version_flags(s, buf, buf_sz, out_sz); break;
        case 12: r = s_splice_boxes(s, buf, buf_sz, add_buf, add_buf_sz, out_sz, max_sz); break;
        case 13: r = s_stts_corrupt(s, buf, buf_sz, out_sz); break;
        case 14: r = s_stsz_corrupt(s, buf, buf_sz, out_sz); break;
        case 15: r = s_stco_overflow(s, buf, buf_sz, out_sz); break;
        case 16: r = s_stsc_corrupt(s, buf, buf_sz, out_sz); break;
        case 17: r = s_ctts_negative(s, buf, buf_sz, out_sz); break;
        case 18: r = s_ftyp_brand_fuzz(s, buf, buf_sz, out_sz, max_sz); break;
        case 19: r = s_nal_length_corrupt(s, buf, buf_sz, out_sz); break;
        case 20: r = s_codec_box_corrupt(s, buf, buf_sz, out_sz); break;
        case 21: r = s_elst_corrupt(s, buf, buf_sz, out_sz); break;
        case 22: r = s_double_mutate(s, buf, buf_sz, add_buf, add_buf_sz, out_sz, max_sz); break;
        case 23: r = s_random_byte(s, buf, buf_sz, out_sz); break;
        case 24: r = s_cross_table_mismatch(s, buf, buf_sz, out_sz); break;
        case 25: r = s_timescale_attack(s, buf, buf_sz, out_sz); break;
        case 26: r = s_duration_overflow(s, buf, buf_sz, out_sz); break;
        case 27: r = s_iloc_corrupt(s, buf, buf_sz, out_sz); break;
        case 28: r = s_trun_corrupt(s, buf, buf_sz, out_sz); break;
        case 29: r = s_nal_unit_type(s, buf, buf_sz, out_sz); break;
        case 30: r = s_matrix_corrupt(s, buf, buf_sz, out_sz); break;
        case 31: r = s_esds_tag_corrupt(s, buf, buf_sz, out_sz); break;
        case 32: r = s_version_upgrade(s, buf, buf_sz, out_sz); break;
        case 33: r = s_box_payload_havoc(s, buf, buf_sz, out_sz); break;
        case 34: r = s_stsd_entry_corrupt(s, buf, buf_sz, out_sz); break;
        case 35: r = s_infe_type_inject(s, buf, buf_sz, out_sz); break;
        default: break;
    }
    return (r >= 8) ? r : 0;
}

/* ── Main entry point ────────────────────────────────────────────────────── */
size_t afl_custom_fuzz(void *data,
                       uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
    my_state_t *s = data;
    if (!s || !buf || buf_size < 8) return 0;
    if (buf_size > s->scratch_size - 1024) return 0;

    memcpy(s->scratch, buf, buf_size);

    /* Build recursive box list */
    build_box_list(s, buf, buf_size);

    /* Pick strategy (adaptive weighted) */
    int strat = pick_strategy(s);
    s->last_strategy = strat;
    s->calls[strat]++;
    decay_weights(s);

    size_t out_sz = do_one_mutate(s, buf, buf_size, add_buf, add_buf_size,
                                   buf_size, max_size, strat);

    if (out_sz < 8) {
        /* Strategy produced nothing useful — try random_byte as fallback */
        memcpy(s->scratch, buf, buf_size);
        out_sz = s_random_byte(s, buf, buf_size, buf_size);
    }

    *out_buf = s->scratch;
    return out_sz;
}

/* ── Credit strategy when AFL++ adds a new queue entry ──────────────────── */
uint8_t afl_custom_queue_new_entry(void *data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {
    (void)filename_new_queue; (void)filename_orig_queue;
    my_state_t *s = data;
    if (s && s->last_strategy >= 0)
        credit_strategy(s, s->last_strategy);
    return 0;
}

/* ── Human-readable mutator name for AFL++ status screen ─────────────────── */
const char *afl_custom_describe(void *data, size_t max_description_len) {
    (void)data; (void)max_description_len;
    return MUTATOR_VERSION " built:" MUTATOR_BUILD_DATE;
}
