/*
 * isobmff_mutator.c — AFL++ custom mutator for ISOBMFF / MP4 / HEIF
 *
 * Structure-aware mutations that understand the box-container hierarchy:
 *   1. box_type_swap    — replace box FourCC with a random known-valid type
 *   2. size_edge        — set box size to 0, 1, 8, max32, or random small value
 *   3. box_duplicate    — copy a random top-level box and append it
 *   4. box_insert       — insert a synthetic minimal box between existing boxes
 *   5. box_delete       — remove a random top-level box
 *   6. field_overflow   — in version/flags fields, write 0xFF bytes
 *   7. splice_boxes     — take boxes from crossover input and append
 *   8. random byte      — flip a random byte (fallback)
 *   ── NEW ────────────────────────────────────────────────────────────────
 *   9. box_truncate     — shrink a random box to test partial-parse paths
 *  10. box_reorder      — swap two adjacent boxes
 *  11. version_flags    — inject known-bad version/flags combos into FullBoxes
 *  12. nested_inject    — inject a child box inside a container box
 *  13. size_overflow    — write size > remaining to trigger bounds checks
 *
 * Build: afl-clang-fast -shared -fPIC -O2 isobmff_mutator.c -o isobmff_mutator.so
 * Use:   AFL_CUSTOM_MUTATOR_LIBRARY=/fuzzer/isobmff_mutator.so afl-fuzz ...
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* AFL++ custom mutator API */
typedef struct {
    uint32_t seed;
    uint8_t *scratch;
    size_t   scratch_size;
} my_state_t;

/* Known-valid ISOBMFF FourCCs */
static const char *KNOWN_BOXES[] = {
    "ftyp","moov","mdat","free","skip","wide",
    "mvhd","udta","meta","ilst","mean","name","data",
    "trak","tkhd","edts","elst","tref","load",
    "mdia","mdhd","hdlr","minf","vmhd","smhd","hmhd","nmhd",
    "dinf","dref","url ","urn ",
    "stbl","stsd","stts","ctts","stsc","stsz","stz2","stco","co64",
    "stss","stsh","sdtp","sbgp","sgpd","subs",
    "avc1","avc2","hvc1","hev1","vp09","av01","mp4a","mp4v",
    "avcC","hvcC","vpcC","av1C","esds","btrt","colr","pasp","clap",
    "mvex","mehd","trex","moof","mfhd","traf","tfhd","tfdt","trun",
    "pssh","sinf","frma","schm","schi","tenc","senc",
    "pict","idat","iref","iprp","ipco","ipma","iinf","infe",
    "iloc","ispe","pixi","irot","imir",
};
#define N_BOXES (sizeof(KNOWN_BOXES)/sizeof(KNOWN_BOXES[0]))

/* Fast LCG RNG (seeded per-instance) */
static uint32_t lcg(my_state_t *s) {
    s->seed = s->seed * 1664525u + 1013904223u;
    return s->seed;
}
static uint32_t rng_range(my_state_t *s, uint32_t n) {
    return n ? lcg(s) % n : 0;
}

/* Read big-endian uint32 */
static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void write_u32(uint8_t *p, uint32_t v) {
    p[0]=v>>24; p[1]=(v>>16)&0xFF; p[2]=(v>>8)&0xFF; p[3]=v&0xFF;
}

/* Count top-level boxes; fill offsets[] (up to max entries) */
static int count_boxes(const uint8_t *buf, size_t len,
                       uint32_t *offsets, int max) {
    int n = 0;
    size_t off = 0;
    while (off + 8 <= len && n < max) {
        uint32_t sz = read_u32(buf + off);
        if (sz == 0) sz = (uint32_t)(len - off); /* extends to EOF */
        if (sz < 8 || off + sz > len) break;
        offsets[n++] = (uint32_t)off;
        off += sz;
    }
    return n;
}

/* ── AFL++ API ──────────────────────────────────────────────────────────── */

void *afl_custom_init(void *afl, unsigned int seed) {
    my_state_t *s = calloc(1, sizeof(my_state_t));
    if (!s) return NULL;
    s->seed = seed ^ (uint32_t)(uintptr_t)afl ^ (uint32_t)time(NULL);
    s->scratch_size = 1 << 20; /* 1MB scratch */
    s->scratch = malloc(s->scratch_size);
    return s;
}

void afl_custom_deinit(void *data) {
    my_state_t *s = data;
    if (s) { free(s->scratch); free(s); }
}

/*
 * afl_custom_fuzz — called by AFL++ for every mutation.
 * buf      = current input
 * buf_size = its size
 * out_buf  = pointer we set to our output buffer
 * add_buf  = crossover input (may be NULL)
 * max_size = maximum allowed output size
 * Returns: size of mutated output (0 = failed, AFL++ will use built-in)
 */
size_t afl_custom_fuzz(void *data,
                       uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

    my_state_t *s = data;
    if (!s || !buf || buf_size < 8) return 0;

    /* Copy input to scratch */
    if (buf_size > s->scratch_size - 512) return 0;
    memcpy(s->scratch, buf, buf_size);
    size_t out_size = buf_size;

    /* Find top-level box offsets */
    uint32_t box_offs[256];
    int n = count_boxes(buf, buf_size, box_offs, 256);
    if (n == 0) return 0;

    /* Pick a mutation strategy (weighted) */
    uint32_t strategy = rng_range(s, 100);

    if (strategy < 20 && n > 0) {
        /* ── Strategy 1: box_type_swap ──────────────────────────────── */
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        const char *new_type = KNOWN_BOXES[rng_range(s, N_BOXES)];
        memcpy(s->scratch + off + 4, new_type, 4);

    } else if (strategy < 35 && n > 0) {
        /* ── Strategy 2: size_edge ──────────────────────────────────── */
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t cur_sz = read_u32(buf + off);
        static const uint32_t EDGE_SIZES[] = {0,1,8,0xFFFFFFFF,0x100,0x1000};
        uint32_t new_sz = EDGE_SIZES[rng_range(s, 6)];
        write_u32(s->scratch + off, new_sz);

    } else if (strategy < 50 && n > 0 && out_size + 512 < max_size) {
        /* ── Strategy 3: box_duplicate ──────────────────────────────── */
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t box_sz = read_u32(buf + off);
        if (box_sz == 0) box_sz = (uint32_t)(buf_size - off);
        if (box_sz < 8 || box_sz > 4096) goto done; /* skip huge boxes */
        if (out_size + box_sz > s->scratch_size || out_size + box_sz > max_size) goto done;
        memcpy(s->scratch + out_size, buf + off, box_sz);
        out_size += box_sz;

    } else if (strategy < 65 && out_size + 16 < max_size) {
        /* ── Strategy 4: box_insert ─────────────────────────────────── */
        /* Insert minimal 8-byte box of a random type before a random box */
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        const char *btype = KNOWN_BOXES[rng_range(s, N_BOXES)];
        uint8_t newbox[8];
        write_u32(newbox, 8);
        memcpy(newbox + 4, btype, 4);
        /* shift tail right */
        if (out_size + 8 > s->scratch_size || out_size + 8 > max_size) goto done;
        memmove(s->scratch + off + 8, s->scratch + off, out_size - off);
        memcpy(s->scratch + off, newbox, 8);
        out_size += 8;

    } else if (strategy < 75 && n > 1) {
        /* ── Strategy 5: box_delete ─────────────────────────────────── */
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t box_sz = read_u32(buf + off);
        if (box_sz == 0) box_sz = (uint32_t)(buf_size - off);
        if (box_sz < 8 || off + box_sz > buf_size) goto done;
        memmove(s->scratch + off, s->scratch + off + box_sz,
                out_size - off - box_sz);
        out_size -= box_sz;

    } else if (strategy < 85 && n > 0) {
        /* ── Strategy 6: field_overflow ─────────────────────────────── */
        /* Smash version/flags/reserved fields (bytes 8-11 of a fullbox) */
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t box_sz = read_u32(buf + off);
        if (box_sz >= 12) {
            static const uint8_t FILL[] = {0xFF,0x00,0x80,0x7F,0x01};
            uint8_t fill = FILL[rng_range(s, 5)];
            memset(s->scratch + off + 8, fill, 4);
        }

    } else if (strategy < 95 && add_buf && add_buf_size >= 8) {
        /* ── Strategy 7: splice_boxes ───────────────────────────────── */
        uint32_t add_offs[64];
        int add_n = count_boxes(add_buf, add_buf_size, add_offs, 64);
        if (add_n == 0) goto done;
        int idx = rng_range(s, add_n);
        uint32_t src_off = add_offs[idx];
        uint32_t src_sz  = read_u32(add_buf + src_off);
        if (src_sz == 0) src_sz = (uint32_t)(add_buf_size - src_off);
        if (src_sz < 8 || src_sz > 4096) goto done;
        if (out_size + src_sz > s->scratch_size || out_size + src_sz > max_size) goto done;
        memcpy(s->scratch + out_size, add_buf + src_off, src_sz);
        out_size += src_sz;

    } else if (strategy < 97 && n > 0) {
        /* ── Strategy 9: box_truncate ───────────────────────────────── */
        /* Shrink a random box by reducing its declared size — forces       */
        /* the parser to handle partial/truncated box content.              */
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t box_sz = read_u32(buf + off);
        if (box_sz == 0) box_sz = (uint32_t)(buf_size - off);
        if (box_sz < 16) goto done;
        /* New size: between 8 and box_sz-1 */
        uint32_t new_sz = 8 + rng_range(s, box_sz - 8);
        write_u32(s->scratch + off, new_sz);
        /* Truncate out_size to end of new box if it was the last one */
        if (off + box_sz == out_size) out_size = off + new_sz;

    } else if (strategy < 98 && n >= 2) {
        /* ── Strategy 10: box_reorder ──────────────────────────────── */
        /* Swap two adjacent top-level boxes — tests assumption that     */
        /* parsers don't depend on box ordering (some do, e.g. ftyp).   */
        int idx = rng_range(s, n - 1);
        uint32_t off_a = box_offs[idx];
        uint32_t off_b = box_offs[idx + 1];
        uint32_t sz_a = read_u32(buf + off_a);
        uint32_t sz_b = read_u32(buf + off_b);
        if (sz_a == 0 || sz_b == 0) goto done;
        if (sz_a < 8 || sz_b < 8) goto done;
        if (off_a + sz_a + sz_b > out_size) goto done;
        if (sz_a + sz_b > 65536) goto done; /* safety limit */
        uint8_t *tmp = malloc(sz_a);
        if (!tmp) goto done;
        memcpy(tmp, s->scratch + off_a, sz_a);
        memmove(s->scratch + off_a, s->scratch + off_b, sz_b);
        memcpy(s->scratch + off_a + sz_b, tmp, sz_a);
        free(tmp);

    } else if (strategy < 99 && n > 0) {
        /* ── Strategy 11: version_flags injection ───────────────────── */
        /* Inject known-interesting version+flags combos into FullBoxes. */
        /* FullBoxes have: [size 4B][type 4B][version 1B][flags 3B]...  */
        static const uint8_t VF[][4] = {
            {0x00,0x00,0x00,0x00}, /* v0, flags=0 */
            {0x01,0x00,0x00,0x00}, /* v1, flags=0 (64-bit timestamps) */
            {0x02,0x00,0x00,0x00}, /* v2, invalid for most */
            {0xFF,0xFF,0xFF,0xFF}, /* all-ones */
            {0x00,0x00,0x00,0x01}, /* v0, flag=track_enabled */
            {0x00,0x00,0x00,0x03}, /* v0, track_enabled+track_in_movie */
            {0x00,0x00,0x00,0x0f}, /* all 4 track flags */
            {0x01,0x00,0x00,0x01}, /* v1+flag */
            {0x00,0x80,0x00,0x00}, /* unknown high flag bit */
            {0x00,0x00,0x01,0x00}, /* flag bit 8 */
        };
        int idx = rng_range(s, n);
        uint32_t off = box_offs[idx];
        uint32_t box_sz = read_u32(buf + off);
        if (box_sz >= 12) {
            int vfi = rng_range(s, 10);
            memcpy(s->scratch + off + 8, VF[vfi], 4);
        }

    } else if (strategy < 100 && n > 0 && out_size + 24 < max_size) {
        /* ── Strategy 12: nested_inject ────────────────────────────── */
        /* Inject a minimal child box inside the payload of a container  */
        /* box. Target boxes that expect children: moov/trak/mdia/etc.  */
        static const char *CONTAINER_TYPES[]={"moov","trak","mdia","minf","dinf","stbl",
                                               "udta","ilst","moof","traf","mvex"};
        /* Find a container box */
        int found=-1;
        for(int i=0;i<n;i++){
            uint32_t off=box_offs[i];
            const uint8_t *t=buf+off+4;
            for(int j=0;j<11;j++){
                if(memcmp(t,CONTAINER_TYPES[j],4)==0){found=i;break;}
            }
            if(found>=0) break;
        }
        if(found<0) found=rng_range(s,n); /* fallback: any box */
        uint32_t off=box_offs[found];
        uint32_t box_sz=read_u32(buf+off);
        if(box_sz==0) box_sz=(uint32_t)(buf_size-off);
        if(box_sz<16) goto done;
        /* Insert 8-byte child at end of box payload */
        uint32_t insert_at=off+box_sz;
        if(insert_at>out_size) goto done;
        if(out_size+8>s->scratch_size||out_size+8>max_size) goto done;
        const char *child_type=KNOWN_BOXES[rng_range(s,N_BOXES)];
        uint8_t child[8]; write_u32(child,8); memcpy(child+4,child_type,4);
        memmove(s->scratch+insert_at+8,s->scratch+insert_at,out_size-insert_at);
        memcpy(s->scratch+insert_at,child,8);
        out_size+=8;
        /* Fix parent box size */
        write_u32(s->scratch+off,box_sz+8);

    } else {
        /* ── Strategy 13: size_overflow ────────────────────────────── */
        /* Write a box size larger than remaining data — tests bounds.   */
        if (n > 0) {
            int idx = rng_range(s, n);
            uint32_t off = box_offs[idx];
            uint32_t rem = (uint32_t)(out_size - off);
            /* Write size = rem+delta (beyond buffer) */
            uint32_t delta = 8 + rng_range(s, 1024);
            write_u32(s->scratch + off, rem + delta);
        } else if (out_size > 0) {
            /* Fallback: random byte flip */
            uint32_t byte_idx = rng_range(s, (uint32_t)out_size);
            s->scratch[byte_idx] ^= (uint8_t)(lcg(s) & 0xFF);
        }
    }

done:
    if (out_size < 8) return 0;
    *out_buf = s->scratch;
    return out_size;
}

/* Optional: called before AFL++ trims — return 1 to let AFL++ handle it */
uint8_t afl_custom_queue_new_entry(void *data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {
    return 0; /* 0 = don't call our custom trim, let AFL++ do it */
}
