/*
 * ISOBMFF Fuzzing Harness — libFuzzer
 *
 * Key design:
 *   - Sanitizes ALL box size fields recursively before parsing (prevents trivial OOM)
 *   - The OOM vulnerability is documented as a separate finding
 *   - Exercises all box types and container hierarchies
 */

#include <ISOBMFF.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <unistd.h>
#include <sstream>

// ── Box size sanitizer ────────────────────────────────────────────────────────
// ISOBMFF doesn't validate size fields — a real OOM vulnerability (documented).
// We patch sizes so the fuzzer can explore code paths beyond the initial OOM.
static void patch_boxes(uint8_t* buf, size_t offset, size_t end, int depth = 0) {
    if (depth > 32) return;  // prevent stack overflow on deeply nested inputs

    while (offset + 8 <= end) {
        uint32_t sz = ((uint32_t)buf[offset]   << 24)
                    | ((uint32_t)buf[offset+1] << 16)
                    | ((uint32_t)buf[offset+2] <<  8)
                    |  (uint32_t)buf[offset+3];

        if (sz == 1) {
            // 64-bit extended size — skip safely
            if (offset + 16 > end) break;
            offset += 8;
            continue;
        }

        if (sz == 0) {
            // "Extends to EOF" — fix size to actual remaining bytes
            uint32_t remaining = (uint32_t)(end - offset);
            buf[offset]   = (remaining >> 24) & 0xFF;
            buf[offset+1] = (remaining >> 16) & 0xFF;
            buf[offset+2] = (remaining >>  8) & 0xFF;
            buf[offset+3] =  remaining        & 0xFF;
            sz = remaining;
            if (sz > 8)
                patch_boxes(buf, offset + 8, offset + sz, depth + 1);
            break;
        }

        if (sz < 8) {
            // Invalid tiny box — fix to minimum valid size
            buf[offset+3] = 8;
            sz = 8;
        }

        uint32_t avail = (uint32_t)(end - offset);
        if (sz > avail) {
            // Cap to available space
            sz = avail;
            buf[offset]   = (sz >> 24) & 0xFF;
            buf[offset+1] = (sz >> 16) & 0xFF;
            buf[offset+2] = (sz >>  8) & 0xFF;
            buf[offset+3] =  sz        & 0xFF;
        }

        // Recurse into box content
        if (sz > 8)
            patch_boxes(buf, offset + 8, offset + sz, depth + 1);

        offset += sz;
    }
}

// ── Main parse function ───────────────────────────────────────────────────────
static void parse_isobmff(const uint8_t* data, size_t size) {
    if (size < 8) return;  // too small to contain a valid box

    // Sanitize size fields (deep copy)
    std::vector<uint8_t> buf(data, data + size);
    patch_boxes(buf.data(), 0, buf.size());

    // Write to temp file (ISOBMFF::Parser reads from file path)
    char tmpname[] = "/tmp/fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd < 0) return;

    if (write(fd, buf.data(), buf.size()) != (ssize_t)buf.size()) {
        close(fd);
        unlink(tmpname);
        return;
    }
    close(fd);

    try {
        ISOBMFF::Parser parser;
        parser.Parse(tmpname);

        auto file = parser.GetFile();
        if (file) {
            for (const auto& box : file->GetBoxes()) {
                if (!box) continue;
                try { (void)box->GetName(); } catch (...) {}
                try {
                    auto* c = dynamic_cast<ISOBMFF::ContainerBox*>(box.get());
                    if (c) {
                        for (const auto& child : c->GetBoxes()) {
                            if (child) {
                                try { (void)child->GetName(); } catch (...) {}
                            }
                        }
                    }
                } catch (...) {}
            }
        }
    } catch (const std::exception&) {
        // Expected on malformed input
    } catch (...) {}

    unlink(tmpname);
}

// ── libFuzzer entry point ─────────────────────────────────────────────────────
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    parse_isobmff(data, size);
    return 0;
}

// ── Standalone mode ───────────────────────────────────────────────────────────
#if defined(STANDALONE_MODE)
int main(int argc, char* argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <file.mp4>\n", argv[0]); return 1; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 64 * 1024 * 1024) { fclose(f); return 1; }
    std::vector<uint8_t> buf(sz);
    fread(buf.data(), 1, sz, f);
    fclose(f);
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
    return 0;
}
#endif
