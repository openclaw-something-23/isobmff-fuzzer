/*
 * ISOBMFF Fuzzing Harness — AFL++ (primary) + libFuzzer (compatibility)
 *
 * Build modes:
 *   AFL++:      afl-clang-fast++ -D__AFL_COMPILER ... (defines __AFL_COMPILER)
 *   libFuzzer:  clang++ -fsanitize=fuzzer ...
 *   Standalone: clang++ -DSTANDALONE_MODE ...
 *
 * Key design:
 *   - AFL++ persistent mode: __AFL_FUZZ_INIT + __AFL_LOOP (10 000 iters/fork)
 *   - /dev/shm temp files: in-memory I/O — no disk overhead in tight fuzz loop
 *   - OOM guard: operator new/new[] cap at 8 MB; prevents process kill from
 *     ISOBMFF's unchecked size fields (documented OOM vulnerability)
 *   - Sanitizes ALL box size fields recursively before parsing
 */

#include <ISOBMFF.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <stdexcept>
#include <new>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sstream>

// ── Allocation guard ──────────────────────────────────────────────────────────
// ISOBMFF trusts user-controlled size fields and can call malloc(4GB+).
// Cap allocations before they OOM-kill the process (libFuzzer) or the
// AFL++ instance. The C++ exception propagates up and is caught cleanly.
static constexpr size_t kMaxAlloc = 8 * 1024 * 1024;  // 8 MB cap

void* operator new(std::size_t sz) {
    if (sz > kMaxAlloc) throw std::bad_alloc();
    void* p = std::malloc(sz);
    if (!p) throw std::bad_alloc();
    return p;
}
void* operator new[](std::size_t sz) {
    if (sz > kMaxAlloc) throw std::bad_alloc();
    void* p = std::malloc(sz);
    if (!p) throw std::bad_alloc();
    return p;
}
void operator delete(void* p)   noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }

// ── Box size sanitizer ────────────────────────────────────────────────────────
static void patch_boxes(uint8_t* buf, size_t offset, size_t end, int depth = 0) {
    if (depth > 32) return;

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
            // "Extends to EOF" — fix to actual remaining bytes
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
            buf[offset+3] = 8;
            sz = 8;
        }

        uint32_t avail = (uint32_t)(end - offset);
        if (sz > avail) {
            sz = avail;
            buf[offset]   = (sz >> 24) & 0xFF;
            buf[offset+1] = (sz >> 16) & 0xFF;
            buf[offset+2] = (sz >>  8) & 0xFF;
            buf[offset+3] =  sz        & 0xFF;
        }

        if (sz > 8)
            patch_boxes(buf, offset + 8, offset + sz, depth + 1);

        offset += sz;
    }
}

// ── Temp-file path (per-process, in-memory on /dev/shm) ──────────────────────
// Using a fixed name per-PID avoids mkstemp() overhead in the tight fuzz loop.
static const char* get_tmpfile() {
    static char path[64] = {0};
    if (!path[0]) {
        // Prefer /dev/shm (RAM) for speed; fall back to /tmp
        struct stat st;
        if (stat("/dev/shm", &st) == 0 && S_ISDIR(st.st_mode))
            snprintf(path, sizeof(path), "/dev/shm/fuzz_isobmff_%d.mp4", (int)getpid());
        else
            snprintf(path, sizeof(path), "/tmp/fuzz_isobmff_%d.mp4", (int)getpid());
    }
    return path;
}

// ── Main parse function ───────────────────────────────────────────────────────
static void parse_isobmff(const uint8_t* data, size_t size) {
    if (size < 8) return;

    // Deep-copy and sanitize size fields
    std::vector<uint8_t> buf(data, data + size);
    patch_boxes(buf.data(), 0, buf.size());

    // Write to temp file (ISOBMFF::Parser takes a file path, not a buffer)
    const char* tmpname = get_tmpfile();
    int fd = open(tmpname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;

    ssize_t written = write(fd, buf.data(), buf.size());
    close(fd);
    if (written != (ssize_t)buf.size()) {
        unlink(tmpname);
        return;
    }

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

// ── libFuzzer entry point (always compiled; called by libFuzzer or AFL++ shim) ─
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    parse_isobmff(data, size);
    return 0;
}

// ── AFL++ persistent mode ─────────────────────────────────────────────────────
// __AFL_COMPILER is set by afl-clang-fast++ / afl-clang-lto++.
// __AFL_FUZZ_INIT() must appear at file scope, before main().
// AFL++ injects shared-memory testcase delivery via __AFL_FUZZ_TESTCASE_BUF /
// __AFL_FUZZ_TESTCASE_LEN; __AFL_LOOP controls the restart cadence.
#ifdef __AFL_COMPILER

__AFL_FUZZ_INIT();

int main(void) {
    // Ensure /dev/shm path is initialized before the fuzz loop
    (void)get_tmpfile();

    unsigned char* buf = __AFL_FUZZ_TESTCASE_BUF;  // shared-memory pointer

    while (__AFL_LOOP(10000)) {
        size_t len = (size_t)__AFL_FUZZ_TESTCASE_LEN;
        parse_isobmff(buf, len);
    }
    return 0;
}

#elif defined(STANDALONE_MODE)
// ── Standalone / crash-replay mode ───────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.mp4> [file2.mp4 ...]\n", argv[0]);
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        FILE* f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); continue; }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        rewind(f);
        if (sz <= 0 || sz > 64 * 1024 * 1024) { fclose(f); continue; }
        std::vector<uint8_t> data(sz);
        fread(data.data(), 1, sz, f);
        fclose(f);
        fprintf(stderr, "[*] Replaying %s (%ld bytes)\n", argv[i], sz);
        parse_isobmff(data.data(), (size_t)sz);
        fprintf(stderr, "[+] Done: %s\n", argv[i]);
    }
    return 0;
}
#endif
