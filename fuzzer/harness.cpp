/*
 * ISOBMFF Fuzzing Harness
 * libFuzzer + AFL++ compatible
 *
 * Supports:
 *   - libFuzzer: clang++ -fsanitize=fuzzer,address,undefined
 *   - AFL++:     AFL_USE_ASAN=1 afl-clang-fast++
 */

#include <ISOBMFF.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

// Suppress all output from the library
class NullStream : public std::streambuf {
protected:
    int overflow(int c) override { return c; }
};

static void parse_isobmff(const uint8_t* data, size_t size) {
    // Write fuzz data to a temp file (ISOBMFF reads from file path/stream)
    char tmpname[] = "/tmp/fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd < 0) return;

    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpname);
        return;
    }
    close(fd);

    try {
        ISOBMFF::Parser parser;

        // Parse options - try different verbosity levels
        if (size > 0 && data[0] % 3 == 0) {
            parser.SetPreferredStringType(ISOBMFF::StringType::Pascal);
        }

        // Open and parse the file
        parser.Parse(tmpname);

        auto file = parser.GetFile();
        if (file) {
            // Walk all boxes to trigger deeper parsing
            for (const auto& box : file->GetBoxes()) {
                if (!box) continue;

                // Trigger display string generation (common crash surface)
                try {
                    (void)box->GetName();
                } catch (...) {}

                // Try to get children if it's a container
                try {
                    auto* container = dynamic_cast<ISOBMFF::ContainerBox*>(box.get());
                    if (container) {
                        for (const auto& child : container->GetBoxes()) {
                            if (child) {
                                try { (void)child->GetName(); } catch (...) {}
                            }
                        }
                    }
                } catch (...) {}
            }
        }
    } catch (const std::exception&) {
        // Expected — library may throw on malformed input
    } catch (...) {
        // Catch all to prevent libFuzzer from seeing non-crash exceptions
    }

    unlink(tmpname);
}

// libFuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Redirect stderr/stdout to suppress library noise
    NullStream null;
    std::streambuf* old_cerr = std::cerr.rdbuf(&null);
    std::streambuf* old_cout = std::cout.rdbuf(&null);

    parse_isobmff(data, size);

    std::cerr.rdbuf(old_cerr);
    std::cout.rdbuf(old_cout);

    return 0;
}

// AFL++ / standalone mode
#ifndef __AFL_FUZZ_TESTCASE_LEN
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.mp4>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    if (sz <= 0 || sz > 64 * 1024 * 1024) {
        fclose(f);
        return 1;
    }

    std::vector<uint8_t> buf(sz);
    fread(buf.data(), 1, sz, f);
    fclose(f);

    LLVMFuzzerTestOneInput(buf.data(), buf.size());
    return 0;
}
#endif
