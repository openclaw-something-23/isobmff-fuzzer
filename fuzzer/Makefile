# ISOBMFF Fuzzer Makefile — AFL++ (primary) + libFuzzer (compatibility)
# Default target: afl

ISOBMFF_DIR   := /opt/ISOBMFF
ISOBMFF_INC   := $(ISOBMFF_DIR)/ISOBMFF/include
ISOBMFF_SRC   := $(ISOBMFF_DIR)/ISOBMFF/source
ISOBMFF_LIB   := $(ISOBMFF_DIR)/Build/Products/libISOBMFF.a

# Compilers
CXX           := clang++
AFL_CXX       := afl-clang-fast++

# Common flags
CXXFLAGS_BASE := -std=c++17 -I$(ISOBMFF_INC)
SAN_FLAGS     := -fsanitize=address,undefined -fno-omit-frame-pointer

# libFuzzer-specific (LLVM coverage for profraw reports)
COV_FLAGS     := -fprofile-instr-generate -fcoverage-mapping
FUZZ_FLAGS    := -fsanitize=fuzzer

# ──────────────────────────────────────────────────────────────────────────────
# Default: AFL++
# ──────────────────────────────────────────────────────────────────────────────
.PHONY: all afl libfuzzer standalone coverage clean

all: afl mutator

# ──────────────────────────────────────────────────────────────────────────────
# AFL++ target (default)
# Builds ISOBMFF with afl-clang-fast++ instrumentation, then the harness.
# ASAN/UBSAN are enabled via AFL env vars (they add the right compiler flags).
# ──────────────────────────────────────────────────────────────────────────────
afl: harness.cpp
	@echo "[*] Building ISOBMFF with AFL++ instrumentation..."
	cd $(ISOBMFF_DIR) && \
	  CXX=$(AFL_CXX) \
	  CXXFLAGS="$(CXXFLAGS_BASE) $(SAN_FLAGS)" \
	  AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
	  make -j$(shell nproc) 2>&1 | tail -10
	@echo "[*] Building AFL++ harness..."
	AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
	$(AFL_CXX) $(CXXFLAGS_BASE) $(SAN_FLAGS) \
	  harness.cpp $(ISOBMFF_LIB) \
	  -lstdc++ -lm \
	  -o fuzz_isobmff_afl
	@echo "[+] Built: ./fuzz_isobmff_afl"
	@echo "[+] Run:   afl-fuzz -i corpus -o /results/afl_out/main -V 300 -- ./fuzz_isobmff_afl"

# ──────────────────────────────────────────────────────────────────────────────
# libFuzzer target (kept for compatibility / comparison)
# ──────────────────────────────────────────────────────────────────────────────
libfuzzer: harness.cpp $(ISOBMFF_LIB)
	@echo "[*] Building ISOBMFF with clang instrumentation..."
	cd $(ISOBMFF_DIR) && \
	  CXX=$(CXX) \
	  CXXFLAGS="$(CXXFLAGS_BASE) $(SAN_FLAGS) $(COV_FLAGS)" \
	  make -j$(shell nproc) 2>&1 | tail -10
	@echo "[*] Building libFuzzer harness..."
	$(CXX) $(CXXFLAGS_BASE) $(SAN_FLAGS) $(COV_FLAGS) $(FUZZ_FLAGS) \
	  harness.cpp $(ISOBMFF_LIB) \
	  -lstdc++ -lm \
	  -o fuzz_isobmff
	@echo "[+] Built: ./fuzz_isobmff"

# ──────────────────────────────────────────────────────────────────────────────
# Standalone crash-replay binary (no fuzzer instrumentation)
# Used by analyze_crashes.sh to get ASAN stack traces on AFL++ crash inputs.
# ──────────────────────────────────────────────────────────────────────────────
standalone: harness.cpp $(ISOBMFF_LIB)
	@echo "[*] Building standalone replay binary..."
	AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
	$(AFL_CXX) $(CXXFLAGS_BASE) $(SAN_FLAGS) \
	  -DSTANDALONE_MODE \
	  harness.cpp $(ISOBMFF_LIB) \
	  -lstdc++ -lm \
	  -o fuzz_isobmff_replay
	@echo "[+] Built: ./fuzz_isobmff_replay"

# ──────────────────────────────────────────────────────────────────────────────
# Coverage report (post-run, using saved AFL++ corpus via libFuzzer build)
# ──────────────────────────────────────────────────────────────────────────────
coverage: libfuzzer
	@echo "[*] Running corpus through libFuzzer build for LLVM coverage..."
	LLVM_PROFILE_FILE="/tmp/fuzz_cov_%p.profraw" \
	./fuzz_isobmff corpus/ -runs=0 2>/dev/null || true
	llvm-profdata merge -sparse /tmp/fuzz_cov_*.profraw -o /tmp/fuzz_cov.profdata
	llvm-cov report ./fuzz_isobmff \
	  -instr-profile=/tmp/fuzz_cov.profdata \
	  $(ISOBMFF_SRC)/*.cpp \
	  > /results/coverage/coverage_report.txt
	llvm-cov show ./fuzz_isobmff \
	  -instr-profile=/tmp/fuzz_cov.profdata \
	  -format=html \
	  $(ISOBMFF_SRC)/*.cpp \
	  > /results/coverage/coverage.html
	@echo "[+] Coverage report at /results/coverage/"

# ──────────────────────────────────────────────────────────────────────────────
# Custom mutator (shared library)
# ──────────────────────────────────────────────────────────────────────────────
mutator: isobmff_mutator.c
	@echo "[*] Building custom ISOBMFF mutator..."
	afl-clang-fast -shared -fPIC -O2 \
	  isobmff_mutator.c \
	  -o isobmff_mutator.so
	@echo "[+] Built: ./isobmff_mutator.so"
	@echo "[+] Use: AFL_CUSTOM_MUTATOR_LIBRARY=$$PWD/isobmff_mutator.so afl-fuzz ..."

# ──────────────────────────────────────────────────────────────────────────────
# CMPLOG build — instruments comparison functions for better coverage
# Use with: afl-fuzz -c ./fuzz_isobmff_cmplog ...
# ──────────────────────────────────────────────────────────────────────────────
cmplog: harness.cpp
	@echo "[*] Building CMPLOG harness..."
	AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
	afl-clang-fast++ \
	  -std=c++17 \
	  -fno-omit-frame-pointer \
	  -g -O1 \
	  -I$(ISOBMFF_INC) \
	  harness.cpp $(ISOBMFF_LIB) \
	  -lstdc++ -lm \
	  -o fuzz_isobmff_cmplog
	AFL_USE_ASAN=1 afl-clang-fast++ -fsanitize=address,undefined \
	  -fno-omit-frame-pointer -g -O1 \
	  -I$(ISOBMFF_INC) harness.cpp $(ISOBMFF_LIB) -lstdc++ -lm \
	  -o fuzz_isobmff_cmplog
	@echo "[+] Built: ./fuzz_isobmff_cmplog"
	@echo "[+] Use: afl-fuzz -c ./fuzz_isobmff_cmplog ..."

clean:
	rm -f fuzz_isobmff fuzz_isobmff_afl fuzz_isobmff_replay fuzz_isobmff_cmplog \
	      isobmff_mutator.so *.profraw *.profdata
