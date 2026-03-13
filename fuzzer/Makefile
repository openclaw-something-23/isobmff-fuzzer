# ISOBMFF Fuzzer Makefile
# Targets: libfuzzer, afl, coverage, clean

ISOBMFF_DIR   := /opt/ISOBMFF
ISOBMFF_INC   := $(ISOBMFF_DIR)/ISOBMFF/include
ISOBMFF_SRC   := $(ISOBMFF_DIR)/ISOBMFF/source
ISOBMFF_LIB   := $(ISOBMFF_DIR)/Build/Products/libISOBMFF.a

CXX           := clang++
AFL_CXX       := afl-clang-fast++

CXXFLAGS_BASE := -std=c++17 -I$(ISOBMFF_INC)
SAN_FLAGS     := -fsanitize=address,undefined -fno-omit-frame-pointer
COV_FLAGS     := -fprofile-instr-generate -fcoverage-mapping
FUZZ_FLAGS    := -fsanitize=fuzzer

# ──────────────────────────────────────────────────────────────
# Build ISOBMFF library (instrumented for coverage + sanitizers)
# ──────────────────────────────────────────────────────────────
$(ISOBMFF_LIB):
	@echo "[*] Building ISOBMFF with sanitizers..."
	cd $(ISOBMFF_DIR) && \
	  CXX=$(CXX) \
	  CXXFLAGS="$(CXXFLAGS_BASE) $(SAN_FLAGS) $(COV_FLAGS)" \
	  make

# ──────────────────────────────────────────────────────────────
# libFuzzer target
# ──────────────────────────────────────────────────────────────
libfuzzer: harness.cpp $(ISOBMFF_LIB)
	@echo "[*] Building libFuzzer harness..."
	$(CXX) $(CXXFLAGS_BASE) $(SAN_FLAGS) $(COV_FLAGS) $(FUZZ_FLAGS) \
	  harness.cpp $(ISOBMFF_LIB) \
	  -lstdc++ -lm \
	  -o fuzz_isobmff
	@echo "[+] Built: ./fuzz_isobmff"

# ──────────────────────────────────────────────────────────────
# AFL++ target
# ──────────────────────────────────────────────────────────────
afl: harness.cpp $(ISOBMFF_LIB)
	@echo "[*] Building AFL++ harness..."
	AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
	$(AFL_CXX) $(CXXFLAGS_BASE) \
	  -D__AFL_FUZZ_TESTCASE_LEN \
	  harness.cpp $(ISOBMFF_LIB) \
	  -lstdc++ -lm \
	  -o fuzz_isobmff_afl
	@echo "[+] Built: ./fuzz_isobmff_afl"

# ──────────────────────────────────────────────────────────────
# Coverage report (run after fuzzing)
# ──────────────────────────────────────────────────────────────
coverage:
	@echo "[*] Merging coverage profiles..."
	llvm-profdata merge -sparse /tmp/fuzz_*.profraw -o /tmp/fuzz_merged.profdata
	llvm-cov report ./fuzz_isobmff \
	  -instr-profile=/tmp/fuzz_merged.profdata \
	  $(ISOBMFF_SRC)/*.cpp \
	  > /results/coverage/coverage_report.txt
	llvm-cov show ./fuzz_isobmff \
	  -instr-profile=/tmp/fuzz_merged.profdata \
	  -format=html \
	  $(ISOBMFF_SRC)/*.cpp \
	  > /results/coverage/coverage.html
	@echo "[+] Coverage report at /results/coverage/"

clean:
	rm -f fuzz_isobmff fuzz_isobmff_afl *.profraw *.profdata

.PHONY: libfuzzer afl coverage clean
