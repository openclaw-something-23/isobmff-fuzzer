#!/usr/bin/env bash
# setup.sh — installs deps, clones & builds ISOBMFF with AFL++, builds harness
set -euo pipefail

echo "[*] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq \
  afl++ \
  clang llvm lld \
  git make cmake \
  python3 python3-pip \
  curl xxd \
  libstdc++-dev

# Verify AFL++ installation
if ! command -v afl-fuzz &>/dev/null; then
    echo "[!] afl-fuzz not found after install. Trying from source..."
    git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus.git /opt/AFLplusplus
    cd /opt/AFLplusplus && make -j$(nproc) && make install
fi

echo "[*] AFL++ version: $(afl-fuzz --version 2>&1 | head -1)"

# ── Clone ISOBMFF ──────────────────────────────────────────────────────────────
echo "[*] Cloning ISOBMFF..."
if [ ! -d /opt/ISOBMFF ]; then
    git clone --depth=1 https://github.com/DigiDNA/ISOBMFF.git /opt/ISOBMFF
fi

# ── Build ISOBMFF with AFL++ instrumentation + ASAN/UBSAN ─────────────────────
echo "[*] Building ISOBMFF with AFL++ instrumentation (ASAN + UBSAN)..."
cd /opt/ISOBMFF

export CXX=afl-clang-fast++
export CC=afl-clang-fast
export CXXFLAGS="-std=c++17 -fsanitize=address,undefined -fno-omit-frame-pointer"
export AFL_USE_ASAN=1
export AFL_USE_UBSAN=1

make -j$(nproc) 2>&1 | tail -10 || {
    echo "[!] ISOBMFF make failed, trying manual compilation..."
    mkdir -p Build/Products
    find ISOBMFF/source -name "*.cpp" | while read -r src; do
        obj=$(basename "${src%.cpp}.o")
        ${CXX} ${CXXFLAGS} -IISOBMFF/include -c "$src" -o "/tmp/${obj}" 2>&1 | tail -3 || true
    done
    ar rcs Build/Products/libISOBMFF.a /tmp/*.o 2>/dev/null || true
    echo "[~] Manual build done"
}

# ── Build fuzzer harness ───────────────────────────────────────────────────────
echo "[*] Building AFL++ fuzzer harness..."
cd /fuzzer
make afl

echo "[*] Building standalone crash-replay binary..."
make standalone

# ── Create seed corpus ─────────────────────────────────────────────────────────
echo "[*] Creating seed corpus..."
mkdir -p /fuzzer/corpus
python3 /scripts/make_corpus.py

# ── AFL++ system config (best-effort, may fail in Docker) ─────────────────────
echo "[*] Configuring system for AFL++..."
echo core > /proc/sys/kernel/core_pattern 2>/dev/null \
    && echo "[+] core_pattern set" \
    || echo "[~] Could not set core_pattern (normal in some containers)"

# Disable ASLR for better coverage stability
echo 0 > /proc/sys/kernel/randomize_va_space 2>/dev/null \
    && echo "[+] ASLR disabled" \
    || echo "[~] Could not disable ASLR (normal in some containers)"

echo "[+] Setup complete."
echo "[+] Run fuzzer: /scripts/run_fuzzer.sh"
echo "[+] Or directly: afl-fuzz -i /fuzzer/corpus -o /results/afl_out/test -V 300 -- /fuzzer/fuzz_isobmff_afl"
