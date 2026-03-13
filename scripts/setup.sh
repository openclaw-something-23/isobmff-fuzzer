#!/usr/bin/env bash
# setup.sh — installs deps, clones & builds ISOBMFF, builds harness
set -euo pipefail

echo "[*] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq \
  clang llvm lld \
  afl++ \
  git make cmake \
  python3 python3-pip \
  curl xxd \
  libstdc++-dev

echo "[*] Cloning ISOBMFF..."
if [ ! -d /opt/ISOBMFF ]; then
    git clone --depth=1 https://github.com/DigiDNA/ISOBMFF.git /opt/ISOBMFF
fi

echo "[*] Building ISOBMFF with coverage + sanitizers..."
cd /opt/ISOBMFF

# Patch Makefile to use clang and add flags
export CXX=clang++
export CC=clang
export CXXFLAGS="-std=c++17 -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping -fno-omit-frame-pointer"

make -j$(nproc) 2>&1 | tail -5 || {
    echo "[!] ISOBMFF make failed, trying alternative build..."
    # Some versions need manual compilation
    mkdir -p Build/Products
    find ISOBMFF/source -name "*.cpp" | xargs \
      ${CXX} ${CXXFLAGS} -IISOBMFF/include -c 2>&1 | tail -10
    ar rcs Build/Products/libISOBMFF.a *.o 2>/dev/null || true
}

echo "[*] Building fuzzer harness..."
cd /fuzzer
make libfuzzer

echo "[*] Creating minimal MP4 corpus..."
mkdir -p /fuzzer/corpus

# Minimal valid ftyp box (MP4 file magic bytes)
python3 -c "
import struct
# ftyp box: size(4) + 'ftyp'(4) + 'mp41'(4) + version(4) + 'mp41'(4)
box = struct.pack('>I', 24) + b'ftyp' + b'mp41' + struct.pack('>I', 0) + b'mp41'
# mdat box: empty
box += struct.pack('>I', 8) + b'mdat'
open('/fuzzer/corpus/minimal.mp4', 'wb').write(box)
print('Created minimal.mp4')
"

# Minimal moov box
python3 -c "
import struct
def box(name, data=b''):
    return struct.pack('>I', 8 + len(data)) + name.encode() + data

mvhd_data = struct.pack('>IIIIIII', 0, 0, 0, 1000, 0, 0x00010000, 0x0100) + b'\x00' * 60
moov = box('mvhd', mvhd_data)
root = box('ftyp', b'isom\x00\x00\x00\x00isom') + box('moov', moov)
open('/fuzzer/corpus/minimal_moov.mp4', 'wb').write(root)
print('Created minimal_moov.mp4')
"

echo "[+] Setup complete. Run: /scripts/run_fuzzer.sh"
