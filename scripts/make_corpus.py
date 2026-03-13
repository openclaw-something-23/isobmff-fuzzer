#!/usr/bin/env python3
"""Generate minimal MP4 seed corpus for fuzzing."""
import struct, os

CORPUS = "/fuzzer/corpus"
os.makedirs(CORPUS, exist_ok=True)

def box(name, data=b""):
    return struct.pack(">I", 8 + len(data)) + name.encode() + data

# 1. Minimal valid ftyp + mdat
b = box("ftyp", b"mp41\x00\x00\x00\x00mp41") + box("mdat")
open(f"{CORPUS}/minimal.mp4", "wb").write(b)

# 2. ftyp + moov with mvhd
mvhd = struct.pack(">IIIIIII", 0, 0, 0, 1000, 0, 0x00010000, 0x0100) + b"\x00" * 60
moov = box("mvhd", mvhd)
b2 = box("ftyp", b"isom\x00\x00\x00\x00isom") + box("moov", moov)
open(f"{CORPUS}/minimal_moov.mp4", "wb").write(b2)

# 3. Truncated (only magic bytes)
open(f"{CORPUS}/truncated.mp4", "wb").write(b"ftyp")

# 4. Wrong size field
b3 = struct.pack(">I", 999) + b"ftyp" + b"mp41\x00\x00\x00\x00mp41"
open(f"{CORPUS}/bad_size.mp4", "wb").write(b3)

# 5. All zeros
open(f"{CORPUS}/zeros.mp4", "wb").write(b"\x00" * 64)

# 6. Random-ish data with valid header
import os as _os
hdr = box("ftyp", b"mp41\x00\x00\x00\x00mp41")
open(f"{CORPUS}/fuzz_seed.mp4", "wb").write(hdr + _os.urandom(128))

# 7. Very large size field (potential integer overflow)
b4 = struct.pack(">I", 0xFFFFFFFF) + b"ftyp" + b"mp41\x00\x00\x00\x00"
open(f"{CORPUS}/large_size.mp4", "wb").write(b4)

print(f"[+] Created {len(os.listdir(CORPUS))} seed files in {CORPUS}")
