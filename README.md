# 🐛 ISOBMFF Fuzzer

Continuous fuzzing infrastructure for [DigiDNA/ISOBMFF](https://github.com/DigiDNA/ISOBMFF) with real-time dashboard.  
**Engine: AFL++ (primary)** — persistent mode, ASAN/UBSAN, edge coverage tracking.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│ Docker Compose                                           │
│                                                          │
│  ┌─────────────────┐     ┌──────────────────────────┐   │
│  │  fuzzer service │────▶│  dashboard :56789        │   │
│  │                 │     │                          │   │
│  │  AFL++          │     │  FastAPI + SQLite        │   │
│  │  persistent     │     │  Coverage timeline       │   │
│  │  ASAN/UBSAN     │     │  Crash dedup             │   │
│  │  edge coverage  │     │  Leaderboard/Scoring     │   │
│  └─────────────────┘     └──────────────────────────┘   │
│          │                          │                    │
│          └──────────────────────────┘                    │
│                  /results volume                         │
└──────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USER/isobmff-fuzzer
cd isobmff-fuzzer

# Start everything
docker-compose up --build

# Dashboard
open http://localhost:56789

# Scale fuzzing (4 parallel AFL++ instances)
docker-compose up --build --scale fuzzer=4

# Custom fuzz time (seconds per run)
FUZZ_TIME=600 docker-compose up
```

## AFL++ Harness Design

The harness (`fuzzer/harness.cpp`) uses **AFL++ persistent mode**:

```
__AFL_FUZZ_INIT();          // shared-memory testcase delivery
while (__AFL_LOOP(10000)) { // 10 000 iterations before fork restart
    parse_isobmff(buf, len);
}
```

Key features:
- **`/dev/shm` temp files** — ISOBMFF requires a file path; we use RAM-backed
  `/dev/shm` to avoid disk I/O in the tight fuzz loop
- **OOM guard** — `operator new` capped at 8 MB; prevents ISOBMFF's unchecked
  size fields from OOM-killing the AFL++ instance
- **Box size sanitizer** — recursive patch of all ISOBMFF box size fields so
  the fuzzer explores parsing logic, not just OOM paths
- **libFuzzer compatibility** — `LLVMFuzzerTestOneInput` always compiled; build
  with `-fsanitize=fuzzer` for libFuzzer mode (see `make libfuzzer`)

## Build Targets

```bash
cd fuzzer

make afl          # AFL++ binary (default): fuzz_isobmff_afl
make libfuzzer    # libFuzzer binary:       fuzz_isobmff
make standalone   # Crash replay binary:    fuzz_isobmff_replay
make coverage     # Run corpus → LLVM HTML coverage report
make clean
```

## Running AFL++ Directly

```bash
# Single instance
afl-fuzz -i fuzzer/corpus -o /tmp/afl_out -V 300 -- fuzzer/fuzz_isobmff_afl

# Multi-core (1 main + 3 secondaries)
afl-fuzz -M main -i fuzzer/corpus -o /tmp/afl_out -V 300 -- fuzzer/fuzz_isobmff_afl &
afl-fuzz -S s1   -i fuzzer/corpus -o /tmp/afl_out -V 300 -- fuzzer/fuzz_isobmff_afl &
afl-fuzz -S s2   -i fuzzer/corpus -o /tmp/afl_out -V 300 -- fuzzer/fuzz_isobmff_afl &
afl-fuzz -S s3   -i fuzzer/corpus -o /tmp/afl_out -V 300 -- fuzzer/fuzz_isobmff_afl &
```

## AFL++ Coverage Metrics

AFL++ tracks edge coverage via its bitmap. Key metrics in `fuzzer_stats`:

| Field | Description |
|-------|-------------|
| `edges_found` | Unique code edges discovered (primary coverage metric) |
| `bitmap_cvg` | % of coverage bitmap populated (≈ branch coverage) |
| `execs_per_sec` | Throughput |
| `saved_crashes` | Deduplicated crash count |
| `corpus_found` | New corpus entries discovered |
| `stability` | % of runs with consistent coverage (lower = flaky target) |

## Scoring System

```
score = (edges × 5) + (unique_crashes × 200) + (corpus_found × 20) + (speed ÷ 10)
```

| Metric | Weight | Source |
|--------|--------|--------|
| Coverage edges | ×5 | `edges_found` in fuzzer_stats |
| Unique crashes | ×200 | `saved_crashes` in fuzzer_stats |
| New corpus entries | ×20 | `corpus_found` in fuzzer_stats |
| Exec speed | ÷10 | `execs_per_sec` in fuzzer_stats |

## Crash Severity

| Type | Severity |
|------|----------|
| stack-buffer-overflow | 95 |
| heap-buffer-overflow | 90 |
| use-after-free / double-free | 85–80 |
| abort | 65 |
| segfault | 70 |
| division-by-zero | 60 |
| undefined-behavior | 50 |
| unknown | 30 |

## Project Structure

```
isobmff-fuzzer/
├── fuzzer/
│   ├── harness.cpp        # AFL++ persistent mode entry point
│   ├── Makefile           # afl (default), libfuzzer, standalone, coverage
│   └── corpus/            # seed MP4/MOV files
├── scripts/
│   ├── run_fuzzer.sh      # orchestrates a single AFL++ run
│   ├── collect_coverage.sh # parses AFL++ fuzzer_stats + optional LLVM HTML
│   ├── analyze_crashes.sh  # dedup + severity via standalone replay binary
│   ├── make_corpus.py      # generates seed corpus
│   └── setup.sh           # installs AFL++, builds ISOBMFF + harness
├── dashboard/
│   ├── backend/
│   │   ├── server.py      # FastAPI
│   │   └── db.py          # SQLite
│   └── static/
│       └── index.html     # UI
├── docker/
│   ├── Dockerfile.fuzzer
│   └── Dockerfile.dashboard
├── results/               # gitignored
│   ├── runs/              # per-run meta.json + fuzzer.log
│   ├── afl_out/           # AFL++ sync directories (queue, crashes, hangs)
│   ├── crashes/           # copied crash inputs + .json analysis
│   └── coverage/          # bitmap_cvg summaries + optional LLVM HTML
└── docker-compose.yml
```

## Adding MP4 Corpus

Drop real `.mp4`/`.mov` files into `fuzzer/corpus/`. AFL++ will also use
`afl-cmin` after each clean run to minimize and merge the corpus.

```bash
wget -P fuzzer/corpus/ https://www.w3schools.com/html/mov_bbb.mp4
```

## Git Tracking

Every run auto-commits metadata:

```bash
git log --oneline | head -5
# run: 20240315_143022_a1b2 | engine=afl++ | score=4250 | crashes=2 | edges=847
```
