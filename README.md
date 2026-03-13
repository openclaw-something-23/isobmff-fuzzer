# 🐛 ISOBMFF Fuzzer

Continuous fuzzing infrastructure for [DigiDNA/ISOBMFF](https://github.com/DigiDNA/ISOBMFF) with real-time dashboard.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│ Docker Compose                                           │
│                                                          │
│  ┌─────────────────┐     ┌──────────────────────────┐   │
│  │  fuzzer service │────▶│  dashboard :56789        │   │
│  │                 │     │                          │   │
│  │  libFuzzer      │     │  FastAPI + SQLite        │   │
│  │  AFL++ (opt)    │     │  Coverage timeline       │   │
│  │  ASAN/UBSAN     │     │  Crash dedup             │   │
│  │  Coverage       │     │  Leaderboard/Scoring     │   │
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

# Scale fuzzing (4 parallel workers)
docker-compose up --build --scale fuzzer=4

# Custom fuzz time (seconds per run)
FUZZ_TIME=600 docker-compose up
```

## Scoring System

Each fuzzing run gets a score:

```
score = (cov_edges × 5) + (unique_crashes × 200) + (exec_per_sec ÷ 10)
```

| Metric | Weight | Notes |
|--------|--------|-------|
| Coverage edges | ×5 | More code explored = better |
| Unique crashes | ×200 | Deduplicated by stack hash |
| Exec speed | ÷10 | Higher throughput bonus |

## Crash Severity

| Type | Severity |
|------|----------|
| stack-buffer-overflow | 95 |
| heap-buffer-overflow | 90 |
| use-after-free | 85 |
| segfault | 70 |
| division-by-zero | 60 |
| undefined-behavior | 50 |
| unknown | 30 |

## Project Structure

```
isobmff-fuzzer/
├── fuzzer/
│   ├── harness.cpp        # libFuzzer/AFL++ entry point
│   ├── Makefile
│   └── corpus/            # seed MP4 files
├── scripts/
│   ├── run_fuzzer.sh      # orchestrates a single run
│   ├── collect_coverage.sh
│   └── analyze_crashes.sh
├── dashboard/
│   ├── backend/
│   │   ├── server.py      # FastAPI
│   │   └── db.py          # SQLite
│   └── static/
│       └── index.html     # UI
├── docker/
│   ├── Dockerfile.fuzzer
│   └── Dockerfile.dashboard
├── results/               # gitignored (too large)
│   ├── runs/
│   ├── crashes/
│   └── coverage/
└── docker-compose.yml
```

## Adding MP4 Corpus

Drop real `.mp4`/`.mov` files into `fuzzer/corpus/` — the more varied, the better coverage.

```bash
# Get sample MP4s from open sources
wget -P fuzzer/corpus/ https://www.w3schools.com/html/mov_bbb.mp4
```

## Git Tracking

Every fuzzing run automatically commits:
- Run metadata (`results/runs/<id>/meta.json`)
- Crash artifacts + analysis
- Coverage reports

```bash
git log --oneline | head -10
# run: 20240315_143022_a1b2 | score=4250 | crashes=2 | cov=847
# run: 20240315_142010_c3d4 | score=3100 | crashes=0 | cov=821
```
