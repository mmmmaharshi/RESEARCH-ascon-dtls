# Renode Cycle-Accurate Benchmark — Cortex-M0+ / M3

## Method

wolfSSL 5.9.2 `benchmark.c` was cross-compiled for ARM Cortex-M and run
inside Renode 1.16.1 (`renode.exe` portable), using the bundled
`bench-m0plus.repl` / `bench-m3.repl` platforms.

- CPU clock: **32 MHz** (`systickFrequency: 32000000`).
- SRAM: 256 KB (`0x20000000`, length `0x40000`), flash 512 KB.
- Bench harness: `tools/renode/bench_main.c` (custom `main`, SysTick-based
  `current_time` remap, SRAM result buffer), built with
  `tools/renode/build_bench.ps1`, executed by `tools/renode/run_driver.ps1`.
- Bench config: `BENCH_EMBEDDED` → `bench_size = 1024 B`, `NUM_BLOCKS = 25`,
  `BENCH_MIN_RUNTIME_SEC = 1.0 s` (each algorithm runs until ≥1 s elapsed).
- Units: **MiB/s** = 1024² bytes/sec. Throughput is measured from CPU cycles
  (SysTick), so Renode's slower-than-real wall-clock is irrelevant.

## Results (MiB/s, higher = better)

| Algorithm | Cortex-M0+ | Cortex-M3 | M3 / M0+ |
|---|---:|---:|---:|
| ASCON-AEAD128 | 0.338 | 0.585 | 1.73× |
| AES-128-GCM (enc) | 0.071 | 0.166 | 2.34× |
| ChaCha20-Poly1305 | 0.691 | 2.725 | 3.94× |
| ChaCha20 | 1.047 | 1.903 | 1.82× |
| SHA-256 | 0.504 | 0.996 | 1.98× |
| HMAC-SHA256 | 0.514 | 0.992 | 1.93× |

(Algorithms whose 1-second run transfers < 1 MiB print `0 MiB` for the block
count; the `MiB/s` column is the throughput and is the comparison metric.)

## Key findings

- **ASCON-AEAD128 is ~4.8× (M0+) / ~3.5× (M3) faster than AES-128-GCM** for
  authenticated encryption. This is the headline result for the constrained
  record-layer case: Ascon provides AEAD at a fraction of AES-GCM's cost.
- **ChaCha20-Poly1305 is ~9.7× (M0+) / ~16.4× (M3) faster than AES-128-GCM.**
  On these small cores, AES-GCM is by far the most expensive option.
- ASCON-AEAD is lighter than ChaCha-Poly in raw throughput (ChaCha20 has no
  permutation-state permutation overhead), but ASCON-AEAD is a *single
  primitive* delivering both confidentiality and authentication, whereas
  ChaCha-Poly is a ChaCha20 + Poly1305 composition. For an AEAD comparison
  ASCON-AEAD vs AES-GCM is the apples-to-apples pairing.
- **M3 speedup over M0+ ranges 1.7×–4×**; ChaCha-family benefits most from M3
  (3.9–4×) because of its more efficient multiply/shift path, while AES/ASCON
  scale ~1.7–2.3×.

## Caveats

- Single run per configuration; Renode emulation has negligible run-to-run
  variance, but numbers are not averaged.
- 32 MHz software implementation — absolute MiB/s are not comparable to the
  desktop host numbers in `T1-final-research-report.md` (hundreds of MB/s on
  x86). Only the relative ordering and the M0+/M3 scaling are meaningful here.
- AEAD throughput includes tag generation/verification; hash/HMAC rows are
  raw transforms for context.
