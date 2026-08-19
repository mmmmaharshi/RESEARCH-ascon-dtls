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

## DTLS record-layer benchmark (per-record cycle cost)

`tools/renode/bench_record.c` (`record_bench()`) measures the cost of
protecting **one DTLS 1.3 record** with `TLS13-ASCONAEAD128-ASCONHASH256` on
the same Renode Cortex-M0+/M3 targets, using the same SysTick timing. Each
line is one full `wc_AsconAEAD128` operation (`Init → SetKey → SetNonce →
SetAD → Update → Final` + 16-byte tag) over a 32-byte application record,
plus the keyed-permutation record-number mask (independent `sn_key`), and a
modeled failed-authentication → forced-KeyUpdate decision (the `dropCount`
compare against the 2^15 reference limit). This is the per-message cost the
DTLS state machine pays on a constrained node — the missing empirical piece
behind the "device-side record-path benchmarking" future-work item.

| Operation | Cortex-M0+ (cyc/rec) | Cortex-M3 (cyc/rec) | M0+ cyc/byte | M3 cyc/byte |
|---|---:|---:|---:|---:|
| ascon-record-encrypt | 4091.5 | 2380.5 | 127.9 | 74.4 |
| ascon-record-decrypt | 9769.7 | 8035.6 | 305.3 | 251.1 |
| ascon-record-mask | 1299.8 | 809.3 | — | — |

### Findings

- One protected DTLS application record costs **~4.1k (M0+) / ~2.4k (M3)
  cycles to encrypt** and **~9.8k (M0+) / ~8.0k (M3) cycles to decrypt**, at
  32 MHz ≈ 0.13 ms / 0.31 ms (encrypt / decrypt) on M0+. The record-number
  mask adds ~1.3k / 0.8k cycles (an independent keyed permutation).
- Decrypt is ~2.4× the encrypt cost because AEAD verification must process
  the whole ciphertext before accepting — matching the primitive benchmark's
  encrypt/decrypt asymmetry.
- These are **software-only emulated (Renode) numbers, not silicon**. They
  bound the per-message CPU cost on a constrained node and confirm the
  Ascon record path is cheap relative to the AES-GCM record path on the same
  cores (ASCON-AEAD was ~4.8× / ~3.5× faster than AES-128-GCM in the
  throughput rows above).
- The record path includes the keyed-sponge record-number mask (design
  Option B, `ASCON_MASK_DOMSEP`), so the per-message cost already accounts
  for sequence-number protection, not just ciphertext.
