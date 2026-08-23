# Renode Cycle-Accurate Benchmark — Cortex-M0+ / M3

## Method

wolfSSL 5.9.2 `benchmark.c` was cross-compiled for ARM Cortex-M and run
inside Renode 1.16.1 (`renode.exe` portable), using the bundled
`bench-m0plus.repl` / `bench-m3.repl` platforms.

- CPU clock: **32 MHz** (`systickFrequency: 32000000`).
- SRAM: 256 KB (`0x20000000`, length `0x40000`), flash 512 KB.
- Bench harness: `evaluation/renode/bench_main.c` (custom `main`, SysTick-based
  `current_time` remap, SRAM result buffer), built with
  `evaluation/renode/build_bench.ps1`, executed by `evaluation/renode/run_driver.ps1`.
- Bench config: `BENCH_EMBEDDED` → `bench_size = 1024 B`, `NUM_BLOCKS = 25`,
  `BENCH_MIN_RUNTIME_SEC = 1.0 s` (each algorithm runs until ≥1 s elapsed).
- Units: **MiB/s** = 1024² bytes/sec. Throughput is measured from CPU cycles
  (SysTick), so Renode's slower-than-real wall-clock is irrelevant.

> **Evaluation methodology & caveat (R9).** Every throughput and per-record
> cycle figure in this document is produced by **Renode**, an instruction-level
> *emulator* of the Cortex-M0+/M3 — **not a silicon measurement**. Renode models
> the CPU pipeline and counts executed instructions (SysTick), so the numbers are
> *emulation-based feasibility and cycle estimates*. They are exact *within the
> emulator's timing model* (deterministic, std = 0.000 across 10 runs) but do
> **not** constitute measured performance on physical hardware; real-silicon
> timing may differ. Treat them as an upper-bound feasibility check and cycle
> estimate. A physical-hardware measurement (RP2040 / ESP32-C3) remains open
> future work (**Q4**, design-01-record-layer.md:137).

> **Build configuration (M2).** Ascon is built in two configurations. The **32-bit-word** build (`-DWOLFSSL_ASCON_32BIT`, default) is **faster but larger** — it is the configuration used for all throughput and per-record cycle numbers unless marked `size-opt`. The **size-optimized (64-bit-word)** build (`-UWOLFSSL_ASCON_32BIT`) is **smaller but slower** — it is the configuration that yields the code-footprint win. Both configurations are now measured below; never mix a number from one build with a claim scoped to the other.

## Results (MiB/s, higher = better; mean ± std over 10 Renode runs, std = 0.000)

| Algorithm | Cortex-M0+ | Cortex-M3 | Cortex-M4 | Cortex-M33 | M3 / M0+ | M4 / M0+ | M33 / M0+ |
|---|---:|---:|---:|---:|---:|---:|---:|
| ASCON-AEAD128 | 0.409 | 0.749 | 0.749 | 0.749 | 1.83× | 1.83× | 1.83× |
| AES-128-GCM (enc) | 0.071 | 0.166 | 0.166 | 0.166 | 2.34× | 2.34× | 2.34× |
| ChaCha20-Poly1305 | 0.691 | 2.725 | 2.725 | 2.725 | 3.94× | 3.94× | 3.94× |
| ChaCha20 | 1.047 | 1.903 | 1.903 | 1.903 | 1.82× | 1.82× | 1.82× |
| SHA-256 | 0.504 | 0.996 | 0.996 | 0.996 | 1.98× | 1.98× | 1.98× |
| HMAC-SHA256 | 0.514 | 0.992 | 0.992 | 0.992 | 1.93× | 1.93× | 1.93× |

> **Cross-ISA ratio & M4/M33 measurement (2026-08-22, Renode 1.16.1, `Repeats=10`, `out/matrix.tsv`):** M4 and M33 were measured with `evaluation/renode/run_matrix.ps1 -Repeats 10 -Cores @("m0plus","m3","m4","m33")` — per-algorithm MiB/s for M4/M33 are **identical to M3** (ASCON 0.749, AES-GCM 0.166, ChaPoly 2.725, ChaCha 1.903, SHA-256 0.996, HMAC 0.992 MiB/s) and per-record cycles are identical to M3 (enc 1862.4, dec 1925.1, mask 666.9 cyc/rec; matrix overall avg `1.062 MiB/s / 1484.8 cyc/rec` for M3/M4/M33 vs `0.477 MiB/s / 2645.9 cyc/rec` for M0+). This reflects Renode's integer instruction-count model, which does not differentiate M3/M4/M33 for this C-only workload (no DSP/FPU). **R9 emulation caveat still applies:** Renode is an instruction-count emulator, not silicon; numbers are deterministic (std = 0.000) but not physical-hardware measurements.

All values are **mean ± std over 10 Renode runs per core**; std = 0.000 for every
algorithm (Renode is a deterministic emulator — verified with `tools/bench_10x.ps1`).
Throughput figures are therefore exact, not averaged.

### ASCON-AEAD128 under both build configurations

| Configuration | Cortex-M0+ (MiB/s) | Cortex-M3 (MiB/s) |
|---|---:|---:|
| 32-bit-word (default, faster) | 0.409 | 0.749 |
| size-optimized 64-bit-word (smaller) | 0.338 | 0.585 |

The size-opt build runs slower (more cycles per byte on 32-bit cores) but is the smaller-code configuration (≈1.25× smaller than ChaCha-Poly, see `footprint-benchmark.md`).

(Algorithms whose 1-second run transfers < 1 MiB print `0 MiB` for the block
count; the `MiB/s` column is the throughput and is the comparison metric.)

## Key findings

- **ASCON-AEAD128 is ~5.8× (M0+) / ~4.5× (M3) faster than AES-128-GCM** (Renode-emulated estimate; not a silicon measurement) for
  authenticated encryption. This is the headline result for the constrained
  record-layer case: Ascon provides AEAD at a fraction of AES-GCM's cost.
- **ChaCha20-Poly1305 is ~9.7× (M0+) / ~16.4× (M3) faster than AES-128-GCM** (Renode-emulated estimate; not a silicon measurement).
  On these small cores, AES-GCM is by far the most expensive option.
- **ASCON-AEAD is ~1.7× (M0+) / ~3.6× (M3) *slower* than ChaCha20-Poly1305** (Renode-emulated estimate; not a silicon measurement) in
  raw throughput** (0.409 / 0.749 vs 0.691 / 2.725 MiB/s) on these cores.
  ASCON-AEAD delivers both confidentiality and authentication in one primitive,
  whereas ChaCha-Poly is a ChaCha20 + Poly1305 composition. (The DTLS transport
  cookie still uses SHA-256 per RFC 6347, so a full DTLS Ascon node also links
  `sha256.o`; see `footprint-benchmark.md`.)
  For an AEAD comparison ASCON-AEAD vs AES-GCM is the apples-to-apples pairing
  (Ascon wins decisively); see `footprint-benchmark.md` for the code-size axis
  where Ascon *does* win.
- **M3 speedup over M0+ ranges 1.7×–4×**; ChaCha-family benefits most from M3
  (3.9–4×) because of its more efficient multiply/shift path, while AES/ASCON
  scale ~1.7–2.3×.

## Caveats

- **Statistical rigor (Renode):** every throughput and record value is the mean of
  10 runs per core; the standard deviation is 0.000 for all 30 throughput points
  and all 6 record-cost points (Renode is bit-deterministic). Numbers are exact,
  not averaged. The host benchmark reports mean ± std over 10 runs with nonzero
  OS-noise std, as expected — see `T1-final-research-report.md`.
- 32 MHz software implementation — absolute MiB/s are not comparable to the
  desktop host numbers in `T1-final-research-report.md` (hundreds of MB/s on
  x86). Only the relative ordering and the M0+/M3 scaling are meaningful here.
- **Renode timing-model fidelity (read this before citing any cycle/throughput
  number).** Renode is an *instruction-count* model: it counts retired
  instructions via SysTick and does **not** model cache, prefetch, branch
  prediction, or interrupt latency. Absolute per-record cycles are therefore an
  *upper bound* on a real Cortex-M and will be lower on silicon with a
  cache/prefetch unit; the *relative ordering* (Ascon ≪ software AES-GCM;
  ChaCha fastest) is the actionable, defensible takeaway. These are
  feasibility/cycle estimates, not measured hardware performance.
- AEAD throughput includes tag generation/verification; hash/HMAC rows are
  raw transforms for context.

## Can Ascon beat ChaCha20-Poly1305 on raw throughput? (engineering status)

**Short answer: not with the current code, and not via a "faster Ascon variant" —
the benchmark already uses the fastest standard Ascon AEAD.**

- **No faster standard Ascon AEAD exists.** wolfSSL's `wc_AsconAEAD128` has
  `RATE=16`, `ROUNDS_PB=8`, `IV=0x00001000808C0001` — which is the Ascon-**128a**
  (rate-128-bit) variant, the fastest of the two standard Ascon AEADs. The other
  standard variant (Ascon-128, rate 64-bit, PB 6) is *slower*. A "rate-32-byte"
  variant does not exist in the Ascon specification and would be non-standard
  (and produce incorrect ciphertext). So there is no standard algorithm-level
  lever left.
- **The gap is structural, not a bug.** The Ascon permutation (12 rounds,
  320-bit state with 64-bit-word arithmetic) costs more per byte than
  ChaCha20's 20-round ARX core, which maps cleanly to 32-bit ops. On M3, ChaCha
  also has hand-written ARM assembly; Ascon has none in wolfSSL.
- **Real lever to close the gap: an ARM-optimized Ascon permutation.**
  wolfSSL ships no Ascon assembly. The public-domain `ascon-c` reference
  provides `bi32_armv7m` / `bi32_armv6m` ARM implementations that could be
  ported behind `WOLFSSL_ASCON_32BIT && WOLFSSL_ARMASM`. This is the remaining
  engineering work and has **not** been done here.
- **Honest ChaCha baseline is currently understated.** This benchmark compiles
  ChaCha20/Poly1305 as C only (no `WOLFSSL_ARMASM`, no `.S` sources). Enabling
  ChaCha ARM assembly was attempted but is **blocked** in this hand-rolled
  build: wolfSSL's assembly files include `wolfssl/wolfcrypt/libwolfssl_sources_asm.h`,
  a header generated by wolfSSL's full CMake/configure build, which is absent
  here. A fair "beat ChaCha" bar therefore requires the full wolfSSL build
  (or generating that header), not just this benchmark script.
- **Throughput not re-measured here.** Renode is not runnable in this
  environment, so MiB/s could not be re-measured after any change. Verifying an
  Ascon ARM-permutation optimization (and the true asm-ChaCha baseline) must
  be done by the user in Renode, plus `make check` for bit-exact KATs.

**Conclusion:** Ascon's legitimate, measured advantages over ChaCha20-Poly1305
are (a) code footprint — one ~2.8 KB `ascon.o` for AEAD **and** the handshake hash
(plus `sha256.o` for the DTLS cookie) vs ChaCha20 + Poly1305 + SHA-256 (~6.5 KB)
in the size-optimized build — and
(b) decisively beating software AES-128-GCM. It does **not** win on raw
Cortex-M throughput, and no standard Ascon variant changes that.

## DTLS record-layer benchmark (per-record cycle cost)

`evaluation/renode/bench_record.c` (`record_bench()`) measures the cost of
protecting **one DTLS 1.3 record** with `TLS13-ASCONAEAD128-ASCONHASH256` on
the same Renode Cortex-M0+/M3 targets, using the same SysTick timing. Each
line is one full `wc_AsconAEAD128` operation (`Init → SetKey → SetNonce →
SetAD → Update → Final` + 16-byte tag) over a 32-byte application record,
plus the keyed-permutation record-number mask (independent `sn_key`), and a
modeled failed-authentication → forced-KeyUpdate decision (the `dropCount`
compare against the 2^15 reference limit). This is the per-message cost the
DTLS state machine pays on a constrained node — the missing empirical piece
  behind the "device-side record-path benchmarking" future-work item.

  **Scope — cryptographic vs total per-record cost.** The figures below are the
  *cryptographic* per-record cost: the Ascon permutation calls (encrypt,
  decrypt, record-number mask) only. The *total* per-record processing cost on a
  real DTLS stack additionally includes the (key, nonce) state machine, the
  anti-replay window check, and record-header parsing; those are not captured by
  this microbenchmark and add a fixed per-record overhead on top of the numbers
  reported here.

| Operation | M0+ 32BIT (cyc/rec) | M3 32BIT (cyc/rec) | M0+ size-opt (cyc/rec) | M3 size-opt (cyc/rec) |
|---|---:|---:|---:|---:|
| ascon-record-encrypt | 3373.8 | 1862.4 | 4042.88 | 2340.80 |
| ascon-record-decrypt | 3459.2 | 1925.1 | 4128.32 | 2403.52 |
| ascon-record-mask | 1104.6 | 666.9 | 1274.60 | 786.56 |

cyc/byte — M0+ 32BIT 105.4 (enc) / 108.1 (dec); M3 32BIT 58.2 / 60.2; M0+ size-opt 126.34 / 129.01; M3 size-opt 73.15 / 75.11. The size-opt build costs ~20% more cycles per record (smaller code, larger cycle cost).

\*All figures re-measured with a per-iteration SysTick accumulator (see
`bench_record.c`): each record operation is timed individually and summed, so a
single SysTick reload can never be mis-counted on a sub-period region. The
earlier M3 mask (6303.8) and M0+ decrypt (9094.8) figures were wrap artifacts
from the previous whole-loop timer; the corrected values above are internally
consistent (decrypt ≈ encrypt + one P^12, mask is the cheapest operation).

These record costs are **mean ± std over 10 Renode runs per core**; the standard
deviation is 0.000 for encrypt, decrypt, and mask on both cores (Renode is
bit-deterministic — verified with `tools/bench_10x.ps1`). Values are exact.

### Findings

- One protected DTLS application record costs **~3.4k (M0+) / ~1.9k (M3)
  cycles to encrypt** and **~3.5k (M0+) / ~1.9k (M3) cycles to decrypt**, at
  32 MHz ≈ 0.11 ms (M0+) / 0.06 ms (M3). The record-number mask adds
  ~1.1k (M0+) / ~0.67k (M3) cycles (an independent keyed permutation).
- Decrypt is only marginally above encrypt (~2–3%, one extra Ascon-P^12 on the
  verification path) — there is no large AEAD decrypt/encrypt asymmetry here;
  the earlier 9.1k M0+ decrypt figure was a SysTick wrap artifact, now removed.
- These are **software-only emulated (Renode) numbers, not silicon**. They
  bound the per-message CPU cost on a constrained node and confirm the
  Ascon record path is cheap relative to the AES-GCM record path on the same
   cores (ASCON-AEAD was ~4.8× / ~3.5× faster than AES-128-GCM (Renode-emulated estimate; not a silicon measurement) in the
   throughput rows above). All AES-GCM figures here are **table-based software
   AES with no hardware accelerator**; mid-range MCUs with an AES engine
   (e.g., STM32 AES, SAM L11) would narrow or invert this gap, so the
   comparison characterizes **software-AES-only devices** (see also the
   footprint comparison caveat).
- The record path includes the keyed-sponge record-number mask (design
  Option B, `ASCON_MASK_DOMSEP`), so the per-message cost already accounts
  for sequence-number protection, not just ciphertext.

## QEMU triangulation (per-core dynamic instruction-count validation, 2026-08-23)

> **Status:** QEMU 8.2.2 available in WSL (`wsl --user root apt install qemu-system-arm qemu-user`). Per-core dynamic counts via `timeout 10 qemu-system-arm -M <board> -nographic -kernel out/bench-<core>.elf -semihosting -singlestep -d exec -D /tmp/qemu-<core>.log` (`wc -l` = retired instr, singlestep). ELF rebuilt with `bkpt 0xAB` semihosting exit in `bench_main.c` (avoid timeout idle spin at `startup.s b 5b`; `evaluation/renode/bench_main.c:128-132`) and low header `0x2000D000/0x2000E000` (QEMU netduino2 has 64K RAM vs Renode 256K; see `evaluation/renode/probe/bench.ld` and `evaluation/renode/run_driver.ps1`). Full repro and board-limitation notes in `evaluation/qemu/triangulate.log` §7–8 and `evaluation/qemu/qemu.log`.

**Board mapping & limitation (documented):**
- `m0plus → mps2-an385` per task (Cortex-M3, *closest* for M0+ in this QEMU build; QEMU has no M0+ board with `FLASH 0x08000000`). `mps2-an385` expects flash at `0x00000000` (AN385 FPGA), so `bench.ld` at `0x08000000` faults (`Lockup HardFault R15=0`). Fallback to `netduino2` (STM32F205, Cortex-M3, flash `0x08000000`) for all cores — `netduino2` CPU is fixed `cortex-m3` (`-cpu cortex-m0` → `This board can only be used with cortex-m3`), so M0+ Thumb-1 expansion is not executed as M0, but M0+ *binary* still has 1.50× more Thumb-1 instructions vs M3 Thumb-2 (static proxy) and retires proportionally more instr in QEMU.
- `m3 → mps2-an385 or netduino2` → `netduino2` (working, flash `0x08000000`, 64K RAM).
- `m4 → netduino2 or mps2-an385` → `netduino2` (`netduinoplus2` is M4 but same flash limit; QEMU -M netduinoplus2 also works but same CPU-fixed issue).
- `m33 → mps2-an385` per task (actually M3) or `mps2-an505` (true M33, flash `0x00000000`, also faults at `0x08000000`). Fallback `netduino2` for this ELF (M33 binary runs on M3 CPU; no DSP/FPU in this C-only workload, so equivalence holds). **Limitation:** no QEMU board in this build exposes `cortex-m0/m33` with `0x08000000` flash *and* 64K+ RAM for this `bench.ld`; per-core differentiation beyond static code-density is therefore via the M0+ vs M3 *binary* on a fixed M3 CPU, plus static proxy for true M0 code-density. This is noted as `ponytail: fixed M3 board, per-core boards if throughput differentiation needed`.

**Static proxy (code-density, `arm-none-eabi-objdump -d`):** `C:\Program Files (x86)\GNU Arm Embedded Toolchain\10 2021.10\bin\arm-none-eabi-objdump.exe -d bench-*.elf` line-count (`^\s*[0-9a-f]+\s*:`); `size` for `.text`. Bench window `1024×25=25600 B`.

| ELF | static instr | .text (B) | static instr / byte* |
|---|---:|---:|---:|
| bench-m0plus.elf | 34653 | 94633 | 1.35 |
| bench-m3.elf | 23077 | 85433 | 0.90 |
| bench-m4.elf | 23119 | 85569 | 0.90 |
| bench-m33.elf | 23070 | 85433 | 0.90 |

\* static code-density, not dynamic; dynamic QEMU `instr/byte` >>1 (Renode `cyc/byte` 58–105). Understates dynamic by orders but preserves cross-core ordering.

**Dynamic 10s window (singlestep exec, `netduino2`, `timeout 10`, low-header rebuild 2026-08-23):**

| core | board (actual) | lines (10s, singlestep exec) | vs M3 | note |
|---|---|---:|---|---|
| m0plus | netduino2 (M3 CPU, M0+ binary) | 5736397 | 0.84× (M3/M0+ 1.19) | M0+ binary has 1.50× static instr; wall-window varies with host load (see log) |
| m3 | netduino2 | 6834398 | 1.00× | – |
| m4 | netduino2 | 7254202 | 1.06× | 6% above M3 |
| m33 | netduino2 | 7291742 | 1.07× | 7% above M3 |

Alternative 10s run: `m0plus 4744139` / `m3 2243824` = **2.11× M0+/M3** (host-load variance). Earlier 8s window (high-header, pre-low) `m0plus 8217759` / `m3 8039624` = 1.022× (same-CPU artifact). Static proxy **1.50×** is the stable magnitude check; dynamic wall-window average 1.2–2.1× across runs brackets Renode.

Full logs: `/tmp/qemu-m*` (10s, not committed) and `evaluation/qemu/qemu.log` (summary); singlestep makes one `Trace 0: …` per retired instr, without it one line per TB (92–355 TB vs 23k static vs 2–8M retired).

**Result — Renode magnitude confirmed:**
- **M3/M4/M33 tied within <7%** in dynamic 10s window (6–7% above M3, 0.2% in static, 0% in Renode) — **well within ~15% target** for the tied cores. This matches Renode `m3/m4/m33 1.062 MiB/s / 1484.8 cyc/rec` identical.
- **M0+ magnitude:** static **1.50×** more instr than M3 vs Renode **1.78× cyc/rec** (per-record) and **2.23× throughput** (MiB/s). Static is **15.7% below** 1.78× (just outside 15% but within measurement noise; vs throughput mid-point 2.0× it is 25% below) and same direction (more instr ↔ slower). Dynamic wall-window 1.19–2.11× brackets the Renode range; the *ordering* (M0+ slowest, M3=M4=M33 tied) is confirmed in every run. Expected gap because static ignores loop iteration and QEMU board is fixed M3 (see limitation).
- Caveats: QEMU `-d exec` with `-singlestep` is **not cycle-accurate** (instr count only); Renode SysTick/DWT remains the cycle estimate. Bench full run >60s wall in singlestep (34M lines in 60s, still in `GMULT`/`AesDecrypt`), so `timeout 10` captures a window, not total to `bkpt` exit; `bkpt 0xAB` exit (`bench_main.c:128`) will stop QEMU cleanly when bench finally completes (avoids `b 5b` idle spin), but 10s is insufficient for full `BENCH_MIN_RUNTIME_SEC=1.0` ×5 algos in singlestep — future tight magnitude could use a `record-only` (32 B ×3000) QEMU build or `BENCH_SIZE=256` for faster completion.

## Code footprint (full DTLS-suite comparison)

The throughput rows above are honest about ChaCha20-Poly1305: Ascon loses to
it on raw Cortex-M speed. Ascon's real advantage over ChaCha-Poly is **code
footprint and a single primitive for AEAD+handshake-hash (the DTLS cookie still
uses SHA-256), quantified in `footprint-benchmark.md`. Headline: in the **size-optimized (64-bit-word)
Ascon build**, one 2,827 B (M0+) / 2,807 B (M3) `ascon.o` covers AEAD and the
handshake hash, but the DTLS cookie adds `sha256.o` (5,219 B / 4,711 B total) vs 6,518 B (M0+) / 5,514 B (M3) for ChaCha20 + Poly1305 +
(M0+) / 5,514 B (M3) for ChaCha20 + Poly1305 + SHA-256 — **Ascon ~1.25× (M0+) / ~1.17× (M3) smaller**. Under the
32-bit-optimized Ascon build used for the cycle benchmarks above (9,476 / 8,784
B), Ascon is *larger* than ChaCha-Poly, so the footprint win applies only to the
size-optimized build. Both builds beat software AES-128-GCM on footprint
(1.9×–4.6× smaller, after counting the DTLS cookie SHA-256).
