# Code-Footprint Benchmark — Ascon vs ChaCha20-Poly1305 vs AES-128-GCM

## Method

To compare the **full DTLS-suite code footprint** (not just raw throughput), each
cryptographic primitive a DTLS 1.3 node must link was compiled standalone for
ARM Cortex-M and measured with `arm-none-eabi-size` (`.text` bytes, i.e. code
size; data/bss were zero for all measured objects).

- Toolchain: GNU Arm Embedded 10 2021.10 (`arm-none-eabi-gcc`, `arm-none-eabi-size`).
- Flags (identical across all objects, for a fair comparison):
  `-mthumb -mcpu=cortex-m0plus|m3 -mfloat-abi=soft -Os -ffreestanding
  -nostartfiles -fno-builtin` plus the research-harness user settings
  (`WOLFSSL_USER_SETTINGS`, `BENCH_EMBEDDED`, `NO_WOLFSSL_DIR`, `WC_NO_RNG`,
  `SINGLE_THREADED`, `NO_*`, `WOLFSSL_BENCHMARK_FIXED_UNITS_MB`) and
  `-include tools/renode/bench_stub.h`.
- Harness: `tools/renode/size_primitives.ps1` (builds each object, prints sizes
  for both cores, and emits `out/size-<core>/footprint.tsv`).
- Common code (`misc.c`, `error.c`, `wc_port.c`, the TLS stack) is excluded —
  it is linked by every suite and is not part of the cipher's footprint. This
  matches the project's existing honesty caveat ("These sizes do not predict
  final embedded image size or RAM use").

### Important: Ascon has two build configurations

wolfSSL's `ascon.c` has two implementations selected by `WOLFSSL_ASCON_32BIT`:

- **32-bit path (`WOLFSSL_ASCON_32BIT`)** — decomposes the 320-bit state into
  ten `word32` lanes. This is the build used by the **throughput benchmark**
  (`tools/renode/build_bench.ps1` defines `-DWOLFSSL_ASCON_32BIT`) and is the
  fast path on 32-bit cores. It is also auto-selected by wolfSSL's settings
  unless explicitly unset, so a plain `-DWOLFSSL_USER_SETTINGS` build lands here.
- **64-bit-word path (default, `WOLFSSL_ASCON_32BIT` undefined, `WORD64_AVAILABLE`)**
  — the original reference permutation over `word64`. On a 32-bit core this
  emulates 64-bit arithmetic in software (smaller code, slower). This is the
  configuration behind the report's earlier **2,827 B** Ascon-object figure
  (`build\arm\ascon.o`), confirmed here as **2,847 B** on M0+ with a clean
  `-UWOLFSSL_ASCON_32BIT` build.

The two Ascon builds are **not interchangeable**: the 2,827 B footprint claim
is the size-optimized (64-bit-word) build, whereas the fresh throughput/cycle
numbers (0.409 / 0.749 MiB/s on M0+ / M3) come from the 32-bit-optimized
    build used for the cycle benchmarks. The paper must state which build each
    number refers to. In both builds a DTLS node additionally links `sha256.o` for the RFC 6347 transport cookie; the suite-size totals in 'Full DTLS-suite footprint' include it.

## Per-object `.text` (bytes, Cortex-M0+ / M3)

| Object | Primivite(s) | M0+ | M3 |
|---|---|---:|---:|
| `ascon.o` (32BIT path)        | Ascon-AEAD128 + Ascon-Hash256 | 9,476 | 8,784 |
| `ascon.o` (64-bit-word path)  | Ascon-AEAD128 + Ascon-Hash256 | 2,847 | 2,807 |
| `chacha.o`                    | ChaCha20 stream cipher         | 1,310 | 1,226 |
| `poly1305.o`                  | Poly1305 MAC                   | 1,920 | 1,484 |
| `chacha20_poly1305.c`         | ChaCha20-Poly1305 AEAD glue    |   916 |   900 |
| `sha256.o`                    | SHA-256 (handshake transcript + HKDF) | 2,372 | 1,904 |
| `aes.o`                       | AES (GCM core)                 | 20,109 | 19,677 |

## Full DTLS-suite footprint (sum of primitives a node must link)

For each suite we sum the primitives the DTLS 1.3 record + handshake actually
require:

  - **Ascon `0x006E`**: `ascon.o` — one permutation delivers **both** the AEAD
    (record protection) **and** the handshake hash (transcript + HKDF + Finished).
    The TLS 1.3 handshake needs no SHA-256. However, the **DTLS transport cookie
    (RFC 6347) retains SHA-256** (`DTLS_COOKIE_TYPE = WC_SHA256` in
    `wolfssl/src/dtls.c`), so a DTLS node additionally links `sha256.o` for the
    cookie. `sha256.o` is therefore counted in the Ascon suite totals below.
- **ChaCha20-Poly1305**: `chacha.o` + `poly1305.o` + `chacha20_poly1305.c` for
  the AEAD, **plus `sha256.o`** because the TLS 1.3 handshake (transcript hash,
  HKDF, Finished, PSK binders) runs on SHA-256, not on a ChaCha-derived hash.
- **AES-128-GCM**: `aes.o` + `sha256.o` (same SHA-256 handshake dependency).

| Suite (primitives linked) | M0+ (32BIT Ascon) | M0+ (size-opt Ascon) | M3 (32BIT Ascon) | M3 (size-opt Ascon) |
|---|---:|---:|---:|---:|
| Ascon 0x006E (AEAD+hash; +SHA-256 cookie) | 11,848 | **5,219** | 10,688 | **4,711** |
| ChaCha20-Poly1305 (+SHA-256)          | 6,518 | 6,518 | 5,514 | 5,514 |
| AES-128-GCM (+SHA-256)                | 22,481 | 22,481 | 21,581 | 21,581 |

Ratios (smaller is better for footprint):

| Comparison | M0+ (size-opt Ascon) | M3 (size-opt Ascon) | M0+ (32BIT Ascon) | M3 (32BIT Ascon) |
|---|---:|---:|---:|---:|
| ChaCha-Poly / Ascon | **0.80×** (Ascon 1.25× smaller) | **0.85×** (Ascon 1.17× smaller) | 0.55× (Ascon larger) | 0.52× (Ascon larger) |
| AES-GCM / Ascon     | 4.31× (Ascon smaller) | 4.58× (Ascon smaller) | 1.90× (Ascon smaller) | 2.02× (Ascon smaller) |

## Findings

  - **Ascon's footprint win over ChaCha20-Poly1305 is real but modest, and holds
    only for the size-optimized (64-bit-word) Ascon build**: the Ascon suite
    (`ascon.o` + `sha256.o` for the DTLS cookie) totals 5,219 B (M0+) / 4,711 B
    (M3), versus 6,518 B / 5,514 B for ChaCha20 + Poly1305 + SHA-256 — **Ascon is
    ~1.25× (M0+) / ~1.17× (M3) smaller** (not the ~2.3×/2.0× previously stated;
    that earlier figure omitted the cookie's SHA-256). This is the configuration
    behind the report's 2,827 B `ascon.o` figure (cookie SHA-256 is added on top).
  - **Under the 32-bit-optimized Ascon build used for the throughput benchmark,
    Ascon is *larger* than ChaCha-Poly** (11,848 vs 6,518 B on M0+; 10,688 vs
    5,514 B on M3 — about 1.8–1.9× larger). The single-primitive advantage is
    outweighed by the 32-bit-decomposed permutation's code size plus the cookie
    SHA-256. The paper must not claim a footprint win for the 32BIT build.
  - **Both Ascon builds beat software AES-128-GCM on footprint**
    (1.9×–4.6× smaller), because AES-GCM needs the large table-based `aes.o`
    plus SHA-256; the gap is narrower than the earlier 2.4×–7.9× figure because
    the Ascon totals now include the cookie SHA-256.
  - The honest headline (per reviewer R1) is therefore: *Ascon's advantage over
    ChaCha20-Poly1305 on constrained nodes is code footprint — the handshake hash
    is folded into the Ascon primitive, while ChaCha-Poly needs a separate
    SHA-256 for the handshake; the DTLS cookie adds SHA-256 to both, narrowing but
    not erasing Ascon's lead (≈1.25×/1.17× smaller in the size-opt build) — not
    raw throughput. The footprint win is real for the size-optimized Ascon build;
    it is not a throughput win, and it does not hold for the 32-bit-optimized
    build used in the cycle benchmarks.*

## Caveats

- Per-object `.text` is a standard, conservative footprint proxy; it does not
  include linker dead-code elimination or the shared TLS-stack code, which is
  common to all suites and excluded by design.
- The 64-bit-word Ascon build uses software-emulated 64-bit arithmetic on a
  32-bit core; its runtime cost on Cortex-M0/M3 is higher than the 32BIT build,
  which is why the cycle/throughput benchmarks use the 32BIT build. The
  footprint and throughput figures come from different, explicitly-labelled
  builds.
- `aes.o` includes AES-GCM and AES-CCM code paths; a build limited to GCM only
  could be marginally smaller, but it would still dwarf Ascon.
