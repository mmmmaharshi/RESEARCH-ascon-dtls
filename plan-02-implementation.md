# Phase 2 Plan — Implementation (base: wolfSSL)

**Goal:** working DTLS 1.3 connection using suite 0x006E (TLS_ASCONAEAD128_ASCONHASH256) between two wolfSSL endpoints; instrumented record layer; own test vectors.

**Design inputs:** design-01-record-layer.md §4.1 (KDF/HMAC-Ascon-Hash256), §4.2 (nonce), §4.2.1 (mask Option B), §4.3 (usage limits).

---

## 1. Environment

- wolfSSL **v5.9.2-stable (June 2026)** — VERIFIED
- DTLS 1.3 since v5.4.0, flag `WOLFSSL_DTLS13` (also `WOLFSSL_DTLS13_5_9_0_COMPAT` for pre-5.9.0 interop) — VERIFIED
- Ascon primitives present since v5.8.0: `wc_AsconAEAD128`, `wc_AsconHash256` behind `HAVE_ASCON`; NOT in default/--enable-all; requires `--enable-ascon --enable-experimental` (or settings.h HAVE_ASCON + WOLFSSL_EXPERIMENTAL_SETTINGS). `wc_AsconXOF128` does NOT exist (not needed) — VERIFIED
- **Suite 0x006E NOT present anywhere in wolfSSL** (internal.c 46k lines, internal.h, tls13.c: zero matches). Adding the suite is upstream-level work: internal.h suite enum + internal.c suite table + tls13.c AEAD/hash wiring + record-layer mask hooks. This IS the paper's implementation contribution — VERIFIED
- Mask needs Ascon-P^12 permutation: ascon.h exposes AEAD/Hash only — plan: independent ~40-line Ascon-P implementation in our record-layer module (also clean-room hygiene for research code)
- Flags: HAVE_ASCON, WOLFSSL_EXPERIMENTAL_SETTINGS, WOLFSSL_DTLS13, WOLFSSL_TLS13
- Dev OS: native Windows build first (MSVC/MinGW); WSL as fallback for benchmarking
- No IANA registration needed — wire code 0x006E exists

## 2. Tasks

**M2.1 Desktop build + KATs — COMPLETE (2026-08)**
1. ✅ Build recipe (Windows, verified): CMake + Ninja + ucrt64 gcc; `-DWOLFSSL_USER_SETTINGS=ON -DCMAKE_C_FLAGS=-I<proj-root> -DCMAKE_ASM_FLAGS=-I<proj-root> -DWOLFSSL_EXAMPLES=ON -DWOLFSSL_CRYPT_TESTS=ON`; user_settings.h at project root (full macro list = research build config, on disk)
2. ✅ **testwolfcrypt exit 0; `ASCON Hash test passed!` + `ASCON AEAD test passed!` (NIST KATs)**
3. ✅ 0x006E has NO suite-id entry in wolfSSL (verified byte-complete); DTLS 1.3 mature enough (v5.4.0+, 5.9.2 has compat flag)

**wolfSSL quirks found (must keep in user_settings.h):** HAVE_AEAD, HAVE_FFDHE_2048, WC_RSA_PSS, HAVE_TLS_EXTENSIONS, WOLFSSL_TLSX, WOLFSSL_SEND_HRR_COOKIE, HAVE_SUPPORTED_CURVES, HAVE_HASHDRBG all required for DTLS 1.3 (autotools sets them implicitly; user_settings does not). HAVE_HASHDRBG omission = uninitialized RNG mutex = Windows access-violation crash in wc_InitRng_ex. Two local patches: functions.cmake (append ascon.c) + user_settings.h. Shared build: run with build dir on PATH.

**M2.2 Wire suite 0x006E, PSK mode (2 wks)**
1. Add suite ID 0x006E to wolfSSL ciphersuite table
2. Map AEAD → wc_AsconAEAD128; handshake hash → Ascon-Hash256 (transcript, HKDF, Finished, exporters, binders)
3. Grep tls13.c for SHA-256 hardcoding; parameterize the handshake hash
4. Start with **external PSK mode `psk_ke`** (RFC 9147 §5.1, pure PSK, no DHE), 256-bit key, identity `Client_identity`; `psk_dhe_ke` also supported for interop: no certificates → the handshake hash is Ascon-Hash256, but the DTLS transport cookie still uses SHA-256 per RFC 6347 (so "no SHA-256 anywhere" is false — restate as "no SHA-256 in the handshake transcript hash or record AEAD")
5. Handshake + application data over DTLS 1.3, both directions

**M2.3 Mask + usage accounting (1 wk)**
1. Implement §4.2.1 mask in DTLS 1.3 record layer: sn_key = HKDF-Expand-Label(secret, "sn", "", key_length); sponge-PRF state S = sn_key(128) || ct[0..15](128) || domsep(64); Ascon-P^12; mask = low 16 bits; XOR into wire seq (send + recv paths)
2. Usage-limit accounting: count records protected + records failing authentication per key; KeyUpdate trigger (configurable cap for tests, MUST-bound 2^48-1 per RFC 9846 §4.7.3)
3. Negative tests: wrong key, tampered ciphertext, tampered wire seq

**M2.4 Test harness green — CLOSED (validation §5)**
1. Lossy/reordering proxy between endpoints; retransmission; replay within/outside window — **VERIFIED** across observe/tamper/replay/truncate/sequence/epoch (see dtls13-ascon-validation.md §5)
2. KeyUpdate mid-connection — *follow-up*: forced-KeyUpdate path (`Dtls13CheckAEADFailLimit` 2^15 → `dtls13DoKeyUpdate`) implemented + unit-reachable but not driven by the proxy harness
3. Generate own record-layer test vectors — **DONE** (mask vectors: tools/ascon_mask_kat.c, validation §4.2.1; full-record AEAD encrypt/decrypt vectors: tools/ascon_record_kat.c, validation §4.2.2 + committed `tools/ascon_record_kat.txt`, values verified against a fresh build — KAT OK)

**M2.5 X.509 mode with Ascon-Hash256 — DONE (validation §6)**
- Mutual RSA-PSS cert auth over DTLS 1.3 0x006E; CertificateVerify signs over the
  Ascon-Hash256 transcript; only residual SHA-256 is the RSA-PSS *scheme* hash
  (by-design, RFC 9846 §4.2.3, obsoletes RFC 8446). PSK path still the primary paper claim.

## 3. Milestones

| Milestone | Exit criterion |
|-----------|----------------|
| M2.1 | Build green, Ascon KATs pass |
| M2.2 | PSK-mode DTLS 1.3 handshake + data with 0x006E |
| M2.3 | Mask + accounting working, negative tests pass |
| M2.4 | Loss/reorder negative-proxy harness green (VERIFIED §5); KeyUpdate-path = follow-up; own vectors DONE (§4.2.1 mask + §4.2.2 record AEAD) |
| M2.5 | X.509 cert-mode 0x006E handshake (RSA-PSS, Ascon-Hash256) — DONE (§6) |

## 4. Risks

1. SHA-256 hardcoding in wolfSSL TLS 1.3 paths → grep tls13.c early (M2.2 step 3)
2. DTLS 1.3 maturity → check release history at M2.1
3. Mask hooks don't exist in record layer → they are the contribution; code is ours
4. Windows build quirks (wolfSSL MinGW/MSVC) → WSL fallback documented

## 5. Phase 2 exit

Working 0x006E DTLS 1.3 endpoint pair + vector file → feeds Phase 4 (formal model) and Phase 5 (benchmarks).

## 6. Verified result

- wolfSSL build: PASS (CMake + Ninja + MinGW, exit 0).
- Ascon Hash256 KAT: PASS.
- Ascon-AEAD128 KAT: PASS.
- DTLS 1.3 PSK handshake: PASS.
- Encrypted echo: PASS (`ascon-dtls test message`).
- Suite: `TLS_ASCONAEAD128_ASCONHASH256` (IANA `0x006E`).
- Temporary diagnostic logs: removed from library sources.
- The wolfCrypt test program reports an RSA signature verification warning in
  this minimal research build, but exits 0. This is outside the Ascon-DTLS
  PSK scope.
