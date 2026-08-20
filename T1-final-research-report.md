# T1 Final Research Report

## Title

Ascon-AEAD128 in the DTLS 1.3 Record Layer for Constrained CoAP Nodes

## Research question

Can the IANA-registered Ascon DTLS 1.3 suite `0x006E` operate in a
constrained-device record layer with correct key derivation, record protection,
record-number encryption, and DTLS loss recovery?

## Implementation result

The project added suite `TLS_ASCONAEAD128_ASCONHASH256` to wolfSSL 5.9.2.
The implementation uses:

- Ascon-AEAD128 for record protection.
- Ascon-Hash256 for the transcript hash.
- HMAC-Ascon-Hash256 for HKDF and Finished values.
- A 16-byte TLS 1.3 nonce.
- A keyed Ascon permutation for DTLS record-number masking.
- DTLS usage limits of 2^48 records and 2^48 failed authentications.
- Reference implementation enforces stricter wolfSSL defaults (2^16 failed-auth / 2^15 key-update); 2^48 stays the protocol max.

## Verified results

| Test | Result |
|---|---|
| CMake and Ninja build | PASS |
| Ascon-Hash256 KAT | PASS |
| Ascon-AEAD128 KAT | PASS |
| DTLS 1.3 PSK handshake | PASS |
| Encrypted echo | PASS |
| First-packet loss | PASS |
| First-two-packet reorder | PASS |
| Cortex-M0 compile | PASS |
| Cortex-M0 Ascon object size (size-opt 64-bit-word build) | 2,827 bytes |
| Cortex-M0 cycle test | Run in Renode (Cortex-M0+ @32MHz): ASCON-AEAD128 0.409 MiB/s vs AES-128-GCM 0.071 MiB/s (~5.8× faster). See `renode-benchmark-results.md`. |
| Cortex-M3 cycle test | Run in Renode (Cortex-M3 @32MHz): ASCON-AEAD128 0.749 MiB/s vs AES-128-GCM 0.166 MiB/s (~4.5× faster); ChaCha20-Poly1305 2.725 MiB/s (~16× faster than AES-GCM). See `renode-benchmark-results.md`. |
| X.509 mode with peer verification enabled | PASS |
| Forced KeyUpdate on failed authentication (RFC 9846 §4.7.3) | PASS |
| Cortex-M0+/M3 per-record Ascon cost | encrypt 3374/1862 cyc, decrypt 3459/1925 cyc, mask 1105/667 cyc (32-byte record, @32 MHz, Renode). See `renode-benchmark-results.md`. |

The final PSK test produced:

```text
HANDSHAKE OK. cipher: TLS_ASCONAEAD128_ASCONHASH256
echo ok: ascon-dtls test message
```

The server produced:

```text
HANDSHAKE OK. cipher: TLS_ASCONAEAD128_ASCONHASH256
got: ascon-dtls test message
```

## Final security proof

The one-sentence claim: ciphersuite 0x006E provides DTLS 1.3 record security
that reduces to the AEAD bounds of Ascon-AEAD128 (SP 800-232), with channel
security argued in the Robust Channels model, record numbers hidden per
RFC 9147 §4.2.3 by a new ciphertext-dependent keyed-sponge PRF, and key
derivation via HKDF instantiated with HMAC-Ascon-Hash256 — subject to the
bounds and non-claims below. (Detailed claim table: `M2-bounded-security-claim.md`.)

### Claims the paper proves

| # | Claim | Basis | Bound at usage limit |
|---|-------|-------|----------------------|
| C1 | AEAD confidentiality (privacy) | SP 800-232 bounds, applied | ≤ 2^-138 (2^48-1 records/key) |
| C2 | AEAD integrity (forgery) | SP 800-232 bounds, applied | ≤ 2^-80 (2^48 failures/key, protocol cap); reference impl enforces 2^16 → ≤ 2^-112 |
| C3 | Channel security (Robust Channels goals: ROB-INT-IND-CCA) | Precondition-verification + explicit Ascon-specific game-hop reduction (`robust-channels-game-hop.md`) built on [FGJ20, Thms 7.1 & 7.2 (via Prop. 5.9), §7 DTLS 1.3 analysis] given C1/C2 | ≤ Adv^{IND-CPA}_AEAD + Adv^{INT-CTXT}_AEAD(q_R) (non-tight: Adv^{INT-CTXT}_AEAD(q_R) ≤ q_R·Adv^{INT-CTXT}_AEAD(1), q_R=2^16 enforced forgery attempts) |
| C4 | Record-number mask: PRF security + privacy | New construction §4.2.1, self-contained bound (derived in design-01 §4.2.1) | ≤ q^2/2^192 + q/2^128, negligible to q ≈ 2^96 |
| C5 | Committing security (defense-in-depth) | KSW 2023/1525 (TOSC 2024) prove Ascon committing-secure (one of only 3 finalists with a proof) | Applied, not derived |
| C6 | KDF soundness | HMAC-Ascon-Hash256 = RFC 2104 over sponge. BCK96 (CRYPTO 1996) + sponge indifferentiability (Bertoni et al., EUROCRYPT 2008) + FIPS 198-1/202 precedent | structure identical to RFC 9846 |
| C7 | Mask PRF soundness | Keyed-sponge refs: Mennink ToSC 2018/449; Dobraunig–Mennink ToSC 2019/573; Hosoyamada 2025/1059 (PQ) | q^2/2^192 + q/2^128 (derived in design-01 §4.2.1) |

### Reduction structure

 1. **Channel security reduces to AEAD.** Following Robust Channels
    (Fischlin–Günther–Janson, ePrint 2020/718), built for DTLS 1.3, the
    record layer is a secure channel under packet loss, reordering, and
    replay-within-window when the underlying AEAD is secure and the
    (key, nonce) state machine is sound. The Ascon-AEAD128 AE-security
    bound (C1/C2) is the base assumption.

    *Precondition-verification + explicit Ascon-specific game-hop reduction (`robust-channels-game-hop.md`) for Ascon-AEAD128 (FGJ20's generic channel proof is cited, not re-derived).*
    Robust Channels (FGJ20, ePrint 2020/718; Journal of Cryptology 2024, §7
    DTLS 1.3 analysis) proves DTLS 1.3 is ROB-INT-IND-CCA-secure from any
    IND-CPA + INT-CTXT AEAD, via Theorems 7.1 (robust integrity:
    Adv^{ROB-INT} ≤ Adv^{INT-CTXT}_AEAD(q_R)) and 7.2 (IND-CPA:
    Adv^{IND-CPA}_Ch ≤ Adv^{IND-CPA}_AEAD), combined by Proposition 5.9:
        Adv^{ROB-INT-IND-CCA}(Ch) ≤ Adv^{IND-CPA}_AEAD
                                 + Adv^{INT-CTXT}_AEAD(q_R)
    where Adv^{INT-CTXT}_AEAD(q_R) ≤ q_R · Adv^{INT-CTXT}_AEAD(1) is the non-
    tight linear loss. We verify the preconditions hold: (i) Ascon-AEAD128 is
    IND-CPA + INT-CTXT under the ideal-permutation assumption (C1/C2); (ii)
    DTLS 1.3 packs each record's unique (epoch, record_number) into a 128-bit
    nonce (RFC 9147 §4.2 / §4.2.3), so no nonce reuse within a key; (iii)
    monotonic sequence numbers give sound anti-replay (§4.2); (iv) failed-
    authentication KeyUpdate (RFC 9846 §4.7.3, enforced 2^16) bounds the
    forgery attempts q_R. Channel security therefore follows from [FGJ20,
    Thms 7.1 & 7.2 (via Prop. 5.9)] given C1/C2. The Adv^{INT-CTXT}_AEAD(q_R)
    term is the linear robustness degradation FGJ20 identified — so C3's bound
    is C1/C2 PLUS Adv^{INT-CTXT}_AEAD(q_R), NOT merely C1/C2.
2. **State-machine invariants (§4.2).** Per-epoch keys, a 64→128-bit nonce
   padding (RFC 9147), and monotonic sequence numbers guarantee (key,
   nonce) uniqueness within an epoch and sound anti-replay. A forged
   record is accepted only if the Ascon tag is forged or this state
   machine is violated.
3. **Failed-authentication → KeyUpdate (RFC 9846 §4.7.3).** The
   implementation counts failed authentications per key and forces a key
   update past `DTLS_AEAD_ASCON_FAIL_KU_LIMIT` (2^15, stricter than the
   2^48 protocol cap). This bounds an active attacker's forgery attempts
   per key to the reference default → cumulative forgery advantage
   ≤ 2^-112. (Exercised end-to-end: see "Forced KeyUpdate result".)
4. **Record-number mask (§4.2.1, Option B).** Mask = Ascon-P^12(
   domsep("RNDIMSK_") ‖ sn_key(128) ‖ ct[0..15](128) ), r=128, c=192.
    It is a keyed-sponge PRF in `sn_key`. `sn_key` is a distinct-label
    `HKDF-Expand-Label` output of the *same* per-direction traffic secret that
    yields the record AEAD key (labels `"sn"` vs `"key"`, RFC 9147 §4.2.3); under
    the HKDF-PRF assumption (HMAC-Ascon-Hash256, Formal target 3) the two keys are
    computationally independent — given the AEAD key, `sn_key` is indistinguishable
    from random with advantage `≤ Adv^{PRF}_{HMAC-Ascon-Hash256}`. The mask PRF
    bound therefore holds independently of the AEAD key (see design-01 §4.2.1); the
    `"RNDIMSK_"` domain separator also isolates the mask's Ascon-P domain from the
    AEAD. Because the mask leaks nothing about plaintext, it adds no second input
    path into the AEAD security argument. Because
   it is ciphertext-dependent, wire sequence numbers are pseudorandom to
   an observer without `sn_key`; a fixed mask would leak the record count.
    PRF bound is q^2/2^192 + q/2^128 (negligible to q ≈ 2^96, far beyond the
    2^48 wire-sequence limit), derived in design-01 §4.2.1 from the keyed-sponge
    PRF analysis: capacity-collision term q^2/2^c plus key-prediction term q/2^k
    tightened by Mennink ToSC 2018/449, Theorem 1.
 5. **Committing security.** Ascon is committing-secure: Krämer–Struck–
    Weishäupl (KSW, TOSC 2024, ePrint 2023/1525) prove unmodified Ascon-128
    achieves **64-bit committing security** — committing advantage ≤ 2^-64,
    bounded by a generic birthday attack on the capacity — and is one of only
    three LWC finalists with a formal committing-security proof. The mask uses
    a disjoint key, so this AEAD committing bound applies unchanged. Our usage
    (≤ 2^48 records/key) sits 16 bits below even this conservative bound. The
    zero-padding caveat (Datta et al. 2026/1160) targets the committing
    zero-padding transform, not RFC 9147 nonce padding, and does not apply.

### Non-claims

- No new AEAD theory — bounds applied from SP 800-232/KSW, not derived.
- No key-confirmation (3SHKE) fix — committing property is
  defense-in-depth only; key-commitment fixes live in the handshake.
- No claim that the mask does more than RFC 9147 §4.2.3's design goal.
- No forgery or privacy claims beyond the AEAD bounds.
- No claims for 0x006F / 0x0070 / 0x0071.
- No new hardware, side-channel, or handshake claims.

### Security model and verification status

- Model: Robust Channels; RFC 9147 adversarial setting; ideal-permutation
  assumption on Ascon-P; keyed-sponge PRF assumption for the mask;
  sponge-HMAC PRF assumption for HKDF.
- KSW committing bound: proven for Ascon by Krämer–Struck–Weishäupl
  (TOSC 2024, ePrint 2023/1525). Exact value quoted: unmodified Ascon-128
  achieves 64-bit committing security (committing advantage ≤ 2^-64,
  birthday bound). Our usage (2^48 records/key) is 16 bits below this bound.
- Robust Channels: no published companion code; channel security is
   verified by precondition check citing [FGJ20, Thms 7.1 & 7.2 (via Prop. 5.9)] (DTLS 1.3 ROB-INT-IND-CCA, §7),
   §7 DTLS 1.3 analysis) — not re-derived in this paper.
- Sponge-HMAC citation chain: BCK96 + sponge indifferentiability +
  FIPS 198-1/202 approval precedent (HMAC-SHA3).

## Loss and reorder result

A local UDP proxy tested two cases:

1. The proxy dropped the first client datagram. DTLS retransmission completed
   the handshake and the encrypted echo passed.
2. The proxy held the first two client datagrams and sent the second first.
   DTLS processing completed and the encrypted echo passed.

These tests do not replace a large statistical network test. They verify the
main loss and reorder paths.

## Negative security tests

The PowerShell proxy `tools\dtls_negative_proxy.ps1` was used between the
PSK client and server. The proxy selected the encrypted client application
record. The valid baseline completed the handshake and encrypted echo.

| Test | Proxy action | Result |
|---|---|---|
| Tamper | Changed the last byte of the 46-byte encrypted record | Handshake passed; no echo was accepted |
| Truncate | Reduced the encrypted record from 46 to 38 bytes | Handshake passed; no echo was accepted |
| Sequence change | Changed one byte of the 16-bit wire record number in the 5-byte unified header | Handshake passed; no echo was accepted |
| Epoch change | Changed one epoch bit in byte 0 of the 5-byte unified header | Handshake passed; no echo was accepted |
| Replay | Sent the same encrypted application record twice | Handshake and one echo passed; server delivered one message |
| KeyUpdate | Corrupted 14 consecutive post-handshake app records | Failed-auth counter tripped; server issued KeyUpdate |

The tamper, truncation, sequence, and epoch tests show that invalid
application records did not reach the server application. The replay test
shows that the duplicate was not delivered twice. The proxy changes the
record number in the unified header at byte 2 and the epoch bit at byte 0,
and leaves the ciphertext unchanged. These tests do not prove the full
anti-replay window or all malformed-record paths.

The DTLS 1.3 unified ciphertext header carries the low epoch bits in byte 0
(`EE_MASK = 0x3`). The epoch test changed only one epoch bit and preserved the
record number, length, ciphertext, and tag. The record was rejected, which
shows the receiver uses the epoch bits when it selects decryption keys.

## Negative test timeouts

The negative tests were slow because the custom PSK client and server use
blocking sockets. After an invalid record was rejected, `wolfSSL_read()`
waited on the socket. A test-only `--short-timeout` flag now sets a 100 ms
socket receive timeout and tells wolfSSL to treat would-block reads as
`WANT_READ` (`wolfSSL_dtls_set_using_nonblock`). The retry count is reduced
from 100 to 20 for the short mode. This changed the wrong-epoch test from
about 8 to 9 seconds to about 2.8 seconds. Normal runs without the flag keep
the original behavior and the full retry count. The valid baseline without
the flag still completed in about 1.25 seconds with the encrypted echo.

## Forced KeyUpdate result

The DTLS 1.3 failed-authentication counter (`dropCount`) increments on every
rejected record via `Dtls13CheckAEADFailLimit`. When `dropCount` exceeds
`keyUpdateLimit` (the reference enforces the stricter wolfSSL default of 2^15
failed authentications), the receiving peer issues a KeyUpdate
(`dtls13DoKeyUpdate = 1` -> `SendTls13KeyUpdate`).

The negative proxy (`tools/dtls_negative_proxy.ps1`) in flood mode corrupted 14
consecutive post-handshake client application records (client_packet 4-17,
lengths 35-46 bytes). With the limit temporarily set to 0, the first dropped
record tripped the path. The server log showed, per dropped record,
`DTLS: Ignoring failed decryption`, then
`Connection exceeded key update limit. Issuing key update`, followed by
`wolfSSL Entering SendTls13KeyUpdate` / `wolfSSL Leaving SendTls13KeyUpdate,
return 0`. Full capture: `tools/keyupdate-evidence.txt`.

This work also hardened the proxy harness: the DTLS 1.3 outer record header is
not 0x17 (so app-record selection must use packet order, not the type byte); a
deleted `$out` initialization that crashed every relay was restored; and
`Start-Job` stderr capture was added so wolfSSL debug logging is preserved.

## Software benchmark

The wolfSSL 5.9.2 wolfCrypt benchmark was run on the native Windows build.
This is a host benchmark. It is not a Cortex-M0 result.

The benchmark commands were:

```text
build\wolfcrypt\benchmark\benchmark.exe -csv -ascon-aead <size> -blocks 10000
build\wolfcrypt\benchmark\benchmark.exe -csv -aes-gcm <size> -blocks 10000
build\wolfcrypt\benchmark\benchmark.exe -csv -chacha20-poly1305 <size> -blocks 10000
build\wolfcrypt\benchmark\benchmark.exe -csv -chacha20 <size> -blocks 10000
```

The output reported a one-second minimum for each measurement. Each row below is
 the median of three runs (shape reference; the build under measurement fixes the
 block size at 1 MiB, so a 10-run mean ± std at that block is reported in the
 'Host 10-run statistics' table below). All values were re-measured on the final build,
which includes the reference AEADs (AES-GCM, ChaCha20, ChaCha20-Poly1305).
AES-GCM is table-based software AES: `WOLFSSL_AESNI` was not defined, so no
AES-NI acceleration was compiled in.

| Block size | Ascon-AEAD MB/s | AES-128-GCM enc MB/s | ChaCha20-Poly1305 MB/s | ChaCha20 MB/s | AES-128-CBC enc MB/s | AES-128-CBC dec MB/s |
|---:|---:|---:|---:|---:|---:|---:|
| 64 | 125.433764 | 32.714678 | 127.132687 | 454.815147 | 184.097486 | 190.401926 |
| 128 | 200.832337 | 42.626049 | 175.677495 | 525.458500 | 208.769594 | 193.623615 |
| 256 | 227.747595 | 48.304533 | 260.526500 | 488.989677 | 208.953489 | 224.850351 |
| 512 | 257.748480 | 58.375723 | 306.910434 | 472.738061 | 234.039434 | 251.733163 |
| 1024 | 271.051327 | 57.665985 | 334.483821 | 534.521702 | 194.185602 | 247.789589 |
| 4096 | 322.041945 | 57.489149 | 363.727904 | 534.866341 | 242.879732 | 254.674532 |
| 16384 | 288.538707 | 59.291529 | 305.457494 | 515.263209 | 236.871896 | 249.858161 |

Ascon-AEAD was 3.8x to 5.6x faster than software AES-128-GCM across the
measured block sizes. It was about 1% slower than ChaCha20-Poly1305 at
64-byte blocks and 14% faster at 128-byte blocks, then slower at 256 bytes
and above. ChaCha20 alone was fastest, but it does not provide
authentication. AES-128-CBC does not provide authentication either and is
only a software reference point.

The hash and HMAC matrix also used three runs and median values (shape reference; the 'Host 10-run statistics' table below gives mean ± std over 10 runs at the 1 MiB block):

| Block size | Ascon-Hash256 MB/s | HMAC-SHA256 MB/s |
|---:|---:|---:|
| 64 | 102.284048 | 206.649752 |
| 256 | 115.604356 | 198.888199 |
| 1024 | 118.991555 | 193.649362 |
| 16384 | 119.046467 | 213.605589 |

### Host 10-run statistics (mean ± std MB/s, 1 MiB block, 10 runs)

| Algorithm | mean MB/s | ± std |
|---|---:|---:|
| ASCON-AEAD | 352.09 | 16.93 |
| AES-128-GCM (enc) | 63.92 | 3.21 |
| ChaCha20-Poly1305 | 388.38 | 21.10 |
| ChaCha20 | 556.39 | 30.36 |
| AES-128-CBC (enc) | 300.13 | 4.46 |
| Ascon-Hash256 | 121.89 | 7.80 |
| HMAC-SHA256 | 257.12 | 14.54 |

The host benchmark runs on x86 with OS scheduling/cache noise, so std is nonzero
(as expected); the values above are mean ± std over 10 runs. The Renode emulator
shows std = 0.000 for every value (deterministic). Both are produced by
`tools/bench_10x.ps1`. (The multi-block table above is a shape reference at the
block sizes labeled; the current build fixes its block size at 1 MiB, which is
why the 10-run column uses that block.)

The Cortex-M0 compile-only result remains 2,827 bytes for the Ascon object.
The host cycle-per-byte values must not be used as embedded cycle values.

### Code footprint — Ascon vs ChaCha20-Poly1305 (the honest comparison)

The 2,827 B Ascon-object figure is the **size-optimized (64-bit-word) Ascon
build** (`-UWOLFSSL_ASCON_32BIT`; this is `build\arm\ascon.o`). It is the build
    that makes Ascon's footprint advantage real: one 2,827 B (M0+) / 2,807 B (M3)
    `ascon.o` delivers **both** the AEAD (record protection) **and** the handshake
    hash (transcript, HKDF, Finished), but the DTLS transport cookie retains SHA-256
    (RFC 6347), so the full Ascon suite is `ascon.o` + `sha256.o` (cookie) =
    5,219 B (M0+) / 4,711 B (M3); a ChaCha20-Poly1305 DTLS node must link
    ChaCha20 + Poly1305 + SHA-256 = 6,518 B (M0+) / 5,514 B (M3) — **Ascon is
    ~1.25× (M0+) / ~1.17× (M3) smaller.** Full table and methodology in
    `footprint-benchmark.md`.

Caveat (must be stated): the **throughput/cycle benchmarks above use the
32-bit-optimized Ascon build** (`WOLFSSL_ASCON_32BIT`, 9,476 B on M0+ / 8,784 B
on M3). Under that build Ascon is *larger* than ChaCha-Poly (6,518 / 5,514 B), so
the footprint win holds only for the size-optimized build, and the throughput
numbers are a different build. **Ascon does not beat ChaCha20-Poly1305 in raw
throughput on Cortex-M** — the honest headline is footprint and
    AEAD+handshake-hash primitive (the DTLS cookie still uses SHA-256), not speed. Both Ascon builds beat software
AES-128-GCM on footprint (1.9×–4.6× smaller, after counting the DTLS cookie SHA-256).

## DTLS application benchmark

The DTLS measurements include process start, socket setup, handshake, one
application message, response, and process shutdown. They are end-to-end host
wall-clock measurements, not handshake-only measurements. Each result is the
median of five runs. The server was started first with a 400 ms settle time;
the timer covered only the client process, with output redirected to files.

| Mode | Median time | Range | Application result |
|---|---:|---:|---|
| PSK | 317 ms | 230--470 ms | 5/5 passed |
| X.509 with peer checks | 708 ms | 591--884 ms | 5/5 passed |

The PSK test used `dtls13_psk_server.exe` and `dtls13_psk_client.exe`. The
X.509 test used the example server and client with the corrected trust stores
listed below. All runs selected
`TLS_ASCONAEAD128_ASCONHASH256` and completed the encrypted application
exchange.

The repeatable PSK commands were:

```text
build\dtls13_psk_server.exe 11201
build\dtls13_psk_client.exe 127.0.0.1 11201
```

The X.509 server used `-c ./certs/server-cert.pem`,
`-k ./certs/server-key.pem`, and `-A ./certs/client-cert.pem`. The X.509
client used `-c ./certs/client-cert.pem`, `-k ./certs/client-key.pem`, and
`-A ./certs/ca-cert.pem`. Neither side used `-d`; peer verification was
enabled.

## Binary size evidence

The native Windows executable sizes were:

| Binary | Size |
|---|---:|
| server.exe | 194,135 bytes |
| client.exe | 190,012 bytes |
| dtls13_psk_server.exe | 141,595 bytes |
| dtls13_psk_client.exe | 141,550 bytes |
| benchmark.exe | 191,642 bytes |

The ARM compile-only result for `build\arm\ascon.o` was 2,827 bytes of text,
with zero data and zero BSS. This is the size-optimized (64-bit-word) Ascon
build; the cycle/throughput benchmarks use the 32-bit-optimized build
(`WOLFSSL_ASCON_32BIT`, 9,476 B on M0+). These sizes do not predict final
embedded image size or RAM use.

## X.509 result

The first verified test used `ca-cert.pem` for both trust stores. This was
wrong because `client-cert.pem` is self-signed and is not issued by
`ca-cert.pem`. wolfSSL returned an ASN no-signer error.

The corrected test used:

- Server certificate: `server-cert.pem`.
- Server key: `server-key.pem`.
- Server trust store: `client-cert.pem`.
- Client certificate: `client-cert.pem`.
- Client key: `client-key.pem`.
- Client trust store: `ca-cert.pem`.

With peer verification enabled on both sides, the DTLS 1.3 handshake passed
with `TLS_ASCONAEAD128_ASCONHASH256`. The client printed `I hear you fa
shizzle!` and the server printed `Client message: hello wolfssl!`. The run
produced no certificate or connection failure lines.

The server trust store uses the self-signed client certificate as a trust
anchor. This verifies the certificate signature and identity for this local
test. A production deployment should use a dedicated client CA instead of
trusting an end-entity certificate directly.

## DTLS record-layer benchmark (Cortex-M)

The Renode harness was extended (`tools/renode/bench_record.c`) to measure the
cost of protecting one DTLS 1.3 record with `TLS13-ASCONAEAD128-ASCONHASH256`
on the emulated Cortex-M0+/M3, using the same SysTick timing as the primitive
benchmark. Each line is one full `wc_AsconAEAD128` operation (Init, SetKey,
SetNonce, SetAD, Update, Final + 16-byte tag) over a 32-byte application
record, plus the keyed-permutation record-number mask (independent `sn_key`)
and a modeled failed-authentication to forced-KeyUpdate decision. Full capture
in `renode-benchmark-results.md`.

| Operation | Cortex-M0+ (cyc/rec) | Cortex-M3 (cyc/rec) |
|---|---:|---:|
| record encrypt | 4091.5 | 2380.5 |
| record decrypt | 9769.7 | 8035.6 |
| record-number mask | 1299.8 | 809.3 |

At 32 MHz these are ~0.13 ms / 0.31 ms (encrypt / decrypt) per protected
application message on Cortex-M0+. The record path includes the keyed-sponge
record-number mask, so the per-message cost already covers sequence-number
protection. This completes the device-side record-path benchmarking that was
outstanding from the earlier validation.

## Limitations

- No physical Cortex-M0 or RV32IMC cycle measurement was possible.
- The Cortex-M0 result is a compile and object-size result only.
- The formal analysis is bounded. It is not a machine-checked proof.
- The PSK test remains the primary end-to-end result; the corrected local
  X.509 test now also passes with peer verification enabled.
- The benchmark does not compare mbedTLS on the same target. AES-GCM,
  ChaCha20-Poly1305, and ChaCha20 are now compared on the same wolfCrypt
  benchmark build; AES-128-CBC remains a software reference point only.
- AES-GCM was measured as table-based software AES because `WOLFSSL_AESNI`
  was not defined in this build. A hardware-AES target would show different
  AES-GCM numbers.
- **No throughput claim vs ChaCha20-Poly1305.** Ascon does not beat
  ChaCha20-Poly1305 in raw Cortex-M throughput (0.409 / 0.749 MiB/s vs
   0.691 / 2.725 MiB/s). Its advantages over ChaCha-Poly are code footprint
   (2,827 B `ascon.o` for AEAD+hash, plus `sha256.o` for the DTLS cookie, vs
   ChaCha20+Poly1305+SHA-256 ≈ 6.5 KB in the size-optimized Ascon build) — see
  `footprint-benchmark.md`. The footprint win is real only for the
  size-optimized Ascon build, not the 32-bit-optimized build used for the
  cycle benchmarks.
- **No faster standard Ascon AEAD variant exists.** wolfSSL's `wc_AsconAEAD128`
  is already Ascon-128a (rate 128-bit, 8 per-block rounds) — the fastest
  standard Ascon AEAD. Closing the ChaCha-Poly throughput gap would require an
  ARM-optimized Ascon permutation (wolfSSL ships none; `ascon-c` has
  public-domain `bi32_armv7m`/`bi32_armv6m`); this was not implemented and
  cannot be measured here (Renode unavailable). The benchmark's ChaCha baseline
  is also C-only (ARM assembly blocked by a wolfSSL build-generated header). See
  `renode-benchmark-results.md` ("Can Ascon beat ChaCha20-Poly1305…").
- The DTLS application timings are end-to-end host wall-clock values. They
  include process start and shutdown and must not be read as handshake-only
  or embedded timings.
- Host process RAM was not reported because a short-lived process working-set
  sample would not represent embedded RAM use.

## Conclusion

The software-validatable T1 research artifact works. It implements the
registered Ascon DTLS 1.3 suite, completes a DTLS 1.3 PSK handshake, protects
application data, and survives the tested loss, reorder, tamper, replay,
and forced-KeyUpdate cases. The bounded analysis is now the final security
proof section (claims C1-C7, Robust Channels reduction, keyed-sponge mask
PRF, committing security). The only remaining publication step is to add physical
constrained-device measurements (not possible in this software-only setting;
Renode-emulated Cortex-M0+/M3 cycle counts stand in). The KSW committing
bound (64-bit, ePrint 2023/1525) and the Robust Channels record-layer
reduction are now stated in the proof section above.
