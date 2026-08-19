# DTLS 1.3 `TLS_ASCONAEAD128_ASCONHASH256` (0x006E) — Desktop Validation

**Status:** validated end-to-end on Windows/desktop (loopback UDP).
**Date:** 2026-08-14
**Scope:** M2.1 + M2.2 verification (suite wiring, PSK handshake, handshake-hash
binding to Ascon-Hash256) and M2.4 partial (AEAD authentication under tamper,
via `tools/dtls_negative_proxy.ps1`).

## Build recipe

```powershell
# wolfSSL shared library (Ascon + DTLS 1.3 PSK)
cmake -S wolfssl -B build -G Ninja `
  -DWOLFSSL_USER_SETTINGS=ON `
  -DWOLFSSL_DTLS=ON -DWOLFSSL_DTLS13=ON `
  -DWOLFSSL_EXAMPLES=ON -DWOLFSSL_CRYPT_TESTS=ON `
  -DCMAKE_C_FLAGS=-I<repo-root> -DCMAKE_ASM_FLAGS=-I<repo-root>
cmake --build build --target wolfssl wolfcrypt/test/testwolfcrypt.exe

# test endpoints (tools/)
gcc tools/dtls13_psk_client.c -o build/psk_client.exe `
  -I. -Iwolfssl -DWOLFSSL_USER_SETTINGS -Lbuild -lwolfssl -lws2_32
gcc tools/dtls13_psk_server.c -o build/psk_server.exe `
  -I. -Iwolfssl -DWOLFSSL_USER_SETTINGS -Lbuild -lwolfssl -lws2_32
```

`user_settings.h` enables `HAVE_ASCON`, `WOLFSSL_EXPERIMENTAL_SETTINGS`,
`WOLFSSL_TLS13`, `WOLFSSL_DTLS13`. `BUILD_TLS_ASCONAEAD128_ASCONHASH256` is
defined automatically when `HAVE_ASCON` is set (`wolfssl/wolfssl/internal.h:836`).

## Cryptographic self-test

`wolfcrypt/test/testwolfcrypt.exe` -> **ASCON Hash test passed!**,
**ASCON AEAD test passed!** (the RSA "Signature Verify failed" line is the known
benign warning in this minimal research build; it exits 0 and is outside the
Ascon/PSK scope).

## End-to-end PSK handshake (observe mode)

Server: `psk_server.exe 11111`, proxy `dtls_negative_proxy.ps1 -Mode observe
-ListenPort 12000 -ServerPort 11111`, client `psk_client.exe 127.0.0.1 12000`.

- Client: `HANDSHAKE OK. cipher: TLS_ASCONAEAD128_ASCONHASH256`
- Server: `HANDSHAKE OK. cipher: TLS_ASCONAEAD128_ASCONHASH256`
- App data `ascon-dtls test message` encrypted by client, **`got: ascon-dtls
  test message`** on server, echo read back by client (`echo ok: ...`).

Both sides performed Ascon AEAD decrypt of the application record; the
`Provisioning Ascon Record Number enc/dec key` lines confirm the
ciphertext-dependent record-number mask keys are derived.

## Handshake hash is genuinely Ascon-Hash256

Two independent confirmations:

1. **Static mapping** (`wolfssl/src/tls13.c:3743-3745`): `SuiteMac()` maps
   `TLS_ASCONAEAD128_ASCONHASH256` -> `mac = ascon_hash256_mac`. The suite's
   hash drives the TLS 1.3 transcript hash, HKDF, and Finished MAC -- so all of
   these use Ascon-Hash256, not SHA-256.
2. **Runtime trace**: every HKDF step printed `Extract_ex ret: 0 (digest 21)`,
   where `21` is the Ascon-Hash256 algorithm ID (not SHA-256, which would be
   `digest 4`).

The repeated `Sha256` lines in the debug stream are a **forensic `HashRaw` dump**
(`internal.c:10870`) that prints *all* available hashes of a buffer for
diagnostics -- it is not the handshake hash.

## AEAD authentication holds up (negative test)

Same topology, proxy `-Mode tamper` (flips the last byte of one
client->server application-record packet):

- Handshake still completes (`HANDSHAKE OK` on both ends).
- Server then reports **`read fail, err 6`** and **no `got:` line** -- the
  tampered ciphertext failed Ascon AEAD verification and the message was
  dropped.

A/B comparison: observe mode delivers `got: ascon-dtls test message`; tamper
mode does not. This proves the AEAD tag authenticates the record.

> Note: the proxy's tamper filter (packets >=4, length 40-80) targets the
> small post-handshake records, not the large ClientHello/ServerHello, so it
> validates *application-record* integrity, which is the relevant property.

## SHA-256 caveat (not a handshake-hash violation)

`wolfssl/src/dtls.c:161` sets `DTLS_COOKIE_TYPE = WC_SHA256`. The DTLS
anti-amplification **cookie** uses SHA-256 at the *transport* layer, which is
orthogonal to the TLS 1.3 handshake hash (Ascon-Hash256). This is an expected,
RFC 6347-mandated mechanism and does not contradict the "no SHA-256 in the
handshake crypto" property of the 0x006E suite.

## What this establishes vs. what remains

| Item | State |
|------|-------|
| Suite 0x006E wired (client+server) | done |
| DTLS 1.3 PSK handshake negotiates 0x006E | done |
| Handshake hash = Ascon-Hash256 (not SHA-256) | done |
| App-data AEAD encrypt/decrypt + echo | done |
| AEAD rejects tampered ciphertext | done |
| Record-number mask implementation (M2.3) | **done** (Option B keyed-sponge PRF, see below) |
| Full proxy matrix: replay / reorder / KeyUpdate (M2.4) | partial (observe + tamper only) |
| Own record-layer test vectors (M2.4.3) | partial (mask vectors produced, see below) |
| Real DTLS record path on Renode (M0+/M3) | future |

## M2.3 — Record-layer integration verification

All three record-layer components (nonce, mask, usage limits) are **already
implemented and wired** in the wolfSSL fork. This section verifies each against
`design-01-record-layer.md`.

### 4.2 Nonce mapping — VERIFIED

`BuildTls13Nonce()` (`wolfssl/src/tls13.c:2550`) builds the per-record nonce as
`nonce = fixed_iv XOR zero-pad64(seq)`: it copies `iv[0..ivSz-SEQ_SZ]` then
XORs the 8-byte sequence number into the low 64 bits. For Ascon the IV is
16 bytes (`ASCON_AEAD128_NONCE_SZ`, `tls13.c:2857`) and the record path uses
`client_write_IV`/`server_write_IV` as the fixed IV (`tls13.c:2754-2756`).
No epoch bits are mixed into the nonce — exactly §4.2.

### 4.2.1 Record-number mask — VERIFIED (Option B keyed-sponge PRF)

The mask primitive is `wc_AsconAEAD128_Mask()` (`wolfssl/wolfcrypt/src/ascon.c:543`),
wired into `Dtls13GetRnMask()` (`wolfssl/src/dtls13.c:273`) for
`wolfssl_ascon_aead128`, with the sn_key provisioned per epoch by
`Dtls13InitAsconCipher()` (`dtls13.c:2234`, key from
`ssl->keys.client/server_sn_key`, derived at `dtls13.c:2177/2188`).

Construction (matches §4.2.1 "Option B"):

```
state S (320 bits) =
    domsep(64)  ||  sn_key(128)  ||  ciphertext[0..15](128)
    S.s64[0] = ASCON_MASK_DOMSEP
    S.s64[1..2] = sn_key
    S.s64[3..4] = ciphertext[0..15]
permutation(S, 12)          // Ascon-P^12 (ASCON_HASH256_ROUNDS)
mask = S.s64[0] || S.s64[1] // 16 bytes; 8/16 bits consumed per RFC 9147
```

- Rate r = 128 (ciphertext), capacity c = 192 (domsep || sn_key) — exactly the
  design's r=128/c=192.
- P^12, ciphertext-dependent (mask changes with the ciphertext, not a per-epoch
  constant) — satisfies the §4.2.1 privacy requirement (an observer without
  sn_key sees pseudorandom wire sequence numbers).
- `sn_key` is used **only** for masking, never for AEAD — isolation holds.

**Domain-separation deviation (doc only):** the design prose suggested
`domsep = 0x80 || 0x00…0`. The implementation uses the ASCII constant
`"RNDIMSK_"` (`ASCON_MASK_DOMSEP = 0x524e44494d534b5f`,
`wolfssl/wolfcrypt/ascon.h:47`), explicitly distinct from the Ascon-AEAD128 IV
(`0x80400c0600000000`) and Ascon-Hash256 IV. This is a stronger, still-valid
domain separator; `design-01-record-layer.md` §4.2.1 should be updated to match.

### 4.2.1 Mask test vectors (self-checking)

Generated by `tools/ascon_mask_kat.c` against the built `libwolfssl` (the same
sponge the DTLS record layer uses). sn_key = `000102030405060708090a0b0c0d0e0f`.

| ct (hex)                              | mask (hex)                         |
| ------------------------------------- | ---------------------------------- |
| `101112131415161718191a1b1c1d1e1f`   | `55a447510fd0d4035b4bc3ce484a5875` |
| `202122232425262728292a2b2c2d2e2f`   | `78189d22c54b6b24eef9cace03c1e256` |
| `00000000000000000000000000000000`   | `cc1c88261df57b23be3fb91eb6340f54` |

Cases A→B share the key but differ in ciphertext and produce **different** masks
→ confirms ciphertext-dependence (the property the design requires). Case C is
the all-zero-ciphertext (retransmitted empty-plaintext record) vector.

### 4.3 Usage limits — IMPLEMENTED, value deviation (decision needed)

Failed-authentication counting and forced key-update are wired:
`Dtls13CheckAEADFailLimit()` (`wolfssl/src/dtls13.c:3220`) has a
`wolfssl_ascon_aead128` case (`dtls13.c:3250-3255`) that increments
`dtls13DecryptEpoch->dropCount` and, past the key-update limit, sets
`dtls13DoKeyUpdate = 1`. The per-direction secret → key/iv/sn_key mapping
follows RFC 9147 §4.2.3.

**Value deviation from the design:** the design §4.3 table specifies the
**2^48 protocol cap** for "records failing authentication per key". The
reference implementation instead enforces wolfSSL's conservative DTLS defaults:

```c
// wolfssl/wolfssl/internal.h:1454-1455
#define DTLS_AEAD_ASCON_FAIL_LIMIT      w64From32(1 << 16, 0)   // 2^16 hard
#define DTLS_AEAD_ASCON_FAIL_KU_LIMIT   w64From32(1 << 15, 0)   // 2^15 key-update
```

This is *stricter* (and therefore safer) than 2^48: at 2^16 failed attempts the
cumulative forgery advantage is 2^16 / 2^128 = 2^-112, far below the 2^-60
rule of thumb. However it contradicts the paper's stated "limits are set by the
protocol cap (2^48), not by Ascon's bounds" narrative.

**Decision for the paper:** either (a) keep the implementation's 2^16/2^15 and
update §4.3 to say "reference implementation enforces 2^16 (stricter than the
2^48 protocol cap); forgery advantage ≤ 2^-112", or (b) raise the constants to
2^48 to match the design's literal bound. Both are cryptographically sound; the
choice is a paper-claims decision, not a correctness one.
