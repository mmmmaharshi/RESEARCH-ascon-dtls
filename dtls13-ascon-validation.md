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
| Record-number mask implementation (M2.3) | pending (not yet implemented) |
| Full proxy matrix: replay / reorder / KeyUpdate (M2.4) | partial (observe + tamper only) |
| Own record-layer test vectors (M2.4.3) | pending (needs mask, M2.3) |
| Real DTLS record path on Renode (M0+/M3) | future |
