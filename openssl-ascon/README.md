# OpenSSL 3.6.3 ASCON-128/ASCON-HASH256 patch (cross-stack interop evidence)

This directory captures the OpenSSL modifications that enabled a successful
TLS 1.3 handshake with suite **0x006E** (`TLS_ASCON_AEAD128_ASCON_HASH256`)
against the wolfSSL fork in this repository (see `dtls13-ascon-validation.md`
§11.1). It is **evidence, not a maintained fork**: files are exact copies of
the working tree at `<scratch>\openssl-3.6.3` (a scratch checkout, not a git
repo), minus build artifacts.

## Patch surface (vs. stock openssl-3.6.3)

New files (copied verbatim into this directory):

| Upstream path | Here |
|---|---|
| `providers/implementations/ciphers/cipher_ascon128.c` | `providers/implementations/ciphers/` |
| `providers/implementations/digests/digest_ascon_hash256.c` | `providers/implementations/digests/` |
| `providers/implementations/include/prov/ascon_local.h` | `providers/implementations/include/prov/` |
| `ascon_psk_client.c` (interop client, this repo's tool) | `./` |

`ascon_local.h` is the shared core (port of the wolfSSL Ascon commit `9fd500a`,
byte-exact; ASCON-128 rate 16 / 12+8 rounds, ASCON-HASH256 rate 8 / 12 rounds).
`cipher_ascon128.c` wraps it as an EVP cipher (`ASCON-128`, key/iv/tag = 16,
block size 1); `digest_ascon_hash256.c` wraps it as `ASCON-HASH256`. Both are
registered into the `default` provider (`openssl list -cipher-algorithms` →
`ASCON-128 @ default`).

Edited stock files (line numbers refer to the working tree; content shown at
commit time — grep these markers to locate):

- `ssl/ssl_local.h`
  - `#define SSL_ASCON128 0x01000000U` (line 154, enc bit)
  - `#define SSL_MD_ASCON_HASH256_IDX 14`, `SSL_MAX_DIGEST 15` (lines 202-203)
  - `#define SSL_HANDSHAKE_MAC_ASCON_HASH256 SSL_MD_ASCON_HASH256_IDX` (line 217)
  - `#define SSL_ENC_ASCON_IDX 24` (line 357)
  - pseudo-NIDs: `NID_ASCON_AEAD128 20001`, `NID_ASCON_HASH256 20002`
    (lines 366-367, `#ifndef OPENSSL_NO_ASCON` block; the cipher/digest are
    fetched by name, not by OBJ_nid2sn — see comment at line 364)
- `ssl/s3_lib.c` — `ssl3_ciphers[]` entry (lines 131-148): suite
  `TLS1_3_RFC_ASCONAEAD128_ASCONHASH256` (0x006E), `SSL_kANY/SSL_aANY`,
  `SSL_ASCON128`, `SSL_AEAD`, `TLS1_3_VERSION` min/max,
  `SSL_NOT_DEFAULT | SSL_HIGH`, `SSL_HANDSHAKE_MAC_ASCON_HASH256`, strength 128.
- `ssl/ssl_ciph.c`
  - `ssl_cipher_table_enc`: `{ SSL_ASCON128, NID_ASCON_AEAD128 }` (line 65)
  - `ssl_cipher_table_mac`: `{ 0, NID_ASCON_HASH256 }` (line 84)
  - `ssl_cipher_strength_sort` tag-size branch: `out = 16` for `SSL_ASCON128`
    (lines 2181-2182)
- `ssl/ssl_lib.c` — `ssl_load_ciphers()`: `EVP_CIPHER_fetch(libctx, "ASCON-128")`
  when `nid == NID_ASCON_AEAD128` (lines 7473-7474); `EVP_MD_fetch(libctx,
  "ASCON-HASH256")` when `nid == NID_ASCON_HASH256` (lines 7534-7535).

## Known bug fixed inside the patch (keep it)

`ascon_aead128_reset()` originally did **not** clear the `adPart[]`/`ct[]`
scratch buffers. The AAD finalizer pads with XOR (`adPart[adPartSz] ^= 0x01`),
so a stale `0x01` left by the previous record at the same index cancelled the
new record's pad (`0x01 ^ 0x01 == 0x00`) → corrupted tag → `bad_record_mac`
for every record after the first within a key epoch. The current
`ascon_local.h` memsets both buffers in the reset. Do not "simplify" this away.

## How it was built and run

```powershell
# <scratch> = any writable working directory of your choice; all paths are examples.
# build (msys2 bash; mingw32-make needs sh.exe):
C:\msys64\usr\bin\bash.exe -lc "cd /c/<scratch>/openssl-3.6.3 && export PATH=/usr/bin:/ucrt64/bin:`$PATH && make -j8"
# NOTE: provider objects do NOT rebuild on header change (dep untracked).
# Force: delete providers/implementations/{ciphers,digests}/libdefault-lib-*ascon*.obj
# then re-run make, then verify libcrypto.a timestamp changed.

# client (relink against rebuilt libcrypto.a/libssl.a):
gcc ascon_psk_client.c -I <tree>/include <tree>/libssl.a <tree>/libcrypto.a -lws2_32 -lcrypt32 -o ascon_psk_client.exe

# server (this repo, single connection, port 11111):
Start-Process tools\tls13_psk_server.exe -ArgumentList 11111 -WorkingDirectory tools -RedirectStandardOutput <scratch>\wolfD_srv.out -RedirectStandardError <scratch>\wolfD_srv.err -PassThru

# client (CWD must be <scratch>):
ascon_psk_client.exe 127.0.0.1 11111 0123456789abcdef1133557799bbddff21436587a9cbed0f31537597b9dbfd1f Client_identity
```

## Evidence

`evidence/client_final_run.txt` — full client transcript (msg_cb wire sizes,
KEYLOG lines, `connected: TLSv1.3 / TLS_ASCON_AEAD128_ASCON_HASH256`,
`sent:`/`echo (20 bytes): Hello Ascon TLS1.3!`).
`evidence/openssl_interop_srv.out` — server stdout of the same run
(`HANDSHAKE OK. cipher: TLS_ASCONAEAD128_ASCONHASH256`, `got: Hello Ascon
TLS1.3!`).

Keylog cross-check: the client's `SERVER_HANDSHAKE_TRAFFIC_SECRET` equals the
server's derived `s hs traffic` OKM; all ES/derived/HS/transcript values
match between stacks (see §11.1 of the validation doc).