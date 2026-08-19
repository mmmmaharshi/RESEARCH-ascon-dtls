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
| Cortex-M0 Ascon object size | 2,827 bytes |
| Cortex-M0 cycle test | Run in Renode (Cortex-M0+ @32MHz): ASCON-AEAD128 0.338 MiB/s vs AES-128-GCM 0.071 MiB/s (~4.8× faster). See `renode-benchmark-results.md`. |
| Cortex-M3 cycle test | Run in Renode (Cortex-M3 @32MHz): ASCON-AEAD128 0.585 MiB/s vs AES-128-GCM 0.166 MiB/s (~3.5× faster); ChaCha20-Poly1305 2.725 MiB/s (~16× faster than AES-GCM). See `renode-benchmark-results.md`. |
| X.509 mode with peer verification enabled | PASS |

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

## Bounded security analysis

The record-layer claim has the following scope.

Assume:

1. Ascon-AEAD128 has its stated confidentiality and integrity bounds.
2. Each traffic key has unique nonces.
3. DTLS sequence numbers do not repeat in one epoch.
4. The DTLS anti-replay window works as specified.
5. HMAC-Ascon-Hash256 has the normal HMAC security reduction when the hash
   acts as a suitable keyed-hash construction.
6. The record-number mask uses an independent `sn_key`.

Under these assumptions:

- A forged record is accepted only if the Ascon tag is forged or the record
  state machine is violated.
- The record-number mask does not reveal the sequence number to an observer
  without `sn_key` because the mask depends on the ciphertext prefix.
- A fixed record-number mask is not acceptable because it reveals a counter.
- The mask key is separate from the traffic key. Therefore, the mask does not
  add a second input path to the Ascon AEAD security argument.
- The protocol limits of 2^48 records and 2^48 failed authentications bind
  before the estimated Ascon construction limits.
- The analysis does not prove a new AEAD mode. It applies existing AEAD
  bounds to the DTLS state machine and gives a bounded PRF argument for the
  record-number mask.

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

The output reported a one-second minimum for each measurement. Each row below
is the median of three runs. All values were re-measured on the final build,
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

The hash and HMAC matrix also used three runs and median values:

| Block size | Ascon-Hash256 MB/s | HMAC-SHA256 MB/s |
|---:|---:|---:|
| 64 | 102.284048 | 206.649752 |
| 256 | 115.604356 | 198.888199 |
| 1024 | 118.991555 | 193.649362 |
| 16384 | 119.046467 | 213.605589 |

The Cortex-M0 compile-only result remains 2,827 bytes for the Ascon object.
The host cycle-per-byte values must not be used as embedded cycle values.

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
with zero data and zero BSS. These sizes do not predict final embedded image
size or RAM use.

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

## Limitations

- No physical Cortex-M0 or RV32IMC cycle measurement was possible.
- The Cortex-M0 result is a compile and object-size result only.
- The formal analysis is bounded. It is not a machine-checked proof.
- The exact KSW committing theorem value must be quoted from the source paper
  before publication.
- The PSK test remains the primary end-to-end result; the corrected local
  X.509 test now also passes with peer verification enabled.
- The benchmark does not compare mbedTLS on the same target. AES-GCM,
  ChaCha20-Poly1305, and ChaCha20 are now compared on the same wolfCrypt
  benchmark build; AES-128-CBC remains a software reference point only.
- AES-GCM was measured as table-based software AES because `WOLFSSL_AESNI`
  was not defined in this build. A hardware-AES target would show different
  AES-GCM numbers.
- The DTLS application timings are end-to-end host wall-clock values. They
  include process start and shutdown and must not be read as handshake-only
  or embedded timings.
- Host process RAM was not reported because a short-lived process working-set
  sample would not represent embedded RAM use.

## Conclusion

The software-validatable T1 research artifact works. It implements the
registered Ascon DTLS 1.3 suite, completes a DTLS 1.3 PSK handshake, protects
application data, and survives the tested loss and reorder cases. The next
publication step is to add physical constrained-device measurements and to
convert the bounded analysis into the final paper proof section.
