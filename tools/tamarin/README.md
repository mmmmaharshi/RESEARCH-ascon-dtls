# DTLS 1.3 Ascon Record Layer — Tamarin Model

Symbolic model of the `0x006E` (TLS_AEAD_WITH_ASCON_128) / DTLS 1.3 (RFC 9147 + RFC 9846 key schedule) record layer.

File: `dtls13-ascon-record.spthy`

## What it proves

8 lemmas, all verified with Tamarin 1.12.0 (WSL Ubuntu-24.04, Maude 3.2):

- `psk_secret` — external PSK never revealed
- `client_key_secrecy` / `server_key_secrecy` — per-direction record keys never revealed
- `data_secrecy_c2s` / `data_secrecy_s2c` — application data never revealed
- `seq_privacy_c2s` / `seq_privacy_s2c` — **the Ascon masked-sequence-number contribution**: wire `seq` is hidden behind `hmac(sn_key, aad)`, so an observer without `sn_key` learns nothing about the sequence number
- `keyupdate_reachable` — the forced-KeyUpdate (robust channels) rotation is reachable

## Scope

Secrecy + sequence-number privacy only. Authentication/integrity of records is
established by the companion game-hop proof (`robust-channels-game-hop.md`),
consistent with `design-01-record-layer.md:129`: pure Tamarin multiset-rewrite
rules cannot express the MAC tag check (no `if`-guard in rule grammar without
SAPIC / Maude equational theories), so the forgery/authentication property is
left to the analytic proof rather than duplicated here.

Keys are modelled as fresh secrets established by an abstracted handshake
(Setup rule); the HKDF chaining is covered analytically by `M2-bounded-security-claim.md`.

## Run

```
tamarin-prover dtls13-ascon-record.spthy --prove
```
