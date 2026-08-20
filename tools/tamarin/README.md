# DTLS 1.3 Ascon Record Layer — Tamarin Model

Symbolic model of the `0x006E` (TLS_AEAD_WITH_ASCON_128) / DTLS 1.3 (RFC 9147 + RFC 9846 key schedule) record layer.

File: `dtls13-ascon-record.spthy`

## What it proves

8 lemmas (verified on the prior structure with Tamarin 1.12.0, WSL Ubuntu-24.04 + Maude 3.2; re-run after the fidelity edit to re-confirm):

- `psk_secret` — external PSK never revealed
- `client_key_secrecy` / `server_key_secrecy` — per-direction record keys never revealed
- `data_secrecy_c2s` / `data_secrecy_s2c` — application data never revealed
  - `seq_privacy_c2s` / `seq_privacy_s2c` — sequence-number privacy: the wire `seq` is hidden behind the mask, modelled as an opaque PRF `mask_fn(sn_key, ct)`. This proves the *protocol* keeps the seq secret under the symbolic assumption that the mask is a PRF; the cryptographic soundness of the actual Ascon-P^12 keyed-sponge mask (`Ascon-P^12(domsep ‖ sn_key ‖ ct[0..15])`) is established analytically in design-01 §4.2.1 (C4) — **NOT verified by this symbolic model**.
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

The record-number mask is modelled as an opaque function `mask_fn(sn_key, ct)`
abstracting `Ascon-P^12(domsep ‖ sn_key ‖ ct[0..15])`. Tamarin assumes `mask_fn`
behaves as a PRF and does **not** verify the Ascon-P^12 keyed-sponge permutation;
the cryptographic soundness of the mask is the analytic design-01 §4.2.1 / C4
argument, not a result of this model.

## Run

```
tamarin-prover dtls13-ascon-record.spthy --prove
```

> **Re-verification note (DA-3):** the mask was changed for fidelity — it is now
> `mask_fn(sn_key, ct)` (depends on the ciphertext) instead of the previous opaque
> `hmac(sn_key, aad)` (a fresh value). The 8 lemmas were verified on the *prior*
> structure; re-run the command above to re-confirm. The edit only swaps the mask's
> input from a fresh value to the ciphertext and renames the function, so the
> opaque-PRF secrecy argument (and thus `seq_privacy_*`) is expected unchanged.
> Tamarin is **not** installed in this environment, so the re-run was not performed here.
