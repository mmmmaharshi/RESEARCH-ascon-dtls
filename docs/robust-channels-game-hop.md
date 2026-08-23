# Ascon-specific Game-Hop Reduction for C3 (Robust Channels / ROB-INT-IND-CCA)

## Scope

This appendix writes the **Ascon-specific** hops of the Robust Channels
channel-security reduction. The generic DTLS 1.3 channel decomposition
(packet loss, reordering, replay-within-window, sliding window →
ROB-INT-IND-CCA) is **not re-derived here**; it is Fischlin–Günther–Janson
[FGJ20, Thms 7.1 & 7.2 via Prop. 5.9, §7] (ePrint 2020/718; Journal of
Cryptology 2024). We write only the hops that depend on the concrete AEAD
(Ascon-AEAD128) — the reduction from the real channel game to the
AEAD-real-or-random game. This makes the argument self-contained without
overclaiming a new theorem.

## Setup / notation

- `Ch_Ascon` = our record layer: DTLS 1.3 with
  `TLS_ASCONAEAD128_ASCONHASH256` (IANA 0x006E), plus the record-number mask
  (design-01 §4.2.1, disjoint key `sn_key`) and the failed-authentication →
  KeyUpdate mechanism (RFC 9846 §4.7.3), enforced at `q_R = 2^16`
  decryption/forgery attempts per key.
- `Æ` = an ideal AEAD (IND$-CPA + INT-CTXT) oracle.
- `Adv^{ROB-INT-IND-CCA}_A(Ch)` = A's advantage in the ROB-INT-IND-CCA game on
  `Ch_Ascon`.

## Game sequence

- **G0** — Real game. Challenger runs `Ch_Ascon` with Ascon-AEAD128 (real
  P^12 permutation) for Encrypt/Decrypt, real mask PRF for record numbers, and
  enforces `q_R` failed decryptions → key update. Adversary A plays
  ROB-INT-IND-CCA.
- **G1** — Same game, but the Ascon-AEAD128 Encrypt/Decrypt oracles are
  replaced by `Æ`. The mask remains real; by design-01 §4.2.1 it is a
  disjoint-key keyed-sponge PRF whose key never enters the AEAD and whose
  output never feeds AEAD decryption, so it contributes **no cross-term** to
  the channel bound (precondition (c) of M2 §5.2).

### Hop 1 — confidentiality (G0 → G1)

Build a reduction `B_cca` that forwards A's encryption queries 1:1 to its own
IND$-CPA challenger for the AEAD, and answers A's decryption queries using the
AEAD's decryption (reject on tag failure). By Ascon-AEAD128's IND$-CPA
security (C1, SP 800-232):

    |Pr[G0 ⇒ 1] − Pr[G1 ⇒ 1]| ≤ Adv^{IND-CPA}_AEAD(B_cca).

The query count is preserved 1:1, so there is **no multi-query loss** on the
confidentiality side.

### Hop 2 — integrity / forgery (the non-tight part)

For the decryption/forgery queries, build `B_int` forwarding each decryption
query to an INT-CTXT challenger. A can make at most `q_R` decryption queries
that reach a fixed AEAD key (bounded by the failed-auth → KeyUpdate limit).
This is the multi-query INT-CTXT case; we hybrid over the `q_R` decryption
queries:

- `G1.0` = G1 (all `q_R` decryption queries answered by one real AEAD
  decryption oracle).
- For j = 1 … q_R: `G1.j` answers the j-th decryption query with a *fresh*
  single-use INT-CTXT instance that rejects any ciphertext produced by an
  earlier instance.
- Each hybrid step is bounded by single-query INT-CTXT security:

      |Pr[G1.(j-1) ⇒ 1] − Pr[G1.j ⇒ 1]| ≤ Adv^{INT-CTXT}_AEAD(1).

- Summing over `q_R` steps:

      Adv^{ROB-INT}_A(Ch) − Adv^{INT-CTXT}_AEAD(q_R) ≤ q_R · Adv^{INT-CTXT}_AEAD(1).

This `q_R` factor is the **non-tight linear robustness degradation** [FGJ20]
identified; it is exactly why C3 is NOT bounded by C1/C2 alone.

## Combination (Proposition 5.9, [FGJ20])

    Adv^{ROB-INT-IND-CCA}_A(Ch) ≤ Adv^{ROB-INT}_A(Ch) + Adv^{IND-CPA}_A(Ch)
                                ≤ Adv^{INT-CTXT}_AEAD(q_R) + Adv^{IND-CPA}_AEAD.

## Plug-in: Ascon bounds (C1/C2, SP 800-232)

- Confidentiality: `Adv^{IND-CPA}_AEAD ≤ 2^-92` (C1, 2^54-byte NIST SP 800-232 cap).
- Integrity: with enforced `q_R = 2^16` and single-query forgery probability
  `≤ 2^-128` (128-bit Ascon tag),

      q_R · Adv^{INT-CTXT}_AEAD(1) ≤ 2^16 · 2^-128 = 2^-112.

  This equals the enforced C2 figure (`≤ 2^-112`), confirming the two
  framings agree. (The protocol cap `q_R ≤ 2^48` would give `≤ 2^-80`.)
- **Total:** `Adv^{ROB-INT-IND-CCA}_A(Ch) ≤ 2^-92 + 2^-112`.

## Note on q_R binding

The failed-authentication → KeyUpdate mechanism (RFC 9846 §4.7.3, enforced at
`2^16`) is what *binds* `q_R` to `2^16` rather than the protocol maximum
`2^48`. Removing it would let `q_R → 2^48` and weaken the integrity term to
`2^-80`; the mechanism is therefore load-bearing for the bound, not
incidental.

## Mechanization status (honest)

The **arithmetic core** of this game-hop is now machine-checked in
`formal/coq/robust_channels.v` (Rocq/Coq; no `Admitted` — all goals closed).

### What is machine-checked

| Lemma / theorem | Statement | What it proves |
|---|---|---|
| `channel_bound` | `adv_channel ≤ q_R·B_1 + B_conf` | The hybrid sum (Hop 2) composed with Prop. 5.9 (Thms 7.1/7.2): the total channel advantage is bounded by the q_R-fold single-query integrity term plus the confidentiality term. Arithmetic of the composition is fully proven; the game-hops themselves are hypotheses. |
| `concrete_enforced` | `adv_channel ≤ 2^36 + 2^16` (scaled) | The concrete enforced-`q_R=2^16` scenario: `≤ 2^-92 + 2^-112`. Plugs C1 (≤2^36, i.e. 2^-92) and C2 (≤1, i.e. 2^-128) with `q_R=2^16`. |
| `concrete_max` | `adv_channel ≤ 2^36 + 2^48` (scaled) | The protocol-max `q_R=2^48` scenario: `≤ 2^-92 + 2^-80` (no enforced KeyUpdate). |
| `keyupdate_loadbearing` | `2^16 < 2^48` | The forced-KeyUpdate mechanism is load-bearing: it binds `q_R` to `2^16` rather than `2^48`, a difference of `2^32` in the integrity term. |
| `integrity_degradation` | `2^16·1 < 2^48·1` | Removing the mechanism weakens the integrity term from `2^-112` to `2^-80`. |
| `mask_no_crossterm` | `adv_channel ≤ adv_intctxt_qR + adv_indcpa` (mask absent) | The mask's `adv_mask` does **not** appear in the channel bound — precondition (c) (disjoint key, Hop 1) holds, so the mask contributes no cross-term. |
| `channel_security_enforced` | `adv_channel ≤ 2^36 + 2^16` (mask absent) | Summary: full enforced bound `≤ 2^-92 + 2^-112` with the mask contributing zero. |

Re-run (WSL, as for `mask_prf.v`):

```
wsl -u root -e bash -lc 'eval "$(opam env)"; cd /mnt/c/Users/manoh/OneDrive/Desktop/ascon-dtls/formal/coq && coqc robust_channels.v'
```

### Scaling convention (identical to `mask_prf.v`)

All advantages are natural numbers scaled by `2^128`:

| quantity | real-valued bound | scaled (×2^128) |
|---|---|---|
| `Adv^{IND-CPA}_AEAD` (C1) | `≤ 2^-92` | `≤ 2^36` |
| `Adv^{INT-CTXT}_AEAD(1)` (C2) | `≤ 2^-128` | `≤ 1` |
| integrity term, `q_R=2^16` | `2^16·2^-128 = 2^-112` | `2^16·1 = 2^16` |
| integrity term, `q_R=2^48` | `2^48·2^-128 = 2^-80` | `2^48·1 = 2^48` |

### What remains a hand argument (stated as hypotheses in the Coq file)

The three probability-theory steps are **assumptions**, not proven in the
mechanization — exactly as `mask_prf.v` assumes `Hreducible` for the
keyed-sponge reduction. Closing them in full would require an EasyCrypt /
CryptoVerif game-hop mechanization (blocked by toolchain access; see
`mask-prf-proof.md` §7.3):

1. **`Hhybrid`** — the q_R-fold hybrid/telescoping sum:
   `Adv^{INT-CTXT}_AEAD(q_R) ≤ q_R · Adv^{INT-CTXT}_AEAD(1)`.
   This is Hop 2's non-tight linear loss (the q_R factor FGJ20 identify).
2. **`Hchannel`** — Proposition 5.9 + Thms 7.1/7.2 (FGJ20):
   `Adv^{ROB-INT-IND-CCA} ≤ Adv^{INT-CTXT}(q_R) + Adv^{IND-CPA}`.
   This is the generic DTLS 1.3 channel decomposition — *cited, not
   re-derived* (per the scope of this file).
3. **`Hconf` / `Hint1`** — the C1/C2 AEAD bounds (SP 800-232): `Adv^{IND-CPA} ≤ 2^-92`,
   `Adv^{INT-CTXT}(1) ≤ 2^-128`. These are applied, not derived (non-claim).

The **arithmetic that composes these into the final bound** — the hybrid
sum feeding Prop. 5.9, plugging the concrete C1/C2 values, comparing the
enforced vs. protocol-max scenarios, and confirming the mask's absence from
the bound — is fully machine-checked. This is the same honest split as
`mask_prf.v`: proven combinatorial/arithmetic core, stated hypotheses for
the cryptographic-reduction steps.

## References

- [FGJ20] Fischlin–Günther–Janson, "Robust Channels", ePrint 2020/718;
  Journal of Cryptology 37(2):9, 2024 (DOI 10.1007/s00145-023-09489-9).
  Thms 7.1 & 7.2 via Prop. 5.9, §7 DTLS 1.3 analysis.
- NIST SP 800-232 (Ascon-AEAD128 bounds → C1/C2).
- design-01-record-layer.md §4.2.1 (mask PRF, disjoint key).
- `formal/coq/robust_channels.v` (arithmetic-core mechanization).
- `formal/coq/mask_prf.v` (companion mask-PRF bound mechanization).
