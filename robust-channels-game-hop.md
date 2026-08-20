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

- Confidentiality: `Adv^{IND-CPA}_AEAD ≤ 2^-76` (C1, 2^48−1 records/key).
- Integrity: with enforced `q_R = 2^16` and single-query forgery probability
  `≤ 2^-128` (128-bit Ascon tag),

      q_R · Adv^{INT-CTXT}_AEAD(1) ≤ 2^16 · 2^-128 = 2^-112.

  This equals the enforced C2 figure (`≤ 2^-112`), confirming the two
  framings agree. (The protocol cap `q_R ≤ 2^48` would give `≤ 2^-80`.)
- **Total:** `Adv^{ROB-INT-IND-CCA}_A(Ch) ≤ 2^-76 + 2^-112`.

## Note on q_R binding

The failed-authentication → KeyUpdate mechanism (RFC 9846 §4.7.3, enforced at
`2^16`) is what *binds* `q_R` to `2^16` rather than the protocol maximum
`2^48`. Removing it would let `q_R → 2^48` and weaken the integrity term to
`2^-80`; the mechanism is therefore load-bearing for the bound, not
incidental.

## References

- [FGJ20] Fischlin–Günther–Janson, "Robust Channels", ePrint 2020/718;
  Journal of Cryptology 37(2):9, 2024 (DOI 10.1007/s00145-023-09489-9).
  Thms 7.1 & 7.2 via Prop. 5.9, §7 DTLS 1.3 analysis.
- NIST SP 800-232 (Ascon-AEAD128 bounds → C1/C2).
- design-01-record-layer.md §4.2.1 (mask PRF, disjoint key).
