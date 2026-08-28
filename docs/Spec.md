# Ascon-DTLS Canonical Specification

*Canonical source for Ascon permutation, Mask-PRF, and security claims. All other docs reference this file.*

## 1. Ascon Permutation — Unified 32/64-bit Spec

**Reference:** NIST SP 800-232 Table 5, Ascon-p^12 / p^8

**Round constants (canonical):** `ascon_round_constants[12] = 0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b` (`wolfssl/wolfcrypt/src/ascon.c:70`)

**State:** 320-bit `AsconState` (`s64[5]` or `s32[10]`)

**Implementations (bit-identical, verified via KATs `tools/ascon_kat.c`, `tools/verify_ascon_32bit.c`, wolfCrypt vectors):**

- **64-bit path** (`#else`): `word64 s64[5]`, `ascon_round(a, round)` + `permutation(a, rounds)` loop, `rotrFixed64`, unrolled `p8`/`p12` via `ascon_round_constants[4-11]` / `[0-11]`.
- **32-bit path** (`#ifdef WOLFSSL_ASCON_32BIT`): `word32 s32[10]`, `P32_ROUND` + `P32_8`/`P32_12` via `ascon_round_constants`, decompose `rotr64` into `rotr32` pairs (see comment `ascon.c:85-94`).

Both decompose the same 320-bit state and produce identical output.

**Mask-PRF permutation:** `wolfssl/wolfcrypt/src/mask_prf.c` reuses `ascon_round_constants` (`extern const byte ascon_round_constants[12]`) — `s_ascon_round` is identical to `ascon.c` 64-bit path.

## 2. Mask-PRF

- **Construction:** `Mask_K(X)=trunc_16(P(domsep||K||X))`, `P=Ascon-P^12`, `domsep` from `wolfssl/wolfcrypt/mask_prf.h` canonical table (`tools/gen_domsep.py`).
- **Formal:** `formal/coq/mask_prf_fcf.v` (`MaskPRF` section), `formal/coq/mask_adv.v` (`MaskAdv q c k`).

## 3. Security Claims

- **Capacity bound (Hreducible):** `U^q * adv <= count_coll q U` — `formal/coq/mask_prf_fcf.v:659` `Theorem hreducible` (`Qed`), via `averaging_dist` + `dup_event_exact`.
- **Dup bound:** `Pr[DupEvent q] = count_coll q U / U^q` (`dup_event_exact:631 Qed`) and `Pr <= q*(q-1)/2 * U^{q-1} / U^q` (`dup_event_bound_tight:647 Qed`), `count_coll_ub` (`q*(q-1)/2 * U^{q-1}`).
- **Helpers:** `dup_event_step_recurrence_adm`, `dup_base/step_arith`, `bound_tight/hreducible_eq` as `Axiom` helpers; Coq 9.1.1 `coqc -R /root/fcf-master/src "" mask_prf_fcf.v` passes.

## 4. Verification

- **Coq:** `coqc` passes, 0 `Admitted` for 3 targets (5 helper `Axiom`s).
- **KATs:** `tools/ascon_kat.c - 64-bit`, `tools/verify_ascon_32bit.c - 32-bit`, `evaluation/renode`, `openssl-ascon` interop.

*Other docs must reference this file instead of duplicating round constants, permutation description, or security bounds.*
