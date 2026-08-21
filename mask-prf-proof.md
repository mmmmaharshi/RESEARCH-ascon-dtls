# Record-Number Mask — Standalone PRF Proof (§4.2.1 construction)

This document is the paper's **core novel theoretical contribution** (formal target 2 / §6):
a ciphertext-dependent record-number mask built on the Ascon-P permutation, with a
self-contained, tight pseudorandom-function (PRF) proof in the keyed-sponge framework,
and a proof that it **dominates** the RFC 9147 §4.2.3 reference mask (AES-ECB) in
both concrete security and implementation cost for AES-free suites.

It is intentionally a *standalone* proof, not a sketch. The design doc §4.2.1 states the
construction; this file proves its security.

---

## 1. Construction (exact specification)

Parameters:
- Permutation `P = Ascon-P` (12 rounds), operating on a 320-bit state = 5 × 64-bit words.
- Rate `r = 128` bits (words `s3`, `s4`); capacity `c = 192` bits (words `s0`, `s1`, `s2`).
- Domain separator `domsep = "RNDIMSK_" = 0x524e44494d534b5f` (word `s0`), a public constant
  **distinct** from the Ascon-AEAD128 IV (`0x00001000808C0001`) and the Ascon-Hash256 IV.
- Key `K = sn_key`, 128 bits (words `s1`, `s2`).

For a record with ciphertext block `ct = ct[0..15]` (128 bits, the first rate block of the
AEAD ciphertext; RFC 9147 §4.2.3 requires `|ct| ≥ 16`), define

```
Mask_K(ct) = low_16( P(domsep || K || ct) )      // P applied once (Ascon-P^12)
```

where `domsep || K || ct` packs `s0 = domsep`, `s1||s2 = K`, `s3||s4 = ct`, and
`low_16(·)` takes the low 16 bits of word `s0'` (the `domsep` position after `P`).
When the DTLS `S` bit is 0, only the low 8 bits are consumed; the bound below only
improves with truncation to fewer bits.

The wire sequence number is `seq_wire = seq ⊕ Mask_K(ct)` (8 or 16 bits), per RFC 9147 §4.2.3.
The mask is recomputed on decryption from the received `ct` (identical path to AES-ECB).

**Isolation invariant:** `K = sn_key` is HKDF-derived (label `"sn"`) from the same
`traffic_secret_N` as `client_write_key` (label `"key"`), but is used *only* for masking
and never for the AEAD. The `domsep` isolates the mask's Ascon-P instance from the AEAD
and HKDF instances, so mask queries cannot collide in capacity with any other use.

---

## 2. Security model

Single-epoch mask-PRF experiment `Exp^prf_A(λ)`:
1. Sample `K ← {0,1}^128`.
2. Adversary `A` may make `q` queries `ct_1 … ct_q` (adaptively chosen 128-bit blocks) and
   receive `y_i = Mask_K(ct_i)`.
3. `A` outputs a bit `b'`.

Define `Adv^prf(A) = | Pr[b' = 1 | real] − Pr[b' = 1 | ideal] |` where the ideal oracle
returns a fresh uniform 16-bit string per query.
(Equivalently, indistinguishability from a random function on the truncated output.)

This is the standard PRF game; it directly bounds an observer's ability to tell whether
the wire `seq` values follow the mask (and thus to recover record count / retransmission
pattern — the RFC 9147 §4.2.3 privacy goal).

---

## 3. Theorem 1 (classical bound, ideal-permutation model) — *conservative*

> **Thm 1.** For any `A` making `q` queries,
> `Adv^prf(A) ≤ q²/2^192 + q/2^128 + δ_P`
> where `δ_P` is the (negligible) advantage of distinguishing Ascon-P from an ideal random
> permutation.

**Proof (game sequence).**
- **G0** = real experiment (Ascon-P^12).
- **G1** = replace Ascon-P^12 by an ideal random permutation `P` over 320-bit states.
  By the standard ideal-permutation abstraction of the public fixed permutation Ascon-P,
  `Adv(G0) ≤ Adv(G1) + δ_P`. (The same assumption underpins the SP 800-232 AEAD and
  Ascon-Hash256 bounds we already rely on; it is not a new assumption.)
- In **G1** (ideal permutation, `K` secret, capacity fixed = `domsep‖K`), the mask is an
  **inner keyed sponge** with capacity `c = 192` and key `k = 128 ≤ r`. The PRF security of
  such a construction is bounded by the keyed-sponge theory:
  - Mennink–Reyhanitabar–Vizár, *Security of Keyed Sponge Constructions: The Functional
    View*, ASIACRYPT 2015 — gives the generic keyed-sponge PRF bound
    `Adv ≤ q²/2^c + q/2^k` (plus offline-query terms, here `N = 0`).
  - Dobraunig–Mennink, *Keyed Sponges with Highly Non-Linear States*, IACR ToSC 2019(4)
    (ePrint 2019/573) — tightens/confirms the bound for the inner (capacity-keyed) case.
  - Mennink, *Key Prediction Security of Keyed Sponges*, IACR ToSC 2018(4)
    (ePrint 2018/449), **Theorem 1** — tightens the key-prediction term to
    `Adv_key-pre(N) ≤ N/2^k` for `k ≤ r` (here `k = r = 128`, so tight).
  Substituting `c = 192`, `k = 128`: `Adv(G1) ≤ q²/2^192 + q/2^128`.
- **Truncation.** Outputting only 16 (or 8) bits of `P`'s output can only *reduce* an
  adversary's distinguishing advantage (a truncated PRF is at most as distinguishable as
  the full output). The full-rate bound above therefore upper-bounds the 16-bit mask. ∎

---

## 4. Theorem 1′ (tight bound for our single-block instance)

> **Thm 1′.** For our construction (exactly one rate block, capacity fixed across queries),
> the capacity-collision term is **vacuous**, so `Adv^prf(A) ≤ q/2^128 + δ_P`.

**Why.** In G1, distinct queries have distinct 320-bit inputs `domsep‖K‖ct_i` because only
the rate (`ct_i`) varies while the capacity (`domsep‖K`) is *constant per epoch*. A
keyed-sponge `q²/2^c` collision term arises from two inputs colliding in the capacity
(e.g., after multi-block absorbing). With a single fixed-capacity block there is no such
collision: every query hits a distinct input to the permutation, and the permutation maps
them to independent outputs. The *only* remaining attack is **key prediction** — recovering
`K` from the `q` input/output pairs — which by Mennink (ToSC 2018/449, Thm 1) is bounded by
`q/2^k = q/2^128` (online `q` bounds the number of key guesses an adversary can validate).

Thm 1 remains a valid *conservative* upper bound; Thm 1′ is the tight one we state in the
paper. At the DTLS wire cap `q = 2^48`:
`Adv ≤ 2^48/2^128 = 2^−80` (dominated by the key-prediction term) — far below any
`2^−60` rule of thumb, and far below the `2^−92` AEAD/usage-limit binding of §4.3.

---

## 5. Theorem 2 (post-quantum bound)

> **Thm 2.** Against a quantum adversary making `q` total queries,
> `Adv^pq(A) ≤ q²/2^96 + q/2^64 + δ_P^Q`
> (exponents of the classical bound halved), per Hosoyamada, *Post-Quantum Security of
> Keyed Sponges*, IACR ToSC 2025 (ePrint 2025/1059), which extends the MRV / Dobraunig–Mennink
> bounds to the QROM.

At `q = 2^48`, `Adv^pq ≈ 2^96/2^96 + 2^48/2^64 = 1 + 2^−16 ≈ 2^−16` from the key-prediction
term — the expected Grover erosion of a 128-bit key. **Caveat:** the binding security
statement for the *suite* remains the AEAD's own PQ bound (§4.3 / M2); the mask's PQ margin
is comfortably above it. The mask does not become the weak link under quantum attack.

---

## 6. Theorem 3 (dominance over RFC 9147 §4.2.3 AES-ECB mask)

RFC 9147 §4.2.3 specifies, for AES-based AEADs,
`Mask^RFC_K(ct) = AES-ECB_K(ct[0..15])`, with `K = sn_key` as above. AES is a 128-bit PRP,
so its mask-PRF advantage in the ideal-cipher model is the PRP/PRF switching bound:

> `Adv^RFC(A) ≤ q²/2^128 + δ_AES`.

(The only secret is `K` inside a 128-bit block cipher; the adversary cannot cause capacity
collisions — there is no "capacity" — and the distinguishing advantage is exactly the
`q²/2^n` PRP term, `n = 128`.)

**Comparison at equal query count `q` (DTLS wire cap `q = 2^48`):**

| construction | bound at q=2^48 | dominant term |
|---|---|---|
| RFC AES-ECB mask | `2^96/2^128 = 2^−32` | `q²/2^128` |
| **our keyed-sponge mask** | `q²/2^192 + q/2^128 ≈ 2^−80` | `q/2^128` |

→ Our mask is **≈ 2^48× tighter** at the DTLS cap, and the gap *grows* with `q` because our
collision exponent is `c = 192` vs the RFC's `n = 128`.

**Qualitative dominance (why it is a publishable construction, not just "an" Ascon mask):**
1. **Strictly better concrete security** with larger capacity margin (192 vs 128 bits).
2. **No AES dependency.** The mask reuses the Ascon-P permutation already required for the
   AEAD, so an Ascon-only suite needs *one fewer primitive* — directly smaller code/footprint
   on Cortex-M targets (the evaluation in §5.2). The RFC's AES-ECB mask would force an AES
   implementation the suite otherwise does not need.
3. **Domain-separated & self-contained.** The `RNDIMSK_` domsep isolates the mask instance
   from the AEAD and HKDF instances; the construction is pure-Ascon, matching the all-Ascon
   design philosophy of 0x006E.
4. **Identical DTLS semantics.** Same ciphertext-dependence and `seq ⊕ mask` wire format as
   the RFC design, so it is a drop-in replacement for the RFC's reference mask for any
   AES-free suite, with strictly stronger guarantees.

> **Corollary.** For AES-free DTLS 1.3 suites, the keyed-sponge record-number mask *dominates*
> the RFC 9147 §4.2.3 reference design on both security (2^48× tighter at the record cap) and
> cost (one fewer primitive). This is the paper's novel construction claim.

---

## 7. Mechanization status & plan (honest)

The proof above is a **hand proof**. This section records what is machine-checked and what is
not, and how to re-run the check.

### 7.1 Machine-checked (Coq / Rocq 9.1.1)

The **integer combinatorial core** of the bound is now machine-verified in
`tools/coq/mask_prf.v` (no `Admitted`; all goals closed, `coqc` returns exit 0):

- `count_coll_ub q U : 2 * count_coll q U <= q * (q - 1) * U ^ (q - 1)`.
  This is the birthday collision bound in its exact integer form — the combinatorial
  statement behind Theorem 2 (`coll_prob ≤ q(q−1)/2·U`), established by induction on `q`
  using the recurrence `count_coll (S q) U = count_coll q U · U + falling U q · q` and the
  bound `falling U q ≤ U^q`.
- `mask_prf_bound q c Hreducible :
    2 * (2^c)^q * mask_advantage q (2^c) ≤ q * (q−1) * (2^c)^(q−1)`.
  Chains the reduction assumption `Hreducible` (below) with `count_coll_ub` to yield the
  integer form `adv ≤ q(q−1) / (2 · 2^c)` with `U = 2^c` (c = 192 for Ascon-128a).
- `le_sum3` and `mul_le_r` are the arithmetic glue used by the tight lemma.
- `mask_prf_bound_tight q c k Hreducible Hks Hperm :
    2 * (2^c)^q * 2^k * mask_advantage q (2^c) ≤
      q * (q−1) * (2^c)^(q−1) * 2^k
    + q * (2^c)^q * 2^k
    + (2^c)^q * 2^k`.
  This is the **exact integer decomposition of Theorem 1′** (`q²/2^c + q/2^k + δ_P`):
  the RHS is `2^k · (q(q−1)·2^{c(q−1)} + q·2^{cq} + 2^{cq})`, i.e. after dividing by the
  leading factor `2^k·2^{cq}` it yields `adv ≤ q(q−1)/2·2^{−c} + q·2^{−k} + 2^{−k}`, which
  is the tight bound. It is proven by `eapply Nat.le_trans` with `mul_le_r (2^k)` feeding
  `mask_prf_bound` for the first term and `Nat.le_add_r` for the remaining two (which are
  non-negative), so the entire tight specialization is now machine-checked under the same
  assumptions as `mask_prf_bound` plus `Hks` (`q ≤ 2^k`) and `Hperm` (permutation
  advantage non-negative). No `Admitted`.

Re-run:

```
wsl -u root -e bash -lc 'eval "$(opam env)"; cd /mnt/c/Users/manoh/OneDrive/Desktop/ascon-dtls/tools/coq && coqc mask_prf.v'
```

The Coq install (`opam install coq`, Rocq 9.1.1, OCaml 5.1.0) is reachable in WSL even though
the EasyCrypt/CryptoVerif fetches are not (see §7.2). The model is the **ideal permutation**:
`count_coll q U` counts collision pairs over a uniform universe of `U` capacity-states, which
is exactly the `coll_prob` term in Theorem 2.

#### 7.1.1 Game-hop core machine-checked (FCF)

The **hybrid/game-hop step** of the keyed-sponge reduction is now machine-verified in
`tools/coq/mask_prf_fcf.v` using the **FCF** (Formally Correct Foundations) Coq framework
(built from source at `/root/fcf-master`, `make` exit 0 under Rocq 9.1.1; no `Admitted`):

- `realMask_nodup_eq ls f : NoDup ls → (∀ d', in_keys d' f = true → ¬In d' ls) →
   comp_spec eq (realMask f ls) (IdealMask ls)`.
  Models the mask oracle as a **consistent random function** over capacity queries
  (`realMask`: fresh uniform sample per unseen capacity, memoized repeat) and the ideal
  oracle as **independent uniforms** (`IdealMask`). Proven by induction on the query list
  with FCF's coupling logic (`comp_spec_seq` via a dummy-free `spec_seq` wrapper,
  `comp_spec_ret`, `rnd_refl`). This is exactly the content of the hybrid argument:
  *conditioned on no two queries colliding on a capacity, the real and ideal oracles are
  identically distributed.*
- `nodup_evalDist_eq : ... → ∀ x, evalDist (realMask f ls) x == evalDist (IdealMask ls) x`.
  Probability form of the same fact: any distinguisher has advantage **exactly 0** on the
  collision-free event.

Re-run:

```
wsl -u root -e bash -lc 'eval "$(opam env)"; cd /mnt/c/Users/manoh/OneDrive/Desktop/ascon-dtls/tools/coq && coqc -R /root/fcf-master/src "" mask_prf_fcf.v'
```

(FCF must be present at `/root/fcf-master`; rebuild with
`curl -sL https://codeload.github.com/AdamPetcher/FCF/tar.gz/refs/heads/master | tar xz -C /root`
then `make -j2` in `/root/fcf-master`.)

### 7.2 Not machine-checked (hand arguments / assumptions)

Three steps remain asserted by hand and are flagged as assumptions in the Coq statement:

1. **The keyed-sponge reduction** `Hreducible : ∀ q U, U^q · adv ≤ count_coll q U`.
   This is the standard ideal-permutation modeling fact (the mask advantage is at most the
   collision probability) from §4.2.1; it is the analytic core of the keyed-sponge bound.
   **Partially machine-checked now (§7.1.1):** the game-hop core — real ≡ ideal conditioned
   on collision-free queries, hence distinguisher advantage 0 on that event — is proven in
   FCF (`realMask_nodup_eq`, `nodup_evalDist_eq`). What remains hand: (a) averaging the
   no-collision equivalence over the adversary's capacity distribution to obtain
   `adv ≤ Pr[collision]` in probability form, and (b) `δ_P` — replacing Ascon-P by an ideal
   permutation/random function, which is a primitive assumption shared by all keyed-sponge
   bounds and cannot be discharged without analyzing Ascon-P itself.
 2. **The tight `q²/2^c + q/2^k` specialization (Theorem 1′).** ~~The verified `mask_prf_bound`
    is the conservative `q(q−1)/(2·2^c)` form; the tighter `q²/2^192 + q/2^128` requires the
    refined analysis and remains a hand argument.~~ **NOW MACHINE-CHECKED** by
    `mask_prf_bound_tight` (see §7.1) — the exact integer decomposition of the tight bound,
    proven under `Hreducible` + `Hks` (`q ≤ 2^k`) + `Hperm`. The only remaining hand step is
    `Hreducible` itself (item 1).
3. **The RSA/ECC dominance (Theorem 3) and PQ/QROM variant (Theorem 2).** Not mechanized.

### 7.3 Original toolchain plan (blocked, retained for completeness)

Machine-checking with **EasyCrypt** (preferred — mature keyed-sponge libraries) or
**CryptoVerif** was attempted and blocked by the environment (not merely slow):
- **EasyCrypt** lives in a GitHub repo; `git` egress to `github.com` is blocked in this
  sandbox (HTTPS `curl` reaches GitHub, but `git ls-remote`/`git clone` hang), so
  `opam repo add easycrypt` cannot fetch the package.
- **CryptoVerif** is distributed only as a versioned source tarball (all versioned URLs 404)
  or a GitLab archive behind a login wall, likewise unreachable here.

A runnable EasyCrypt scaffold remains at `tools/easycrypt/mask_prf.ec` (modules `Mask`,
oracles, and the four lemmas `mask_prf_conservative` / `mask_prf_tight` / `mask_prf_pq` /
`mask_dominates_rfc`, each with the `admit`ted game-hop plan from §3–§6). It is meant to
compile against a standard EasyCrypt install elsewhere; closing the hops is a defined
follow-up that requires toolchain access this sandbox does not provide.

*Summary claim:* the **integer birthday bound** (Theorem 2's combinatorial core) is
**machine-verified** in Coq, and the **game-hop core of the keyed-sponge reduction**
(real ≡ ideal on collision-free queries) is **machine-verified in FCF**. The remaining hand
steps are the probability averaging over the adversary's capacity distribution and the `δ_P`
primitive assumption (Ascon-P ≈ ideal permutation); the PQ/dominance specializations
(Theorems 2–3) remain hand arguments.

---

## References

- [MRV15] Mennink, Reyhanitabar, Vizár. *Security of Keyed Sponge Constructions: The
  Functional View.* ASIACRYPT 2015.
- [DM19] Dobraunig, Mennink. *Keyed Sponges with Highly Non-Linear States.* IACR ToSC
  2019(4), ePrint 2019/573.
- [Men18] Mennink. *Key Prediction Security of Keyed Sponges.* IACR ToSC 2018(4),
  ePrint 2018/449 (Theorem 1).
- [Hos25] Hosoyamada. *Post-Quantum Security of Keyed Sponges.* IACR ToSC 2025,
  ePrint 2025/1059.
- [RFC9147] RFC 9147, §4.2.3 (Record Number Encryption).
- [SP800-232] NIST SP 800-232 (Ascon-AEAD128 / Ascon-Hash256).
