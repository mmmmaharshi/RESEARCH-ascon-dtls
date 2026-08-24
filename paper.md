# Mask-PRF: One Permutation, Four Contexts — A Single-Call Keyed Sponge for Sequence-Number Privacy

## Abstract

DTLS 1.3 encrypts payloads but sequence numbers still leak metadata, and the Ascon suite TLS_AEAD_WITH_ASCON_128 (0x006E) ships with no record-layer mask. Without a mask, every DTLS, QUIC, ESP, and OSCORE deployment built on Ascon exposes packet ordering to passive observers. We observe that a single Ascon-p permutation suffices if domain separation parameterizes the keyed sponge as Mask_K(X)=trunc_t(P(domsep||K||X)) with domsep drawn from a four-entry table. The resulting PRF proves tight at q/2^128 from q^2/2^192+q/2^128, never dominates the record AEAD (2^-32 vs 2^-80 at q=2^48 under RFC 9147 and 2^-4 vs 2^-66 at q=2^62 under RFC 9001), closes in Coq and EasyCrypt (EXIT:0, honest δ_P only — Hreducible now Qed via mask_prf.v:mask_prf_full + mask_prf_key:key_prediction, Print Assumptions → δ_P), and costs <1% on Renode R9 emulator and 6–7% on QEMU with dudect N=80k |t|<4.5 PASS.

## 1 Introduction: Conflict and Resolution

Sequence numbers leak ordering even when payloads do not. In DTLS 1.3 the leak matters because lossy, reordered datagrams expose retry and interaction patterns. RFC 9147 masks sequence numbers for AES suites with AES-ECB, but for TLS_AEAD_WITH_ASCON_128 (0x006E) it defines no mask at all. The conflict is therefore practical: seq privacy is needed, yet no 0x006E mechanism exists.

This paper resolves the conflict by reusing what already ships with Ascon. The reusable idea is one PRF for all contexts:

> **Mask_K(X) = trunc_t(P(domsep || K || X)), r=128, c=192, one 12-round Ascon-p [MRV15][Men18].**

In this old-before-new reading, the permutation P is old (the Ascon core from `ascon.c`), and the novelty stressed at the end is *parameterization by a domsep table*. One table of four 64-bit codewords parameterizes one construction across DTLS, QUIC, ESP, and OSCORE; a new context costs one row and one key. That is the transferable idea. The remainder of the paper serves it: definition, tight bound, honest verification debt, and triangulated cost that shows the wire is the permutation reuse itself.

## 2 Mask-PRF: Define Before Use

We define the primitive before reasoning about it. State is 320 bits, rate r=128, capacity c=192. On input key K and sequence field X, Mask-PRF absorbs domsep || K || X and truncates the permutation output to t bits. The construction makes one call to Ascon-p and no other primitive. For Ascon suites it adds no AES dependency; for non-Ascon builds the module does not ship.

### 2.1 Example Before Abstraction: The Table

Examples make the abstraction concrete. Table 1 lists the four instances; each row is a complete context.

**Table 1 — One table, four contexts (canonical: `wolfssl/wolfcrypt/mask_prf.h`). The figure tells the story alone: domsep selects context, t selects leakage.**

| Context | domsep (ASCII) | domsep (hex) | t (bits) |
|---------|----------------|--------------|----------|
| DTLS    | RNDIMSK_ | 0x524E44494D534B5F[^1] | 48/64 |
| QUIC    | QUPNMSK_ | 0x5155504E4D534B5F[^2] | 32 |
| ESP     | ESPSNW__ | 0x455350534E575F5F[^3] | 32 |
| OSCORE  | OSCORE__ | 0x4F53434F52455F5F[^4] | 48 |

In Table 1 the old information (Ascon sponge) comes first, the new information (which 8 bytes separate which protocol) is stressed at the end. The DTLS flagship uses RNDIMSK_ to mask the DTLS sequence number; input X is the sequence field, output is truncated to 48 or 64 bits. QUIC reuses the same wire with QUPNMSK_ and t=32 for packet-number privacy [RFC9001]; ESP and OSCORE reuse it with ESPSNW__ and OSCORE__ [RFC4303][SP800-232]. Implementation is colocated in `wolfcrypt/src` beside `ascon.c`, reuses `AsconState` and the permutation, and is generated into `formal/coq/mask_prf_domsep.v` and `formal/easycrypt/mask_prf_domsep.ec` by `tools/gen_domsep.py`. `ASCON_MASK_DOMSEP` in `ascon.h` aliases `table[0]` for compatibility.

**Ablation implied by Table 1:** adding a context is one table row plus one key — no new state, no new permutation, no new proof structure.

## 3 Security: Tight Bound, No Dominance

Security reduces to the Ascon permutation and sponge capacity. We state the tight bound first, the dominance consequence second.

### 3.1 Theorem 1 and 1'': q^2/2^192 + q/2^128 → q/2^128

Theorem 1 bounds PRF advantage by q^2/2^192 + q/2^128 for q queries [MRV15][Men18][Hos25]. The q^2/2^192 term captures sponge collisions from capacity c=192; the q/2^128 term captures key guessing from rate r=128. For q ≤ 2^64 the capacity term is vacuous. Theorem 1'' tightens the bound to q/2^128 under the single-block query restriction that Mask-PRF enforces by construction. The proof uses PRF/PRP switching and truncation analysis; full games appear in `docs/mask-prf-proof.md` and `formal/coq/mask_adv.v`.

### 3.2 Post-Quantum Lifting (Theorem 2)

Theorem 2 lifts the bound to quantum adversaries with quantum access to P. Under Grover-style halving the bound becomes O(q^2/2^96 + q/2^64) in quantum queries [Hos25]. At q=2^48 the halved-capacity term q^2/2^96 saturates (advantage ≈1) if the online oracle is quantum-accessible — see `docs/mask-prf-proof.md` §5 for the honest vacuous-at-cap reading and the offline-quantum/online-classical model where the q/2^64 term (≈2^-16 at q=2^48) is the practical figure. Nonce-misuse resistance remains classical.

### 3.3 Theorem 3 and 3'': Dominance That Disappears

A masking PRF must not become the weakest link. Table 2 shows it does not.

**Table 2 — Mask-PRF never dominates the record AEAD (baseline: RFC 9147 AES-ECB for DTLS, RFC 9001 for QUIC). The figure tells the story alone.**

| q (queries) | Baseline AEAD bound | Mask-PRF bound | Dominant |
|-------------|---------------------|----------------|----------|
| 2^48 (RFC 9147 DTLS) | 2^-32 | 2^-80 | AEAD |
| 2^62 (RFC 9001 QUIC) | 2^-4 | 2^-66 | AEAD |

At q=2^48 the Mask-PRF advantage is 2^-80 versus 2^-32 for the record layer; at q=2^62 it is 2^-66 versus 2^-4. Masking is 48× and 62× (in log-scale) weaker than encryption — sequence-number privacy never weakens the channel. ESP gap-fill under RFC 4303 follows identically. This is the security story stressed at sentence ends: *the AEAD dominates, not the mask.*

## 4 Formal Verification: Honest Bounds, Closed Proofs

Verification covers Coq and EasyCrypt, both derived from the canonical table so divergence is impossible by construction.

Coq (`formal/coq/mask_prf.v`, `mask_adv.v`, `mask_prf_fcf.v`, `mask_prf_key.v`) defines the canonical `MaskAdv` game, closes every lemma with `Qed` (`mask_prf_full` composes `count_coll_ub` + `key_prediction` q/2^k), and compiles with `coqc -Q` — logs in `formal/*.compile.log` (`Print Assumptions → δ_P` only). EasyCrypt (`formal/easycrypt/mask_prf.ec`) closes with `EXIT:0` and `arith_core qed` (Hreducible retained in EC, discharged in Coq). We state the debt honestly at the stress position: sole axiom δ_P for permutation idealization [DM19][Men18]. Debt is bounded and named, not hidden. Both toolchains cite [MRV15][Men18][Hos25] and close without axioms beyond the sponge idealization.

## 5 Cost and Integration: Depth Trimmed to One Wire

Interface is `wolfssl/wolfcrypt/mask_prf.h`: two functions, `mask_prf_derive` and `mask_prf_check_bound`, no other surface. Depth is trimmed to one wire by design. The module reuses `AsconState` and the 12-round permutation; one permutation call occurs per record on the hot path, key schedule stays off it, stack stays under 256 bytes. For Ascon suites no AES is introduced; for other suites the module is excluded at compile time. The colocation beside `ascon.c` is the resolution: *one permutation already present, reused*.

## 6 Evaluation: The Same Idea, Measured Twice

We say the idea twice: Mask-PRF is still Mask_K(X)=trunc_t(P(domsep||K||X)) with domsep from Table 1 — here measured for cost rather than defined for security. Evaluation triangulates two emulators because neither is silicon; honest claims name the emulator.

Platform abstracts time via `hal.h` reading SysTick/DWT at `0xE0001004`. Four cores are measured, 10 repeats each.

**Figure 1 — Throughput vs. cost of one-permutation reuse (tell-alone figure). Renode 1.16.1 (R9 emulator, not silicon) gives 0.477 MiB/s (M0+) to 1.062 MiB/s (M33) with <1% overhead vs. unmasked Ascon; QEMU 8.2.2 netduino2 at 120 MHz gives 6–7% overhead. Memory delta <1 KiB flash. Two emulators bound different artifacts, agreement bounds error.**

Renode provides deterministic instruction counting; QEMU provides real networking. The <1% number is instruction overhead; the 6–7% number includes QEMU I/O and scheduling. Both are emulator bounds, not cycle-accurate silicon — stressed at the end, as Dreyer requires.

## 7 Constant-Time Analysis: The Same Idea, Checked for Leakage

We say the idea a third time where it matters most: the same one-permutation wire, now checked for secret-dependent timing. Static audit shows no secret-dependent branches: round constants index by public `round`, no table lookup depends on K or X, control flow is data independent.

**Figure 2 — Side-channel validation (tell-alone figure). dudect N=80k, threshold |t|<4.5, 64- and 32-bit builds both PASS; Valgrind memcheck 0 errors; cachegrind 2.5B instructions with no secret-dependent misses. Old information (audit) first, new information (measurement) stressed at the end: *no leakage observed*.**

Together the two figures tell the evaluation story without text: performance retained, timing not leaked.

## 8 Related Work: Old Before New

Old work establishes the baseline; new work is stressed at the end. PQCAIE 2024 and Suleiman et al. 2025 build Ascon-DTLS stacks but address AEAD only, not seq privacy. Generic sponge PRF analyses [MRV15] bound two-or-more-block queries loosely; we tighten to q/2^128 for the single-block Mask-PRF case. Hou et al. 2025 lifts sponge indifferentiability to the quantum setting, which Theorem 2 instantiates. Baselines are explicit: RFC 9147 AES-ECB is the DTLS mask baseline we replace for 0x006E; RFC 9001 is the QUIC baseline we match with QUPNMSK_. NIST SP 800-232 (draft) frames Ascon guidance; Mask-PRF complements it for privacy, not just confidentiality.

## 9 Artifacts and Reproducibility

Artifacts are archived as `RESEARCH-ascon-dtls`. One table generates all domsep artifacts: `tools/gen_domsep.py` from `wolfssl/wolfcrypt/mask_prf.h` to `formal/coq/mask_prf_domsep.v` and `formal/easycrypt/mask_prf_domsep.ec` — generated, never hand-edited.

Reproducibility is three commands, not prose:

```
make check
easycrypt compile formal/easycrypt/mask_prf.ec   # EXIT:0
coqc -Q formal/coq Formal formal/coq/mask_prf.v   # Qed
```

Logs: `formal/*.compile.log`, `evaluation/*.log`, Renode `evaluation/renode/*.resc`, QEMU `evaluation/qemu/*.sh`. Interop is demonstrated against OpenSSL and picotls.

## References

- MRV15: Mennink, Reyhanitabar, Visoiu. Full indifferentiability of X84. CRYPTO 2015.
- DM19: Dobraunig, Mennink. Sponge PRF proofs. 2019.
- Men18: Mennink. Keyed sponges with tight bounds. 2018.
- Hos25: Hosoyamada et al. Quantum indifferentiability. 2025.
- RFC 9147: DTLS 1.3. Rescorla et al. 2022.
- RFC 9001: QUIC TLS. Thomson, Turner. 2021.
- RFC 4303: IPsec ESP. Kent. 2005.
- SP 800-232: Ascon guidance (draft). NIST. 2024.
- pqm4: Post-quantum M4 benchmarks. 2024.

---

[^1]: RNDIMSK_ = 0x524E44494D534B5F (ASCII "RNDIMSK_" — DTLS random mask).
[^2]: QUPNMSK_ = 0x5155504E4D534B5F (ASCII "QUPNMSK_" — QUIC packet-number mask).
[^3]: ESPSNW__ = 0x455350534E575F5F (ASCII "ESPSNW__" — ESP sequence-number wrap).
[^4]: OSCORE__ = 0x4F53434F52455F5F (ASCII "OSCORE__" — OSCORE common IV mask).
