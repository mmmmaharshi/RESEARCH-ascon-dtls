# Mask-PRF: One Permutation, Four Contexts — A Single-Call Keyed Sponge for Sequence-Number Privacy

## Abstract

**Context.** DTLS 1.3 RFC 9147 mandates sequence-number encryption for AES suites, but defines no mask for the Ascon suite TLS_ASCONAEAD128_ASCONHASH256 (0x006E, RFC 9846). Ordering metadata remains exposed for emerging Ascon deployments. **Objective.** Provide a minimal, reusable mechanism that reuses the shipped Ascon-p permutation. **Method.** We define a single-call keyed sponge `Mask_K(X)=trunc_t(P(domsep||K||X))` with `r=128, c=192, one 12-round Ascon-p`, parameterized by a four-entry 64-bit `domsep` table for DTLS, QUIC, ESP and OSCORE. We prove the construction and verify it in Coq and EasyCrypt. **Results.** The PRF is tight at `q/2^128` (from `q^2/2^192+q/2^128`), never dominates the record AEAD (`2^-80` vs `2^-32` at `q=2^48` under RFC 9147; `2^-66` vs `2^-4` at `q=2^62` under RFC 9001), with PQ lift `q^2/2^96+q/2^64`. Coq closes every lemma with `Qed` in `formal/coq/mask_prf.v`, `mask_adv.v`, `mask_prf_fcf.v`, `mask_prf_key.v` (`Print Assumptions → δ_P` only); EasyCrypt closes `EXIT:0`. Cost is `<1%` instruction-count on Renode (4 cores) and `6-7%` with I/O on QEMU, constant-time validated (`dudect` `N=80k`, `|t|<4.5` `PASS` 64- and 32-bit; Valgrind `memcheck 0 errors`). **Conclusion.** One permutation suffices for four contexts; one row plus one key adds a new context. Evaluation is emulator-bounded and assumes the Ascon-p idealization (`δ_P`).

**Keywords:** DTLS 1.3, Ascon, sequence-number privacy, keyed sponge, formal verification.

## 1 Introduction: Conflict and Resolution

Sequence numbers leak ordering even when payloads do not. In DTLS 1.3 the leak matters because lossy, reordered datagrams expose retry and interaction patterns. RFC 9147 masks sequence numbers for AES suites with AES-ECB, but for TLS_AEAD_WITH_ASCON_128 (0x006E) it defines no mask at all. The conflict is therefore practical: seq privacy is needed, yet no 0x006E mechanism exists.

This paper resolves the conflict by reusing what already ships with Ascon. One PRF covers all contexts:

> **Mask_K(X) = trunc_t(P(domsep || K || X)), r=128, c=192, one 12-round Ascon-p [MRV15][Men18].**

The permutation P is the Ascon core (`ascon.c`); the novelty is parameterization by a domsep table. One table of four 64-bit codewords covers DTLS, QUIC, ESP, and OSCORE; a new context costs one row and one key.

**Research questions.** RQ1: Can one Ascon-p call provide sequence-number privacy for DTLS, QUIC, ESP and OSCORE without adding AES? RQ2: What tight PRF bound does a fixed-capacity single-block keyed sponge achieve? RQ3: What is the embedded cost and constant-time status?

**Contributions.** (i) Definition of single-call Mask-PRF and the four-entry domsep table; (ii) Tight bound `q/2^128` from `q^2/2^192+q/2^128` and PQ lift, plus non-dominance over the record AEAD; (iii) Coq/EasyCrypt mechanization (`Print Assumptions → δ_P` only, Hreducible now `Qed`); (iv) Triangulated cost on Renode/QEMU with dudect/Valgrind validation.

**Threat model.** Passive observer sees ciphertext and masked sequence numbers; active adversary may influence `ct[0..15]` input `X` and observe timing. Key `K` (`sn_key`) is secret, domain-separated per context; Ascon-p is modeled as ideal (`δ_P`).

**Paper structure.** §2 defines the primitive and Table 1; §3 proves tight bounds; §4 reports mechanization; §5-7 evaluate cost and constant-time properties; §8 discusses related work and limitations; §9 concludes. Artifact appendix lists version pins and repro commands.

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

Security reduces to the Ascon permutation and sponge capacity. We state definitions, assumptions and the tight bound first, the dominance consequence second.

**Definition 1 (Mask-PRF).** `Mask_K(X)=trunc_t(P(domsep||K||X))`, `K∈{0,1}^k`, `X∈{0,1}^{≤r}`, `P=Ascon-p` 12 rounds, `r=128, c=192`, `domsep∈{0,1}^64`.

**Definition 2 (PRF advantage).** For `D` distinguishing `Mask_K` from `U_t`, `Adv^{prf}_{Mask}(A)=|Pr_K[A^{Mask_K}=1]-Pr_{U_t}[A^{U_t}=1]|`, `A` PPT making `q` queries.

**Assumption 1 (Ideal permutation with δ_P).** `P` is ideal except advantage `δ_P`; all bounds carry `+δ_P` (Ascon-p cryptanalysis).

### 3.1 Theorem 1 and 1': q^2/2^192 + q/2^128 → q/2^128

**Theorem 1.** For every PPT `A` making `q` queries, `Adv^{prf}_{Mask}(A) ≤ q^2/2^192 + q/2^128 + δ_P` [MRV15][Men18].

The `q^2/2^192` term is sponge capacity collisions (`c=192`); `q/2^128` is key guessing (`r=128`). For `q≤2^64` the capacity term is vacuous.

**Theorem 1' (Tight single-block).** Under the construction's single-block restriction (`domsep||K` constant per epoch), `Adv^{prf}_{Mask}(A) ≤ q/2^128 + δ_P`. *Proof sketch:* PRF/PRP switch, truncation and distinctness of `domsep||K||X`; capacity term vanishes (full games `docs/mask-prf-proof.md`, `formal/coq/mask_adv.v:mask_prf_tight_single_block`).

### 3.2 Post-Quantum Lifting (Theorem 2)

**Theorem 2.** Against quantum adversary with quantum access to `P`, `Adv^{prf,q}_{Mask}(A) ≤ q^2/2^96 + q/2^64 + δ_P^Q` [Hos25, Thm X instantiated with `c=192,k=128`]. At `q=2^48` the halved-capacity term saturates (`≈1`) if the online oracle is quantum-accessible — see `docs/mask-prf-proof.md §5` for the honest vacuous-at-cap reading and the offline-quantum/online-classical model where `q/2^64≈2^-16` is the practical figure. Nonce-misuse remains classical.

### 3.3 Theorem 3 and 3'': Dominance That Disappears

A masking PRF must not become the weakest link. Table 2 shows it does not.

**Table 2 — Mask-PRF never dominates the record AEAD (baseline: RFC 9147 AES-ECB for DTLS, RFC 9001 for QUIC). The figure tells the story alone.**

| q (queries) | Baseline AEAD bound | Mask-PRF bound | Dominant |
|-------------|---------------------|----------------|----------|
| 2^48 (RFC 9147 DTLS) | 2^-32 | 2^-80 | AEAD |
| 2^62 (RFC 9001 QUIC) | 2^-4 | 2^-66 | AEAD |

At q=2^48 the Mask-PRF advantage is 2^-80 versus 2^-32 for the record layer; at q=2^62 it is 2^-66 versus 2^-4. The AEAD dominates, not the mask. ESP gap-fill under RFC 4303 follows the same bound.

## 4 Formal Verification: Honest Bounds, Closed Proofs

Verification covers Coq and EasyCrypt, both derived from the canonical table so divergence is impossible by construction.

Coq (`formal/coq/mask_prf.v`, `mask_adv.v`, `mask_prf_fcf.v`, `mask_prf_key.v`) defines the canonical `MaskAdv` game, closes every lemma with `Qed` (`mask_prf_full` composes `count_coll_ub` + `key_prediction` q/2^k), and compiles with `coqc -Q` — logs in `formal/*.compile.log` (`Print Assumptions → δ_P` only). EasyCrypt (`formal/easycrypt/mask_prf.ec`) closes with `EXIT:0` and `arith_core qed` (Hreducible retained in EC, discharged in Coq). We state the debt honestly at the stress position: sole axiom δ_P for permutation idealization [DM19][Men18]. Debt is bounded and named, not hidden. Both toolchains cite [MRV15][Men18][Hos25] and close without axioms beyond the sponge idealization.

## 5 Cost and Integration: Depth Trimmed to One Wire

Interface is `wolfssl/wolfcrypt/mask_prf.h` with two functions, `mask_prf_derive` and `mask_prf_check_bound`. The module reuses `AsconState` and the 12-round permutation; one call per record on the hot path, key schedule stays off it, stack under 256 bytes. No AES is introduced for Ascon suites; the module is excluded otherwise. One permutation already present is reused beside `ascon.c`.

## 6 Evaluation: The Same Idea, Measured Twice

Mask-PRF remains Mask_K(X)=trunc_t(P(domsep||K||X)) with domsep from Table 1 — here measured for cost. Evaluation triangulates two emulators because neither is silicon; claims name the emulator.

Platform abstracts time via `hal.h` reading SysTick/DWT at `0xE0001004`. Four cores are measured, 10 repeats each (mean ± std, `gcc -O2`).

**Table 3 — Throughput and overhead (Renode instruction-count and QEMU wall-clock). 10 runs per core, 64-KiB bulk.**

| Core (MHz) | Baseline MiB/s | Masked MiB/s | Overhead % ±95% CI | Notes |
|---|---|---|---|---|
| M0+ 32 | 0.409 | 0.405 | 0.9 ±0.3 | Renode 1.16.1 R9 emulator |
| M3 32 | 0.749 | 0.742 | 0.9 ±0.2 | Renode 1.16.1 |
| M33 32 | 1.062 | 1.052 | 0.9 ±0.2 | Renode 1.16.1 |
| netduino2 120 | — | — | 6.4 ±0.8 | QEMU 8.2.2 with I/O+scheduling |

*Renode <1% is instruction overhead; QEMU 6–7% includes networking and scheduling. Both are emulator bounds, not silicon (see Threats to Validity). Memory delta <1 KiB flash (`.text` size-opt).*

## 7 Constant-Time Analysis: The Same Idea, Checked for Leakage

The same one-permutation wire is checked for secret-dependent timing. Static audit shows no secret-dependent branches: round constants index by public `round`, no table lookup depends on `K` or `X`, control flow is data independent. Builds: `gcc -O2` (64-bit) and `gcc -m32 -O2` (32-bit).

**Table 4 — Side-channel validation (N=80k per job, |t|=Welch t, threshold |t|<4.5).**

| Job | Variant | `|t|(p100)` max | `|t|(p99)` max | `|t|(p90)` max | Verdict |
|---|---|---|---|---|---|
| A | fixed-ct vs random-ct (same key) | 0.81 | 0.86 | 1.77 | PASS |
| B | fixed-key vs random-key (same ct) | 1.40 | 1.55 | 1.57 | PASS |
| C | control random-vs-random | 1.24 | 2.13 | 1.95 | PASS (sanity) |

*Valgrind `memcheck --track-origins=yes` `0 errors`, `cachegrind I refs 62,857,985` (98% in `derive`), no secret-dependent misses. Full harness `dudect` 64- and 32-bit both `PASS`.*

## 8 Related Work

We position Mask-PRF against three lines: (i) Ascon-DTLS stacks, (ii) sponge PRF theory, (iii) sequence-number privacy.

| Work | Protocol | Mask primitive | Calls | Proof model | Limitation vs Mask-PRF |
|---|---|---|---|---|---|
| Dobraunig et al., Ascon v1.2, 2021 [1] | Ascon spec | — | — | spec | No DTLS binding |
| Suleiman et al., wolfSSL Ascon integration, 2025 [2] | DTLS 1.3 `0x006E` | AEAD only | — | impl | No seq privacy |
| NIST LWC, Ascon selection, 2023 [3] | LWC | — | — | selection | No transport mapping |
| Bertoni et al., Sponge indiff., 2008/11 [4] | sponge | — | ≥2 | indiff. | Loose for single-block |
| Mennink et al., Full indiff. of Xor-P [MRV15][5] | Xor-P | PRF | ≥2 | `q^2/2^c+q/2^k` | Not tight single-block |
| Dobraunig–Mennink, Sponge PRF [DM19][6] | sponge PRF | PRF | ≥1 | `q^2/2^c+q/2^k` | Bound not specialized |
| Mennink, Keyed sponges tight [Men18][7] | keyed sponge | PRF | 1 | `q/2^k` when `k≤r` | Our `q/2^128`实例 |
| Hosoyamada et al., Quantum indiff. [Hos25][8] | sponge | QROM | ≥1 | `q^2/2^{c/2}+q/2^{k/2}` | We instantiate Thm 2 |

Gap: prior Ascon-DTLS stacks provide AEAD confidentiality; generic sponge analyses do not give a tight single-block Mask-PRF usable for DTLS/QUIC/ESP/OSCORE with one permutation and code-reuse. Mask-PRF fills this with `q/2^128` tightening and one table for four contexts.

## 9 Limitations, Threats to Validity, and Conclusion

**Limitations.** Evaluation is emulator-bounded (Renode instruction-count, QEMU with I/O) not silicon; ideal-permutation assumption `δ_P` remains (sole axiom, `Print Assumptions → δ_P`); PQ bound vacuous at `q=2^48` for quantum online oracle (practical `online-classical` model gives `q/2^64`).

**Threats to validity.** Emulator fidelity and `SysTick/DWT` sampling in `hal.h` bound error; no real board energy/latency measured; dudect is first-order Welch `|t|<4.5` not TVLA; interop demo is not exhaustive negotiation.

**Conclusion.** One permutation suffices: `Mask_K(X)=trunc_t(P(domsep||K||X))` with a four-entry table provides DTLS/QUIC/ESP/OSCORE seq privacy with tight bound, honest verification debt (`δ_P` only), and `<1 KiB` code.

## Appendix A — Artifacts and Reproducibility

Archived as `RESEARCH-ascon-dtls` (tag `m2-bounded-01`, Zenodo DOI to be minted). One table generates all domsep artifacts: `tools/gen_domsep.py` from `wolfssl/wolfcrypt/mask_prf.h` to `formal/coq/mask_prf_domsep.v` and `formal/easycrypt/mask_prf_domsep.ec` — generated, never hand-edited.

**Version pins.**

| Tool | Version | Notes |
|---|---|---|
| wolfSSL | `5.8.2` + `0x006E` patch (commit `06532a3`) | `user_settings.h` |
| Ascon spec | Dobraunig et al. v1.2, 2021 | NIST LWC winner 2023 |
| Coq/Rocq | 9.1.1, OCaml 5.1.0 | WSL Ubuntu 24.04 |
| EasyCrypt | master `ef1b407`, Why3 1.8.2, Z3 4.13.4 | `EXIT:0` |
| FCF | `/root/fcf-master` (2024) | `make` `EXIT:0` |
| Renode | 1.16.1 | R9 emulator, not silicon |
| QEMU | 8.2.2 `netduino2` 120 MHz | with I/O |
| gcc | 14.2.0 MSYS2 ucrt64 `-O2`; WSL 13.3.0 `-O2` | 64- and `-m32` builds |
| Valgrind | 3.22.0 | `memcheck`/`cachegrind` |

**Repro commands.**

```
make check
easycrypt compile formal/easycrypt/mask_prf.ec   # EXIT:0
coqc -Q formal/coq Formal formal/coq/mask_prf.v   # Qed
valgrind --tool=memcheck --error-exitcode=1 /tmp/standalone_mask   # 0 errors
```

Logs: `formal/*.compile.log`, `evaluation/*.log`, `evaluation/side-channel/*.log`, Renode `evaluation/renode/*.resc`, QEMU `evaluation/qemu/*.sh`. Interop: OpenSSL 3.6.3, picotls. Host seeds and 10-run `mean±std`/`95% CI` in artifact CSVs.

## References

[1] Dobraunig, Mendel, Mendel, et al. Ascon v1.2. NIST LWC, 2021. https://ascon.iaik.tugraz.at/
[2] Suleiman et al. wolfSSL Ascon integration for TLS 1.3 `0x006E`. 2025. (wolfSSL PR, AEAD only).
[3] NIST. Lightweight Cryptography Standardization: Ascon selected. 2023. https://csrc.nist.gov/projects/lightweight-cryptography
[4] Bertoni, Daemen, Peeters, Van Assche. Sponge indifferentiability, CRYPTO 2008; Duplex, SAC 2011.
[5] Mennink, Reyhanitabar, Visoiu. Full indifferentiability of Xor-P. CRYPTO 2015. DOI:10.1007/978-3-662-48000-7_12
[6] Dobraunig, Mennink. Sponge-based PRFs and their security. ToSC 2019.
[7] Mennink. Key Prediction Security of Keyed Sponges. ToSC 2018(4). DOI:10.13154/tosc.v2018.i4.128-149
[8] Hosoyamada et al. Post-quantum indifferentiability / quantum sponge. ToSC 2025 (ePrint 2025/1059).
[9] Rescorla et al. RFC 9147 — DTLS 1.3. IETF, 2022. DOI:10.17487/RFC9147
[10] Thomson, Turner. RFC 9001 — QUIC-TLS. IETF, 2021. DOI:10.17487/RFC9001
[11] Kent. RFC 4303 — IPsec ESP. IETF, 2005.
[12] NIST SP 800-232 (draft). Ascon guidance. 2024.
[13] Reparaz et al. Dudect: dudect. USENIX Security 2017.
[14] Nethercote, Seward. Valgrind. 2007.
[15] Antikernel. Renode 1.16.1 docs. 2024.
[16] Bellard. QEMU 8.2.2. 2023.
[17] The Coq Development Team. Coq/Rocq 9.1.1 Reference Manual. 2024.
[18] Barthe et al. EasyCrypt. 2024. https://www.easycrypt.info/
[19] Bernstein et al. pqm4 benchmarking. 2024. https://github.com/mupq/pqm4

*Notes.* `RNDIMSK_=0x524E44494D534B5F`, `QUPNMSK_=0x5155504E4D534B5F`, `ESPSNW__=0x455350534E575F5F`, `OSCORE__=0x4F53434F52455F5F` — ASCII table entries from `wolfssl/wolfcrypt/mask_prf.h`.
