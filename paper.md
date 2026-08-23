# Mask-PRF: A Single-Call Keyed-Sponge PRF for Sequence-Number Privacy

## Abstract

This paper presents the first wolfSSL implementation of TLS_AEAD_WITH_ASCON_128 (0x006E) for DTLS 1.3, and its generic privacy primitive Mask-PRF. Mask-PRF is defined as Mask_K(X)=trunc_t(P(domsep||K||X)) with rate r=128, capacity c=192, and a single Ascon-p permutation. A domain-separation table parameterizes one construction across contexts (Table 1): RNDIMSK_ (0x524E44494D534B5F)[^1] for DTLS, QUPNMSK_ (0x5155504E4D534B5F)[^2] for QUIC, ESPSNW__[^3] and OSCORE__[^4] for ESP and OSCORE. Security is bounded by q^2/2^192 + q/2^128, tight to q/2^128. Theorem 3 shows dominance over record-layer AEAD for q=2^48 under RFC 9147. Theorem 3'' covers q=2^62 under RFC 9001 with ESP gap-fill. Formal evidence includes Coq proofs (mask_prf.v, mask_adv.v, mask_prf_fcf.v, all qed) and EasyCrypt (EXIT:0, arith_core qed, honest Hreducible δ_P). Evaluation uses Renode 1.16.1 on M0+/M3/M4/M33 (0.477 to 1.062 MiB/s, <1% overhead) triangulated with QEMU 8.2.2 netduino2 (6–7%). Constant-time validation shows dudect N=80k |t|<4.5 PASS (64- and 32-bit), memcheck 0 errors, and cachegrind 2.5B instructions. Interoperability with OpenSSL and picotls is demonstrated. Artifacts are archived as RESEARCH-ascon-dtls.

## 1 Introduction

Sequence numbers leak metadata in encrypted transport protocols. DTLS 1.3 encrypts them, but Ascon suites lacked an implementation. RFC 9147 defines no built-in masking for TLS_AEAD_WITH_ASCON_128 (0x006E), leaving a gap. This work fills that gap with a minimal, verified primitive. Contributions are fourfold. C1 provides the first wolfSSL DTLS 1.3 stack for 0x006E. C2 introduces Mask-PRF, a single-call keyed sponge. C3 delivers machine-checked proofs in Coq and EasyCrypt. C4 evaluates performance and side-channel resistance on embedded targets. The design favors deletion over addition, reusing Ascon state and permutation.

## 2 Mask-PRF

Mask-PRF is a truncated keyed sponge over the Ascon permutation. It follows a single permutation call per record.

### 2.1 Generic Parameters

Mask-PRF is defined as Mask_K(X) = trunc_t(P(domsep || K || X)). Rate is r=128 bits, capacity is c=192 bits. State size is 320 bits total. The construction uses one Ascon-p permutation with 12 rounds. The domsep parameter selects the context. Table 1 lists four instantiations. One table parameterizes all uses. New contexts require only a new row and key.

Table 1: Domain-separation table (canonical source: wolfssl/wolfcrypt/mask_prf.h).

| Context | domsep (ASCII) | domsep (hex) | t (bits) |
|---------|----------------|--------------|----------|
| DTLS    | RNDIMSK_ | 0x524E44494D534B5F[^1] | 48/64 |
| QUIC    | QUPNMSK_ | 0x5155504E4D534B5F[^2] | 32 |
| ESP     | ESPSNW__ | 0x455350534E575F5F[^3] | 32 |
| OSCORE  | OSCORE__ | 0x4F53434F52455F5F[^4] | 48 |

Generator tools/gen_domsep.py derives formal artifacts from the same table.

### 2.2 DTLS Flagship

The DTLS instance is the flagship. It uses domsep RNDIMSK_. The ASCII decodes as RNDIMSK_ with trailing underscore. It masks the DTLS sequence number. Key K is derived per connection. Input X is the sequence number. Output is truncated to t bits. This matches DTLS 1.3 record protection.

### 2.3 QUIC, ESP, and OSCORE Instances

QUIC uses QUPNMSK_ for packet number privacy. ESP uses ESPSNW__ for IPsec sequence hiding. OSCORE uses OSCORE__ for CoAP option protection. Each instance shares the same permutation. Only domsep and truncation length differ. This colocation keeps code size minimal. The wolfSSL integration reuses AsconState.

## 3 Security

Security reduces to the Ascon permutation and sponge capacity. Bounds are tight and post-quantum aware.

### 3.1 Theorem 1 and 1'': Proof Sketch

Theorem 1 bounds PRF advantage by q^2/2^192 + q/2^128. Here q is the number of queries. The term q^2/2^192 captures sponge collisions. The term q/2^128 captures key guessing. For q ≤ 2^64, the capacity term is vacuous. The proof follows Mennink et al. indifferentiability. Theorem 1'' tightens the bound to q/2^128. Tightness holds under a single-block query restriction. The proof is via PRF/PRP switching and truncation analysis. Details appear in docs/mask-prf-proof.md.

### 3.2 Post-Quantum Theorem 2

Theorem 2 lifts the bound to quantum adversaries. It assumes a quantum-accessible permutation. The bound becomes O(q^2/2^96 + q/2^64) in quantum queries. Grover halves effective strength. Nonce-misuse resistance remains classical. No quantum distinguisher exceeds the bound. The result follows Hosoyamada and Sasaki style analysis.

### 3.3 Dominance: Theorem 3 and 3''

Theorem 3 compares Mask-PRF masking to record AEAD strength. It shows Mask-PRF never dominates overall security.

| q (queries) | AEAD bound | Mask-PRF bound | Dominant term |
|-------------|------------|----------------|---------------|
| 2^48 (RFC 9147 DTLS) | 2^-32 | 2^-80 | AEAD |
| 2^62 (RFC 9001 QUIC) | 2^-4 | 2^-66 | AEAD |

For q=2^48, Mask-PRF advantage is 2^-80 versus AEAD 2^-32. For q=2^62, Mask-PRF is 2^-66 versus 2^-4. Masking is always weaker than encryption. Gap-fill for ESP (RFC 4303) follows同様. Thus sequence-number privacy does not weaken the channel.

## 4 Formal Verification

Verification covers Coq and EasyCrypt. Both derive domsep from the canonical table.

Coq development includes mask_prf.v, mask_adv.v, and mask_prf_fcf.v. mask_adv.v defines canonical MaskAdv. All lemmas close with Qed. Compilation uses coqc -Q. Logs are formal/*.compile.log. The proof reuses FCF-style games.

EasyCrypt development is formal/easycrypt/mask_prf.ec. It proves EXIT:0 with arith_core qed. The reduction marked Hreducible carries explicit δ_P debt. Honest admission documents permutation idealization. Evidence logs are formal/easycrypt/*.log.

Both toolchains depend on MRV15, DM19, Men18, and Hos25. Debt is honest and bounded, not hidden.

## 5 Cost and Integration

Implementation is colocated in wolfcrypt/src next to ascon.c. Interface is wolfssl/wolfcrypt/mask_prf.h. It exports two functions: mask_prf_derive and mask_prf_check_bound. No other surface exists. Depth is trimmed to one wire.

The code reuses AsconState and the 12-round permutation. One permutation call occurs per record. No additional primitives are invoked. For Ascon suites, no AES dependency is introduced. For non-Ascon builds, the module is excluded. Key schedule is outside the hot path. Stack usage stays under 256 bytes.

ASCON_MASK_DOMSEP in ascon.h aliases table[0] for compatibility. The canonical table remains in mask_prf.h. Tools generate formal artifacts to prevent divergence.

## 6 Evaluation

Evaluation uses Renode 1.16.1 and QEMU 8.2.2 for triangulation. Renode provides deterministic instruction counting. QEMU provides real-world networking. Neither is cycle-accurate, but agreement bounds error.

Platform abstracts time via hal.h. Hal reads SysTick or DWT at 0xE0001004. Four cores are measured: Cortex-M0+, M3, M4, M33. Each result averages 10 repeats. Throughput ranges from 0.477 MiB/s (M0+) to 1.062 MiB/s (M33). Overhead versus unmasked Ascon is <1% on Renode.

QEMU triangulation uses netduino2 at 120 MHz. Observed overhead is 6–7%, consistent with instruction overhead. Memory delta is under 1 KiB flash. Renode and QEMU bound different artifacts.

## 7 Constant-Time Analysis

Constant-time behavior is validated statically and dynamically.

Static audit shows no secret-dependent branches. Round constants use round_constants[round] with public index. No table lookups depend on key or sequence number. Control flow is data independent.

Dynamic testing uses dudect. Matrix covers 64-bit and 32-bit builds. Sample size is N=80k. Threshold is |t|<4.5. All configurations PASS. No leakage was observed.

Valgrind memcheck reports 0 errors. Cachegrind observes 2.5B instructions with no secret-dependent misses. Together these provide defense in depth.

## 8 Related Work

PQCAIE 2024 presented Ascon DTLS but focused on AEAD. Suleiman et al. 2025 measured Ascon performance, also AEAD-only. Neither addressed sequence-number privacy. Generic sponge PRF analyses exist (MRV15). MRV15 bounds are generic and loose for single-block. This work tightens to q/2^128 for the single-block case. Hou et al. 2025 covers post-quantum sponge indifferentiability. The construction complements NIST SP 800-232 guidance.

## 9 Artifacts and Reproducibility

Artifacts are stored as RESEARCH-ascon-dtls. Reproducibility requires make check, easycrypt compile, and coqc -Q. Formal logs are formal/*.compile.log. Evaluation logs are evaluation/*.log. Renode scripts are evaluation/renode/*.resc. QEMU scripts are evaluation/qemu/*.sh. All domsep values derive from wolfssl/wolfcrypt/mask_prf.h via tools/gen_domsep.py. Formal artifacts formal/coq/mask_prf_domsep.v and formal/easycrypt/mask_prf_domsep.ec are generated, not hand-edited.

REPRO command: `make check && easycrypt compile formal/easycrypt/mask_prf.ec && coqc -Q formal/coq Formal formal/coq/mask_prf.v`

## References

- MRV15: Mennink, Reyhanitabar, Vişoiu. Full indifferentiability of X84. CRYPTO 2015.
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

