# DTLS 1.3 + Ascon AEAD — Paper Outline

**Status:** skeleton / source-map. Content is assembled from the existing repo docs.
**Open decisions (BLOCKING before final drafting):** target venue + page/word budget + format (LaTeX vs Markdown).

## Proposed structure (standard applied-crypto paper)

1. **Abstract** — what we did: we present an **open, reproducible implementation** of `TLS_AEAD_WITH_ASCON_128` (0x006E) as a DTLS 1.3 record-protection suite in wolfSSL, with a masked sequence number, validated by cross-stack TLS 1.3 interop with OpenSSL 3.6.3 and picotls (AEAD + key schedule) and self-checking KAT vectors, with DTLS 1.3 interop exercised wolfSSL↔wolfSSL (cross-stack DTLS 1.3 interop is out of scope); plus an evaluation on embedded targets and a bounded-security argument. To our knowledge this is the first implementation of the 0x006E suite in a mainstream TLS library, and the first with a bounded-security argument (earlier Ascon-in-(D)TLS prototypes — PQCAIE 2024; Suleiman & Javeed 2025 — did not include security analysis). This is an **implementation + evaluation + bounded-security-argument paper** — Ascon-128 is a standardized primitive (FIPS 202 / SP 800-232); we propose no new cryptography.
2. **1. Introduction** — motivation (IoT/constrained DTLS 1.3), gap (TLS 1.3 lacks a CAESAR-assembled AEAD; Ascon is the LWC winner but not in TLS), contributions.
   - **Contribution class (R11):** this is an *implementation + evaluation + bounded-security-argument* paper. Ascon-128 is a standardized primitive (FIPS 202 / SP 800-232); we propose **no new cryptographic construction**. Our contributions:
      - **(C1) Implementation** — an open wolfSSL DTLS 1.3 0x006E suite + masked-sequence-number record layer (to our knowledge the first such suite in a mainstream TLS library; earlier Ascon-in-(D)TLS prototypes — PQCAIE 2024; Suleiman & Javeed 2025 — lacked security analysis); cross-stack **TLS 1.3** interop with OpenSSL 3.6.3 (AEAD + key schedule) and picotls; DTLS 1.3 interop exercised wolfSSL↔wolfSSL (cross-stack DTLS 1.3 interop out of scope); committed self-checking KAT vectors.
     - **(C2) Evaluation** — Renode-emulated Cortex-M0+/M3 throughput, footprint vs ChaCha20-Poly1305 / AES-GCM, per-record cycle costs.
       - **(C3) Bounded-security argument + a NEW mask construction** — standalone, tight PRF proof of the keyed-sponge record-number mask (`mask-prf-proof.md`: Thm 1/1′ classical, Thm 2 PQ, Thm 3 dominance over the RFC 9147 §4.2.3 AES-ECB mask); plus M2 bounds + Robust-Channels game-hop + a Tamarin model (protocol-level sequence-number privacy under the symbolic PRF assumption; the mask's cryptographic soundness is the §4.2.1 / `mask-prf-proof.md` analytic result, not a Tamarin verification).
   - The masked sequence number is a *design* contribution (reuse of `sn_key` for anti-replay), an instantiation choice — not a new construction. Honesty/claim boundaries: design-01-record-layer.md §6 ("Claims NOT made = no new AEAD theory").
3. **2. Background** — DTLS 1.3 (RFC 9147) + TLS 1.3 key schedule (RFC 9846, obsoletes 8446); Ascon-128 AEAD; the sequence-number / nonce-reuse problem.
4. **3. Design: 0x006E record layer**
   - 3.1 Key schedule (HKDF-Extract/Expand-Label over HMAC-Ascon-Hash256; labels unchanged) — src: `design-01-record-layer.md` §4.1, §5.
    - 3.2 Record format + masked sequence number (XOR-PRFe with sn_key; recovers epoch alignment) — src: `design-01-record-layer.md` §4.2, §4.2.1; standalone PRF proof: `mask-prf-proof.md`.
   - 3.3 AEAD usage (wc_AsconAEAD128, DTLS 1.3 nonce = iv XOR seq) — src: `design-01-record-layer.md` §4.2.2, `tools/ascon_record_kat.txt`.
5. **4. Security analysis**
   - 4.1 Bounded-security claim (M2) + usage-limit accounting + forced KeyUpdate — src: `M2-bounded-security-claim.md`.
   - 4.2 Robust-channels game-hop (authentication / forgery / replay under bounded queries) — src: `robust-channels-game-hop.md`.
     - 4.2a Arithmetic-core mechanization (Coq/Rocq: the hybrid sum + Prop. 5.9 composition + concrete enforced/protocol-max bounds + KeyUpdate load-bearing + mask no-cross-term; no `Admitted`; the probability-theory game-hops are stated hypotheses) — src: `tools/coq/robust_channels.v`, `robust-channels-game-hop.md` §"Mechanization status".
     - 4.3 Symbolic model (Tamarin: 8 lemmas — secrecy + sequence-number privacy under the PRF assumption; cryptographic soundness of the mask is §4.2.1 / `mask-prf-proof.md`, not verified by Tamarin) — src: `tools/tamarin/dtls13-ascon-record.spthy`, `tools/tamarin/README.md`, `design-01-record-layer.md` §129.
 6. **5. Implementation & Evaluation**  *(R9: explicitly frame all numbers as **emulation-based feasibility / cycle estimates**, NOT silicon measurements — see `renode-benchmark-results.md` / `footprint-benchmark.md` caveats. Real-hardware Q4 is future work.)*
    - 5.1 wolfSSL 0x006E DTLS 1.3 implementation (PSK + X.509) — src: `dtls13-ascon-validation.md` §11, `T1-final-research-report.md`.
    - 5.2 Renode throughput / per-record cycles (Cortex-M0+/M3, **emulated**) — src: `renode-benchmark-results.md`.
    - 5.3 Footprint (.text sizes real; cycle figures emulated) vs ChaCha20-Poly1305 / AES-GCM — src: `footprint-benchmark.md`.
    - 5.4 Self-checking vectors (KAT) — src: `tools/ascon_record_kat.txt`, `dtls13-ascon-validation.md` §4.2.1–4.2.2.
7. **6. Related work** — DTLS 1.3; lightweight TLS (e.g., TLS 1.3 over OSCORE/EDHOC, tinyDTLS, Ascon-in-TLS drafts); prior Ascon-in-(D)TLS prototypes (PQCAIE 2024 — Ascon in the TLS record layer, no security analysis; Suleiman & Javeed 2025 — Ascon replaces DTLS) contrasted with this work's bounded-security argument; masked sequence numbers (past proposals).
8. **7. Conclusion + future work** (real-hardware Q4: RP2040 vs ESP32-C3; ARM-optimized Ascon permutation).
9. **Appendix** — full record AEAD test vectors.

## Source-doc inventory (repo root)
- `design-01-record-layer.md` — record-layer design (key schedule, masked seq, AEAD).
- `M2-bounded-security-claim.md` — bounded-security claim.
- `robust-channels-game-hop.md` — game-hop authentication proof.
- `dtls13-ascon-validation.md` — validation + interop + KAT sections.
- `T1-final-research-report.md` — research report (impl status, benchmarks summary).
- `renode-benchmark-results.md`, `footprint-benchmark.md` — benchmarks.
- `tools/tamarin/` — Tamarin model + README.
- `tools/ascon_record_kat.txt` — committed AEAD vectors.

## Next step
Confirm **venue** (e.g., ACM CCS / NDSS / a lightweight-crypto workshop / preprint), **length** (page budget), and **format** (LaTeX `.tex` vs Markdown `.md`). Then flesh out §1–§7.
