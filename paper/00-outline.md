# DTLS 1.3 + Ascon AEAD — Paper Outline

**Status:** skeleton / source-map. Content is assembled from the existing repo docs.
**Open decisions (BLOCKING before final drafting):** target venue + page/word budget + format (LaTeX vs Markdown).

## Proposed structure (standard applied-crypto paper)

1. **Abstract** — what we did: we present an **open, reproducible implementation** of `TLS_AEAD_WITH_ASCON_128` (0x006E) as a DTLS 1.3 record-protection suite in wolfSSL, with a masked sequence number, validated by cross-stack TLS 1.3 interop with OpenSSL 3.6.3 and picotls (AEAD + key schedule) and self-checking KAT vectors, with DTLS 1.3 interop exercised wolfSSL↔wolfSSL (cross-stack DTLS 1.3 interop is out of scope); plus an evaluation on embedded targets, a bounded-security argument, and a **side-channel constant-time analysis of the new mask**. To our knowledge this is the first implementation of the 0x006E suite in a mainstream TLS library, and the first with a bounded-security argument + mask side-channel analysis (earlier Ascon-in-(D)TLS prototypes — PQCAIE 2024; Suleiman & Javeed 2025 — did not include security analysis). This is an **implementation + evaluation + bounded-security-argument paper** — Ascon-128 is a standardized primitive (FIPS 202 / SP 800-232); the only new crypto is the **Mask-PRF** primitive (single-call keyed-sponge PRF, §3.2), not a new AEAD. **Positioning vs the registry (novelty check 2026-08):** IANA has already assigned `0x00,0x6E` (`TLS_ASCONAEAD128_ASCONHASH256`, DTLS-OK=Y, Recommended=N) citing SP 800-232 alone, plus 0x6F–0x71; however RFC 9846 Appendix B.4 defines only the classic five {0x13,01..05} suites and no public document specifies the Ascon suites' key schedule, HKDF-over-Ascon-Hash256 mapping, or RFC 9147 §4.5.3 AEAD limits. We therefore claim the **first end-to-end realization** (normative record-protection design + implementation + interop + security argument) of an IANA-assigned-but-unspecified suite — not the assignment itself.
2. **1. Introduction** — motivation (IoT/constrained DTLS 1.3), gap (TLS 1.3 lacks a CAESAR-assembled AEAD; Ascon is the LWC winner: SP 800-232 finalized Aug 2025, IANA assigned Ascon-based suites 0x6E–0x71, wolfSSL ships wolfCrypt primitives only since 5.8.0 (PR 8307) with no cipher suite — issue #7050 — and ecosystem adoption is accelerating outside TLS/DTLS: IEEE P802.1AEef MACsec-Ascon amendment, draft-ochkas-cose-ascon, ACVP Ascon spec; yet no normative record-layer spec or implementation exists), contributions.
   - **Contribution class (R11):** this is an *implementation + evaluation + bounded-security-argument* paper. Ascon-128 is a standardized primitive (FIPS 202 / SP 800-232); we propose **no new cryptographic construction**. Our contributions:
      - **(C1) Implementation** — an open wolfSSL DTLS 1.3 0x006E suite + masked-sequence-number record layer — the **first end-to-end realization** of the IANA-assigned-but-unspecified suite in a mainstream TLS library (upstream wolfSSL ≥5.8.0 provides Ascon wolfCrypt primitives only, no TLS integration; earlier Ascon-in-(D)TLS prototypes — PQCAIE 2024; Suleiman & Javeed 2025 — lacked security analysis); cross-stack **TLS 1.3** interop with OpenSSL 3.6.3 (AEAD + key schedule) and picotls; DTLS 1.3 interop exercised wolfSSL↔wolfSSL (cross-stack DTLS 1.3 interop out of scope); committed self-checking KAT vectors.
      - **(C2) Evaluation** — Renode-emulated Cortex-M0+/M3 throughput, footprint vs ChaCha20-Poly1305 / AES-GCM, per-record cycle costs, plus a **side-channel constant-time analysis of the mask path** (static data-oblivious audit + `dudect` Welch t-test on `wc_AsconAEAD128_Mask` with fixed-vs-random `ct` and fixed-vs-random `sn_key`, `N=80k`, `|t|<4.5`, control passes — `side-channel-constant-time.md`, `tools/ascon_mask_dudect.c` + log).
        - **(C3) Bounded-security argument + a NEW primitive: Mask-PRF** — a general-purpose single-call keyed-sponge PRF `trunc_t(P(domsep‖K‖X))` with a standalone tight proof (`mask-prf-proof.md`: §0 primitive claim; Thm 1/1′ classical for *any* single-block fixed-capacity instance, Thm 2 PQ, Thm 3 dominance over the RFC 9147 §4.2.3 AES-ECB mask, Thm 3′ dominance over the RFC 9001 §5.4.4 QUIC packet-number mask at the 2^62 cap); DTLS record-number masking is the flagship instance (ESP seq-hiding / OSCORE Partial-IV as further applications); plus M2 bounds + Robust-Channels game-hop + a Tamarin model (protocol-level sequence-number privacy under the symbolic PRF assumption; the mask's cryptographic soundness is the §4.2.1 / `mask-prf-proof.md` analytic result, not a Tamarin verification).
    - Honesty/claim boundaries: Mask-PRF *is* a new construction at the primitive level (Thm 1′ applies to any single-block fixed-capacity instance, not only DTLS); what we do NOT claim is new AEAD theory (design-01-record-layer.md §6). The masked-sequence-number wire format itself remains an instantiation choice of the primitive.
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
     - 5.5 Side-channel constant-time (mask path) — static audit (permutation is arithmetic-only, fixed 12 rounds, no data-indexed tables) + dudect on `wc_AsconAEAD128_Mask` (A: fixed-`ct` vs random-`ct`, B: fixed-`key` vs random-`key`, C: random-vs-random control; `|t|<4.5` at `p100/p99/p90`, `N=80k`, 8 rounds, all `ok`) — src: `side-channel-constant-time.md`, `tools/ascon_mask_dudect.c`, `tools/ascon_mask_dudect.log`.
7. **6. Related work** — DTLS 1.3; TLS 1.3 spec lineage (RFC 9846 obsoletes 8446/5246 etc., July 2026 — Appendix B.4 defines only {0x13,01..05}; Ascon suites 0x6E–0x71 exist in the IANA registry via Specification Required citing SP 800-232, with no normative text anywhere: this paper supplies it); registry caveat: 0x006E is marked Recommended=N (no IETF consensus yet) — this paper is positioned as the evidence base for adoption; lightweight TLS (e.g., TLS 1.3 over OSCORE/EDHOC, tinyDTLS, Ascon-in-TLS drafts); prior Ascon-in-(D)TLS prototypes (PQCAIE 2024 — Ascon in the TLS record layer, no security analysis; Suleiman & Javeed 2025 — Ascon replaces DTLS) contrasted with this work's bounded-security argument; masked sequence numbers (past proposals); Ascon ecosystem outside TLS/DTLS: wolfSSL 5.8.0 primitives-only (PR 8307, issue #7050), IEEE P802.1AEef MACsec-Ascon amendment (D1.2 Jun 2026), draft-ochkas-cose-ascon-04, ACVP Ascon JSON spec (draft-ross-acvp-ascon), AEGIS TLS suites (draft-denis-tls-aegis) as the closest non-AEAD-suite precedent for non-{AES,ChaCha} suites.

   **Related-work contrast table** (draft for §6; cells marked † = not present in
   the cited paper per our reading — re-verify against the final PDFs before
   submission):

   | Axis | PQCAIE 2024 (Mansoor et al., *Internet of Things* 27:101228) | Suleiman & Javeed 2025 (Ascon-over-CoAP vs DTLS, Springer IMS) | **This work** |
   |---|---|---|---|
   | **Cross-stack interop** | None reported† — single-stack performance/security comparison of PQC authentication schemes over TLS 1.3 | None by design — Ascon is applied at the CoAP application layer and *compared against* DTLS, not integrated into it; no peer interoperates | wolfSSL↔OpenSSL 3.6.3 (patched) and wolfSSL↔picotls over TLS 1.3 (AEAD + key schedule, PSK `psk_ke`/`psk_dhe_ke`, X.509 both directions); DTLS 1.3 wolfSSL↔wolfSSL plus independent Wireshark dissection and RFC 9147 §4 conformance check on captured wire bytes |
    | **Security argument** | Empirical only (performance + qualitative security discussion); no reduction or bound† | Empirical attack-resistance observations (MITM/replay scenarios) + latency/energy results; no proof† | Bounded-security claim (M2) reducing record security to Ascon-AEAD128/Hash256 assumptions with concrete AEAD usage limits; standalone tight Mask-PRF proof (generic `trunc_t(P(domsep‖K‖X))`, Thm 1′ for any single-block instance, PQ variant, Thm 3 vs RFC 9147 + Thm 3′ vs QUIC RFC 9001 at 2^62 cap) — Table 1 domsep assignments make QUIC/ESP instantiations concrete |
    | **Formal model** | None† | None† | Tamarin symbolic model (8 lemmas: secrecy + sequence-number privacy under a symbolic PRF assumption); Coq/Rocq mechanization of the mask-PRF hybrid sum, FCF game-hop core (`averaging`/`dup_event_bound` in `mask_prf_fcf.v`), and robust-channels bounds (`tools/coq/`), EasyCrypt `compile EXIT:0` (`arith_core`/`mask_dominates_rfc` qed; Hop2 gap 0 axiom in EC, proven in Coq) |
    | **Embedded eval** | IoT e-health context, but no constrained-device benchmark reported† | Yes — Orange Pi Zero 2 W SBC testbed: handshake latency (−65% vs DTLS) and energy (−12.2%) | Cortex-M0+/M3 via Renode emulation: per-record cycle costs and .text footprint vs ChaCha20-Poly1305 / AES-GCM (explicitly framed as emulation-based feasibility numbers; silicon is future work) + static + dudect timing of mask path (data-oblivious audit, `N=80k` Welch `|t|<4.5`) — none for prior works† |

   Gap in one glance: prior Ascon-in-(D)TLS-adjacent prototypes are either
   application-layer substitutions (Suleiman & Javeed) or PQC-authentication
   comparisons (PQCAIE) with empirical evaluation only; none integrates Ascon as
   an RFC 9147 record-protection suite inside a mainstream TLS library, none
   interoperates across stacks at the protocol surface, and none carries a
   security argument beyond benchmarking. The IANA 0x6E–0x71 assignments
   (2026-08 registry) confirm the slot is reserved but empty: RFC 9846 App. B.4
   omits them and no public spec text exists — this paper fills exactly that gap.
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
