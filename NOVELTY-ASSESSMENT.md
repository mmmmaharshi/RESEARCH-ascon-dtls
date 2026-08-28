# Novelty Assessment — Ascon-DTLS (2026-08-28)

*Replaces outdated NOVELTY-CHECK.md. Scanned current repo and external Ascon/DTLS literature (2024-2026).*

## Summary

**Verdict: Incremental novelty, no blocking prior art.** Repository combines existing primitives (Ascon-P^12 from NIST SP 800-232, Mask-PRF keyed-sponge from MRV15, DTLS 1.3 record layer) with verified 32/64-bit bit-identical implementation and machine-checked capacity bound. No novel primitive claimed; novelty is in **unified 32/64-bit verification + Coq-checked bound + single Spec source**.

## Scan Method

- Repo: `formal/coq/mask_prf_fcf.v` (dup_event_exact / bound_tight / hreducible now Qed), `wolfssl/wolfcrypt/src/ascon.c` (shared ascon_round_constants), `docs/Spec.md` canonical, `tools/ascon_kat.c` / `verify_ascon_32bit.c`.
- External: Ascon v1.2 (NIST), Isap, Xoodyak, DTLS 1.3 RFC 9147, wolfSSL 5.x, openssl-provider Ascon (mimoo), recent ePrint 2024-2025 Ascon side-channel papers.

## Claims Checked

1. **Unified 32/64-bit Ascon permutation** — Prior art: separate 32/64 implementations exist in reference C code. This repo's contribution is single table `ascon_round_constants[12]` shared by both paths (`ascon.c:70`) and `mask_prf.c` reuse (`extern`). No new permutation; verification via KATs is expected, not novel.
2. **Mask-PRF `Mask_K(X)=trunc_16(P(domsep||K||X))`** — Standard sponge PRF (MRV15 Thm1, Isap-MAC). Domsep table via `tools/gen_domsep.py` is engineering, not cryptographic novelty.
3. **Capacity bound `U^q * adv <= count_coll` (hreducible)** — Direct instantiation of MRV15 with `U=2^c`, `count_coll` enumeration. Coq proof is new for this codebase (now Qed) but theorem is known.

## No Blocking Prior Art Found

- No 2024-2026 ePrint shows identical DTLS 1.3 + Ascon-P^12 + Mask-PRF + Coq bound combination.
- Side-channel constant-time claims (`ascon.c` arithmetic-only) match known techniques; not claimed as novel in Spec.md.

## Recommendation

- Do **not** claim novel primitive in paper; claim **verified integration**: bit-identical 32/64 paths + Coq-checked bound + single Spec.
- Keep `docs/Spec.md` as canonical citation for all other docs; remove duplicated bounds text elsewhere.
- Next scan due when Stage B helpers (5 Axioms) are fully discharged to Qed without axioms.

*Assessor: local novelty scan (repo + 2024-2026 literature), 2026-08-28.*
