# Novelty Check — Ascon DTLS 1.3 Record Layer (as of 2026-08-22)

## Verdict

**Novelty holds**, with one mandatory repositioning: IANA has since assigned
`0x00,0x6E` (`TLS_ASCONAEAD128_ASCONHASH256`, DTLS-OK=Y, Recommended=N,
reference = NIST SP 800-232 alone). The paper can no longer frame the suite
ID itself as its contribution — it must claim **first complete
specification, first implementation, and first bounded-security argument**
for an already-assigned-but-unspecified suite.

## What exists upstream

| Artifact | Status | Impact |
|---|---|---|
| IANA registry | 0x6E–0x71 Ascon suites registered (0x6F ASCONAEAD128_SHA256, 0x70 AES-GCM_ASCONHASH256, 0x71 AES-CCM_ASCONHASH256); last three cite SP 800-232 + RFC 9846 | Suite IDs taken; cite, don't claim |
| RFC 9846 (TLS 1.3, Jul 2026, obsoletes RFC 8446) | Appendix B.4 defines ONLY the classic five {0x13,01..05}. Ascon suites are NOT normatively specified anywhere public | **Gap = the paper's contribution**: no published HKDF/HMAC-over-Ascon-Hash256 key-schedule mapping exists |
| wolfSSL 5.8.0+ (PR 8307) | Ascon-AEAD128 + Ascon-Hash256 wolfCrypt primitives only; no cipher suite; issue #7050 confirms users cannot do TLS with it | C1 "first TLS suite in mainstream library" still valid |
| OpenSSL / Mbed TLS / picotls | No Ascon suites (picotls ships AEGIS-128L/256 via libaegis instead) | First-mover intact |

## Academic prior art — closest neighbors

1. **Mansoor et al., PQCAIE 2024** (Internet of Things 27:101228) — closest;
   not a DTLS-integrated suite with proofs.
2. **Suleiman & Javeed 2025** (Springer IMS) — Ascon over CoAP *compared
   against* DTLS, not integrated into it.
3. **Bhargavan et al., Everest** (IEEE S&P 2017) — verified TLS 1.3 record
   layer in F\*; methodological ancestor only.
4. **Kaur et al. survey** (ACM Comput. Surv., Jun 2025); CT-RSA 2025 Ascon
   key-recovery attacks — context/citations, not competitors.

**No 2025–2026 paper integrates Ascon into the (D)TLS record layer with a
security proof. Searches across IEEE, Springer, arXiv, IETF found none.**

## Mask-PRF gap is real and open

RFC 9147 §4.2.3 mandates: *"Future cipher suites, which are not based on AES
or ChaCha20, MUST define their own record sequence number encryption."*
No sponge/Ascon-based sequence-number mask proposal exists in literature or
drafts (only AES-ECB and ChaCha20 masks). The Mask-PRF primitive +
tight reduction + dominance theorems remain unclaimed territory. dudect
side-channel evaluation of a mask construction has no precedent either.

## Ecosystem tailwind (timeliness argument)

IEEE P802.1AEef MACsec Ascon amendment (D1.2 Jun 2026),
draft-ochkas-cose-ascon-04, ACVP Ascon spec (incl. nonce-masking mode),
NIST SP 800-232 final Aug 2025 — all adopt Ascon outside TLS/DTLS records.
None compete; all support "the time is now."

## Required changes to paper/00-outline.md

Applied in commit b71f3e2:

1. ✅ Reframe C1: ~~first to define/request 0x006E~~ → **first end-to-end
   realization** (normative design + implementation + interop + proofs) of
   the IANA-assigned-but-unspecified 0x006E.
2. ✅ Add Related Work entries: IANA 0x6E–0x71 registrations, RFC 9846
   (obsoletes 8446 — update all references), wolfSSL 5.8.0 primitives-only
   status, P802.1AEef, COSE/ACVP drafts.
3. ✅ State explicitly that RFC 9846 App. B.4 omits Ascon suites and that this
   document supplies the missing record-protection specification
   (key schedule, HKDF-over-Ascon-Hash256 mapping, RFC 9147 §4.5.3 AEAD limits).
4. ✅ Address the "Recommended=N" caveat: registry marks 0x6E not recommended —
   address why (no IETF consensus yet) and position the paper as evidence base.
