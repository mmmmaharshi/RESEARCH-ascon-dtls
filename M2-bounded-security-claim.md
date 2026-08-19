# M2 Gate Deliverable — Bounded Security Claim

**Project:** Ascon-AEAD128 as a DTLS 1.3 Ciphersuite for Constrained Endpoints
**Target suite:** TLS_ASCONAEAD128_ASCONHASH256 (IANA 0x006E)
**Status:** M2 gate — one-page claim (references design-01-record-layer.md §3–§6)

---

## 1. The claim (one sentence)

The ciphersuite 0x006E provides DTLS 1.3 record security that reduces to the
AEAD bounds of Ascon-AEAD128 (SP 800-232), with channel security argued in the
Robust Channels model, record numbers hidden per RFC 9147 §4.2.3 by a new
ciphertext-dependent keyed-sponge PRF, and key derivation via HKDF instantiated
with HMAC-Ascon-Hash256 — subject to the bounds and non-claims below.

## 2. Claims the paper proves

| # | Claim | Basis | Bound at usage limit |
|---|-------|-------|----------------------|
| C1 | AEAD confidentiality (privacy) | SP 800-232 bounds, applied | ≤ 2^-138 (2^48-1 records/key) |
| C2 | AEAD integrity (forgery) | SP 800-232 bounds, applied | ≤ 2^-80 (2^48 failures/key, protocol cap); reference impl enforces 2^16 → ≤ 2^-112 |
| C3 | Channel security (Robust Channels goals) | Paper proof, reduction to Ascon-AEAD128 + state-machine invariants | Same as C1/C2 |
| C4 | Record-number mask: PRF security + privacy | New construction §4.2.1, self-contained bound | ≤ q^2/2^192 + q/2^128, negligible to q ≈ 2^96 |
| C5 | Committing security (defense-in-depth) | KSW 2023/1525 (Krämer–Struck–Weishäupl, TOSC 2024, ePrint 2023/1525) prove unmodified Ascon-128 committing-secure at 64-bit (committing advantage ≤ 2^-64, birthday bound); one of only 3 finalists with a formal proof. Our usage (≤ 2^48 records/key) is 16 bits below this bound. Zero-padding caveat (Datta et al. 2026/1160) does NOT apply: those results target the committing zero-padding TRANSFORM on finalists; our nonce padding is the RFC 9147 64→128-bit nonce padding, a different mechanism | Applied, not derived |
| C6 | KDF soundness | HMAC-Ascon-Hash256 = RFC 2104 over sponge. Citation chain: HMAC PRF theorem (Bellare–Canetti–Krawczyk, CRYPTO 1996) + sponge indifferentiability from RO (Bertoni–Daemen–Peeters–Van Assche, EUROCRYPT 2008) + approval precedent: HMAC-SHA3 is NIST-approved (FIPS 198-1 + FIPS 202) | Structure identical to RFC 9846 |
| C7 | Mask PRF soundness | Keyed-sponge references for §4.2.1 Option B: Key Prediction Security of Keyed Sponges (Mennink, IACR ToSC 2018/449); Security of the Suffix Keyed Sponge (Dobraunig–Mennink, ToSC 2019/573); PQ extension: Hosoyamada 2025/1059 (keyed sponges incl. Ascon, quantum) | q^2/2^192 + q/2^128 |

## 3. Non-claims (explicit boundaries)

- No new AEAD theory — bounds applied from SP 800-232/KSW, not derived.
- No key-confirmation (3SHKE) fix — the committing property is defense-in-depth
  only; key-commitment fixes live in the handshake.
- No claim that the mask does anything beyond RFC 9147 §4.2.3's design goal.
- No forgery or privacy claims beyond the AEAD bounds.
- No claims for 0x006F / 0x0070 / 0x0071.
- No new hardware, no masking/SCA claims, no new handshake.

## 4. Security model

- Robust Channels (Fischlin–Günther–Janson, ePrint 2020/718): record layer
  under packet loss, reordering, replay-within-window, per-epoch keys.
- RFC 9147 adversarial setting; retransmission reuse of (key, nonce) is safe
  and required (§4.2).
- Ideal-permutation assumption on Ascon-P (as assumed by SP 800-232 and Ascon
  v1.2); keyed-sponge PRF assumption for the mask; sponge-HMAC PRF assumption
  for HKDF (cited).
- Usage limits of §4.3 are protocol-set (non-binding for Ascon); implementation
  MUST count failed authentications per key and key-update per RFC 9846 §5.5/§4.7.3.
  The reference implementation enforces the stricter wolfSSL defaults 2^16 hard /
  2^15 key-update (`DTLS_AEAD_ASCON_FAIL_LIMIT` / `DTLS_AEAD_ASCON_FAIL_KU_LIMIT`),
  giving cumulative forgery ≤ 2^-112; 2^48 remains the protocol maximum.

## 5. Verification status (all three items closed)

 1. **KSW committing bound — CLOSED.** Krämer–Struck–Weishäupl (TOSC 2024,
    ePrint 2023/1525) prove unmodified Ascon-128 committing-secure at 64-bit
    (committing advantage ≤ 2^-64, birthday bound). Our usage (2^48 records/key)
    is 16 bits below this bound, so the claim is robust.
   Zero-padding attack results (Datta et al. 2026/1160, KSW §4) do not apply:
   they attack the committing zero-padding transform, not RFC 9147 nonce padding.
 2. **Robust Channels record-layer reduction — CLOSED (re-derived).** No
    companion artifacts (model/scripts/repo) are published with ePrint 2020/718,
    so the instantiate-and-use reduction for Ascon-AEAD128 is re-derived
    directly in the proof section: channel security reduces to Ascon-AEAD128's
    IND-CPA/INT-CTXT (C1/C2); DTLS 1.3's unique (epoch, record_number) nonce
    (RFC 9147 §4.2.3) plus the usage-limit KeyUpdate (RFC 9846 §4.7.3) give
    nonce uniqueness with no extra game hops, so C3 inherits C1/C2. Authors may
    be contacted for scripts if executable evidence is later required.
3. **Sponge-HMAC citation — CLOSED.** Chain: BCK96 (CRYPTO 1996) + sponge
   indifferentiability (Bertoni et al., EUROCRYPT 2008) + FIPS 198-1/202
   approval precedent. Keyed-sponge citations for the mask: Mennink ToSC
   2018/449, Dobraunig–Mennink ToSC 2019/573, Hosoyamada 2025/1059 (PQ).

## 6. One-sentence abstract version

"TLS_ASCONAEAD128_ASCONHASH256 provides DTLS 1.3 record security reducing to
the SP 800-232 Ascon-AEAD128 bounds, with a new ciphertext-dependent
record-number mask secure up to 2^96 records and HKDF on HMAC-Ascon-Hash256,
together with the first constrained-device evaluation of Ascon-based TLS suites."
