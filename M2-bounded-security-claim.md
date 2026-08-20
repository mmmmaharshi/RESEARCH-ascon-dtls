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
| C3 | Channel security (Robust Channels goals: ROB-INT-IND-CCA) | Precondition-verification + explicit Ascon-specific game-hop reduction (`robust-channels-game-hop.md`) built on [FGJ20, Thms 7.1 & 7.2 (via Prop. 5.9), §7 DTLS 1.3 analysis] given C1/C2 | ≤ Adv^{IND-CPA}_AEAD + Adv^{INT-CTXT}_AEAD(q_R) (non-tight: Adv^{INT-CTXT}_AEAD(q_R) ≤ q_R·Adv^{INT-CTXT}_AEAD(1), q_R=2^16 enforced forgery attempts) |
| C4 | Record-number mask: PRF security + privacy | New construction §4.2.1, self-contained bound (derived in design-01 §4.2.1); sn_key is HKDF-PRF-independent from the AEAD key — same traffic secret, distinct label, `≤ Adv^{PRF}_{HMAC-Ascon-Hash256}` (design-01 §4.2.1) | ≤ q^2/2^192 + q/2^128, negligible to q ≈ 2^96 |
| C5 | Committing security (defense-in-depth) | KSW 2023/1525 (Krämer–Struck–Weishäupl, TOSC 2024, ePrint 2023/1525) prove unmodified Ascon-128 committing-secure at 64-bit (committing advantage ≤ 2^-64, birthday bound); one of only 3 finalists with a formal proof. Our usage (≤ 2^48 records/key) is 16 bits below this bound. Zero-padding caveat (Datta et al. 2026/1160) does NOT apply: those results target the committing zero-padding TRANSFORM on finalists; our nonce padding is the RFC 9147 64→128-bit nonce padding, a different mechanism | Applied, not derived |
| C6 | KDF soundness | HMAC-Ascon-Hash256 = RFC 2104 over sponge. Citation chain: HMAC PRF theorem (Bellare–Canetti–Krawczyk, CRYPTO 1996) + sponge indifferentiability from RO (Bertoni–Daemen–Peeters–Van Assche, EUROCRYPT 2008) + approval precedent: HMAC-SHA3 is NIST-approved (FIPS 198-1 + FIPS 202) | Structure identical to RFC 9846 |
| C7 | Mask PRF soundness | Keyed-sponge references for §4.2.1 Option B: Key Prediction Security of Keyed Sponges (Mennink, IACR ToSC 2018/449); Security of the Suffix Keyed Sponge (Dobraunig–Mennink, ToSC 2019/573); PQ extension: Hosoyamada 2025/1059 (keyed sponges incl. Ascon, quantum) | q^2/2^192 + q/2^128 (derived in design-01 §4.2.1) |
| C8 | PSK mode & parameters specified | External PSK (RFC 9147 §5.1), `psk_ke` primary (256-bit key, identity `Client_identity`), `psk_dhe_ke` also interoperated; binder over HMAC-Ascon-Hash256 | Stated (design-01 §4.1); not a security claim |

## 3. Non-claims (explicit boundaries)

- No new AEAD theory — bounds applied from SP 800-232/KSW, not derived.
- No key-confirmation (3SHKE) fix — the committing property is defense-in-depth
  only; key-commitment fixes live in the handshake.
- No claim that the mask does anything beyond RFC 9147 §4.2.3's design goal.
- No forgery or privacy claims beyond the AEAD bounds.
- No claims for 0x006F / 0x0070 / 0x0071.
- No new hardware, no masking/SCA claims, no new handshake.

## 4. Security model

- Robust Channels (Fischlin–Günther–Janson, ePrint 2020/718; Journal of Cryptology 2024 — robust-CCA theorem, §7 DTLS 1.3 analysis): record layer
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
   2. **Robust Channels channel security — VERIFIED (precondition check + explicit Ascon-specific game-hop reduction in `robust-channels-game-hop.md`; FGJ20's generic channel proof is cited, not re-derived).** Fischlin–Günther–Janson (ePrint 2020/718; Journal of
    Cryptology 2024, §7 DTLS 1.3 analysis) prove DTLS 1.3 is ROB-INT-IND-CCA-
    secure from any IND-CPA + INT-CTXT AEAD, via Theorems 7.1 (robust
    integrity: Adv^{ROB-INT} ≤ Adv^{INT-CTXT}_AEAD(q_R)) and 7.2 (IND-CPA:
    Adv^{IND-CPA}_Ch ≤ Adv^{IND-CPA}_AEAD), combined by Proposition 5.9:
        Adv^{ROB-INT-IND-CCA}(Ch) ≤ Adv^{IND-CPA}_AEAD
                                 + Adv^{INT-CTXT}_AEAD(q_R)
    where q_R = tolerated forgery attempts (failed-auth limit), and
    Adv^{INT-CTXT}_AEAD(q_R) ≤ q_R · Adv^{INT-CTXT}_AEAD(1) is the non-tight
    linear loss. We verify the preconditions hold for our record layer: (i)
    Ascon-AEAD128 is IND-CPA + INT-CTXT (= C1/C2); (ii) DTLS 1.3 packs a unique
    (epoch, record_number) into a 128-bit nonce (RFC 9147 §4.2.3), no reuse;
    (iii) monotonic sequence numbers give sound anti-replay (§4.2); (iv)
    failed-authentication KeyUpdate (RFC 9846 §4.7.3, enforced 2^16) bounds q_R.
    Plugging C1/C2 gives ≤ 2^-138 (C1) + 2^-112 (enforced q_R = 2^16). The
    q_R term is the linear robustness degradation R3 requires us to surface;
    C3 is therefore NOT bounded by C1/C2 alone.
3. **Sponge-HMAC citation — CLOSED.** Chain: BCK96 (CRYPTO 1996) + sponge
   indifferentiability (Bertoni et al., EUROCRYPT 2008) + FIPS 198-1/202
   approval precedent. Keyed-sponge citations for the mask: Mennink ToSC
   2018/449, Dobraunig–Mennink ToSC 2019/573, Hosoyamada 2025/1059 (PQ).

## 6. One-sentence abstract version

"TLS_ASCONAEAD128_ASCONHASH256 provides DTLS 1.3 record security reducing to
the SP 800-232 Ascon-AEAD128 bounds, with a new ciphertext-dependent
record-number mask secure up to 2^96 records and HKDF on HMAC-Ascon-Hash256,
together with the first constrained-device evaluation of Ascon-based TLS suites."
