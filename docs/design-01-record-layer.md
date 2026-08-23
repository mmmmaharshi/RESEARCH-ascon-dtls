# Design Document 01 — Ascon-AEAD128 in the DTLS 1.3 Record Layer

**Project:** First implementation, security analysis, and constrained-device benchmark of the IANA-registered Ascon DTLS 1.3 ciphersuites.

**Status:** Phase 1 complete — §3 (suite selection), §4.1 (KDF/HMAC), §4.2 (nonce), §4.2.1 (mask), §4.3 (usage limits), §6 (formal targets) resolved. KSW bound (64-bit, ePrint 2023/1525) verified; Robust Channels channel security verified by precondition check citing FGJ20 robust-CCA theorem (bound not equal to C1/C2); sponge-HMAC citation closed.

---

## 1. Scope

- Target: `TLS_ASCONAEAD128_ASCONHASH256` (IANA code 0x006E, DTLS-OK = Y) in DTLS 1.3 (RFC 9147) record protection.
- Out of scope: handshake redesign, new registry registrations, QUIC, COSE, hardware.
- Deliverable: a design proposal + security argument + evaluation, publishable as a paper and a future IETF individual draft.

## 2. Background

- Ascon-AEAD128: NIST SP 800-232 (final, 2025-08-13). 128-bit nonce, 128-bit key, 128-bit tag.
- DTLS 1.3 record layer: RFC 9147. Uses TLS 1.3 AEAD construction: `nonce = fixed_iv XOR zero-padded(seq_num)`.
- IANA registry (updated 2026-08-10) lists four Ascon suites; all DTLS-OK = Y:
  - 0x006E `TLS_ASCONAEAD128_ASCONHASH256`  <- target
  - 0x006F `TLS_ASCONAEAD128_SHA256`
  - 0x0070 `TLS_AES_128_GCM_ASCONHASH256`
  - 0x0071 `TLS_AES_128_CCM_ASCONHASH256`
- No implementation exists in mbedTLS, tinydtls, wolfSSL (primitives only), or OpenSSL (unmerged PRs).
- Closest work: draft-ochkas-cose-ascon-04 (COSE layer), draft-denis-tls-aegis-06 (AEGIS ciphersuite draft — the process template), Suleiman & Javeed 2025 (Ascon replaces DTLS), PQCAIE 2024 (Ascon in TLS record layer, no analysis).

## 3. Ciphersuite selection

- **Resolved:** Target 0x006E. Rationale: it is the only suite with Ascon for BOTH the AEAD and the hash — fully self-contained, no AES/CCM dependency, and its record-number encryption (RFC 9147 §4.2.3) is a pure-Ascon design problem. 0x006F (SHA-256 KDF) is a variant that reuses standard SHA-256 for the handshake and is worth one paragraph of comparison, not implementation.
- **Resolved:** 0x0070/0x0071 (AES AEAD + Ascon hash) are out of scope — one line in the paper noting they exist and are orthogonal.

## 4. Record layer integration

### 4.1 Key schedule (HKDF with Ascon-Hash256) — RESOLVED (Phase 1)

- **Base spec:** RFC 9846 (TLS 1.3 bis, 2026-07; obsoletes RFC 8446 — the IANA "RFC 9846" reference for suites 0x006F-0x0071 is this base spec, NOT an Ascon document; no hidden Ascon-KDF RFC exists). Key schedule per RFC 9846 §7.1 with Hash = Ascon-Hash256 and HKDF = HMAC-Ascon-Hash256. **VERIFIED (2026-08):** RFC 9846 is published (RFC Editor, 2026-07-11, Standards Track) and obsoletes RFC 8446; its §7.1–§7.3 key schedule is structurally identical — only the "master secret" term was renamed to "main secret", which does not affect this suite's HKDF-Extract/Expand-Label derivation (uses `traffic_secret_N`/`early_secret`/`binder_key` only). Labels unchanged: "tls13 " + {derived, c hs traffic, s hs traffic, c ap traffic, s ap traffic, exp master, res master, e exp master, ext binder, res binder, c e traffic, traffic upd, key, iv, finished}. Hash.length = 32, key_length = 16, iv_length = 16 (max(8, N_MIN)).
- Transcript hash = Ascon-Hash256 (RFC 9846 §4.1, incl. message_hash(254) synthetic message); Finished = HMAC-Ascon-Hash256(finished_key, Transcript-Hash); CertificateVerify hash, PSK binders, exporters likewise. For 0x006E the ENTIRE handshake runs on Ascon-Hash256 (Q1): pre-ServerHello transcript hashing covers each offered hash (standard TLS 1.3); a 0x006E-only client offers a single hash — no SHA-256 in the handshake transcript hash or record AEAD; the DTLS transport cookie retains SHA-256 per RFC 6347.
- **DESIGN DECISION — HMAC instantiation:** SP 800-232 standardizes only the UNKEYED Ascon-Hash256; NIST's Ascon-MAC/PRF standard is announced but future. The suite therefore defines HMAC-Ascon-Hash256 (RFC 2104 over the sponge hash; precedent: HMAC-SHA3). The paper must carry the sponge-HMAC security argument (cite the HMAC-SHA3/sponge-keyed-hash security line; RFC 5869/HKDF structure stays byte-identical — only H changes). Same honest-contribution class as the §4.2.1 mask. Draft notes the migration path to NIST's future Ascon-MAC/PRF.
- KeyUpdate (epoch bump): application_traffic_secret_N+1 = HKDF-Expand-Label(., "traffic upd", "", 32); re-derive key/iv and sn_key per epoch. New RFC 9846 constraints: sender MUST NOT exceed 2^48-1 key updates per connection (receiver MUST NOT enforce); §5.5 now says implementations MUST close or key-update before AEAD usage limits (early data MUST NOT exceed).
- **Per-direction key schedule (RFC 9147 §4.2.3 / RFC 9846 §7.1, Hash = Ascon-Hash256):** the current epoch's per-direction *application traffic secret* `traffic_secret_N` is the single secret from which the record AEAD key, IV, and the mask key all derive — sibling `HKDF-Expand-Label` outputs with distinct labels:

  | Derived key | Label | Length | Formula |
  |---|---|---:|---|
  | `client_write_key` | `"key"` | 16 | `HKDF-Expand-Label(client_traffic_secret_N, "key", "", 16)` |
  | `client_write_iv` | `"iv"` | 16 | `HKDF-Expand-Label(client_traffic_secret_N, "iv", "", 16)` |
  | `client_sn_key` | `"sn"` | 16 | `HKDF-Expand-Label(client_traffic_secret_N, "sn", "", 16)` |
  | `server_*` (key/iv/sn_key) | same labels, `server_traffic_secret_N` | 16 | analogous |

  On KeyUpdate: `traffic_secret_{N+1} = HKDF-Expand-Label(traffic_secret_N, "traffic upd", "", 32)` (line 39), then all three keys re-derive. `sn_key` is therefore the **exact** key the mask PRF is keyed with, and it is co-derived with the AEAD key from the same traffic secret. The wolfSSL fork materialises it at `dtls13.c:2177/2188` (`ssl->keys.client/server_sn_key`), matching this derivation (see `dtls13-ascon-validation.md` §4.2.1).

  - **PSK parameters (evaluated mode).** The ciphersuite is exercised with an **external PSK** (RFC 9147 §5.1 / RFC 9846 §5.1), provisioned out-of-band as a static shared secret — *not* a resumption PSK. **Primary key-exchange mode: `psk_ke`** (pure PSK, no (EC)DHE), matching the wolfSSL-fork interop (`dtls13-ascon-validation.md` §11.0/§11.1). **`psk_dhe_ke`** (PSK + ephemeral DHE) is also interoperated with OpenSSL 3.6.3 in **TLS 1.3 over TCP** (custom group 0x0100; §11.1). **PSK key length: 256 bits (32 bytes)** — the value in `openssl-ascon/README` (64 hex digits). **Identity: `Client_identity`** (fixed test identity). The PSK binder is computed over **HMAC-Ascon-Hash256**: `early_secret = HKDF-Extract(0, psk)`, and `client/server_traffic_secret_N` derives through the standard RFC 9846 §7.1 chain (RFC 9846 obsoletes RFC 8446; key schedule structure unchanged) (below), so the §4.1 key schedule above is fed by an external-PSK-derived secret.

### 4.2 Nonce mapping — RESOLVED (RFC 9147 §4, §4.2.1)

- RFC 9147 states: "the 64-bit sequence_number is used as the sequence number for the AEAD computation; unlike DTLS 1.2, the epoch is not included."
- Decision: `nonce = fixed_iv XOR zero-pad64(seq_num)` with zero-padding to the 128-bit Ascon nonce. No epoch bits in the nonce. This matches TLS 1.3 (RFC 9846 §5.3, obsoletes RFC 8446) and keeps retransmission semantics simple: a retransmitted record re-encrypts with the same (key, nonce), which is safe for AEAD and required by RFC 9147 §4.2.1 ("retransmissions MUST use the same epoch and keying material as the original transmission").
- Sequence numbers restart at 0 per epoch (§4.2). Epoch must not wrap; seq_num must not wrap — the implementation must rekey or abandon the association first.
- Invariant to prove: "no two encryptions share (key, nonce)" — holds because each (epoch, sender) uses a fresh key, and seq_num is unique within an epoch.
- Anti-replay: sliding window per epoch (RFC 9147 §4.5.1), initialized to zero when the epoch starts; window updated only after successful deprotection.

### 4.2.1 Record number encryption — NEW DESIGN REQUIREMENT (RFC 9147 §4.2.3)

- RFC 9147: "Future cipher suites, which are not based on AES or ChaCha20, MUST define their own record sequence number encryption in order to be used with DTLS."
- Ascon is neither AES nor ChaCha20. The ciphersuite must define its own mask generation. This is the paper's core novel design contribution.
- Mask purpose: XOR a mask with the on-the-wire seq_num (8/16 bits). sn_key derived per epoch: `[sender]_sn_key = HKDF-Expand-Label(Secret, "sn", "", key_length)`.
- Constraints from RFC 9147 §4.2.3: ciphertext must be >= 16 bytes for masking; senders must pad short plaintexts. Ascon-AEAD128 has a 16-byte tag, so the minimum record already meets this — no padding needed.
- **Design requirement discovered in analysis:** the mask MUST be ciphertext-dependent. If the mask depends only on (sn_key, nonce) — e.g., a fixed per-epoch constant — the wire seq numbers form a visible arithmetic progression (consecutive seqs XOR the same mask yield consecutive wire values). An observer recovers the record count and the retransmission pattern; this defeats the privacy goal of RFC 9147 §4.2.3. The AES-ECB construction (mask = AES-ECB(sn_key, Ciphertext[0..15])) is ciphertext-dependent for exactly this reason; the Ascon design must mirror that property. (This kills the naive "mask = AEAD(sn_key, fixed nonce, zeros)" variant — its mask is a per-epoch constant.)

  - **Chosen: Option B — keyed-sponge PRF (ciphertext-dependent).**
   - Construction: state S = domsep(64) || sn_key(128) || ciphertext[0..15](128), where domsep = "RNDIMSK_" = 0x524e44494d534b5f (the implementation's ASCII constant, distinct from all SP 800-232 IVs); apply Ascon-P^12; mask = low 16 bits of the first rate word (S0' after P).
   - **Implementation (verified in the wolfSSL fork):** `wc_AsconAEAD128_Mask()` (`wolfcrypt/src/ascon.c:543`) builds `S = domsep(64) || sn_key(128) || ciphertext[0..15](128)` (rate r=128 = ciphertext, capacity c=192 = domsep||key), runs `Ascon-P^12`, and returns `S0' || S1'` (16 bytes; the record layer consumes 8 or 16 bits per RFC 9147 §4.2.3). `domsep` is the ASCII constant `"RNDIMSK_"` (`ASCON_MASK_DOMSEP = 0x524e44494d534b5f`, `wolfcrypt/ascon.h:47`) — a stronger domain separator than the `0x80||0…0` placeholder above, explicitly distinct from the Ascon-AEAD128 IV and Ascon-Hash256 IV. Test vectors: `dtls13-ascon-validation.md` §4.2.1.
    - Security — **standalone, tight PRF proof in `mask-prf-proof.md` (Theorems 1, 1′, 2, 3).** The mask is a keyed sponge with `sn_key` in the 192-bit capacity (c=192 = domsep(64) ‖ sn_key(128)) and the per-record ciphertext `ct[0..15]` in the 128-bit rate (r=128); one Ascon-P^12; output taken from the state (words `s0'‖s1'`), truncated to 16 bits. This is a single-block **inner-keyed sponge** (key in capacity, message in rate) — i.e. a keyed-sponge PRF.

     **PRF bound derivation.** The generic keyed-sponge PRF advantage is governed by two terms (Mennink–Reyhanitabar–Vizár, "Security of Keyed Sponge Constructions", ASIACRYPT 2015; Gaži et al., CRYPTO 2015): (i) a capacity-collision term `q²/2^c` from inner clashes across queries, and (ii) a key-prediction term `q/2^k`. Mennink, "Key Prediction Security of Keyed Sponges", IACR ToSC 2018(4) (ePrint 2018/449), **Theorem 1** tightens (ii) to `Adv_key-pre(N) ≤ N/2^k` for `k ≤ r` (here `k=128, r=128`, so tight). Substituting `c=192, k=128`:
       `Adv_PRF(q) ≤ q²/2^192 + q/2^128`   (small constant factors absorbed into the O(·)).
      The 16-bit truncation of the rate output can only shrink an adversary's advantage, so the full-rate bound above upper-bounds the 16-bit mask. Negligible for `q ≪ 2^96` — far beyond the `2^48` wire-sequence cap. **Tight bound (single-block, fixed-capacity instance):** the `q²/2^192` capacity-collision term is vacuous (capacity = `domsep‖sn_key` is constant across queries, so no inner collision), leaving only the key-prediction term `q/2^128` (Mennink ToSC 2018/449, Thm 1) — i.e. `≈ 2^-80` at the `2^48` cap. Full derivation + RFC 9147 §4.2.3 dominance in `mask-prf-proof.md`.

      **Why the domain separator reduces to this model.** `domsep = "RNDIMSK_" = 0x524e44494d534b5f` fixes the non-key 64 bits of the capacity to a public constant, so every query's initial state has exactly one secret (`sn_key`) — the inner-keyed-sponge model above (no secret IV, no extra absorb pass). Because `domsep` is unique across all Ascon-P uses in the suite, mask queries cannot collide in the capacity with AEAD or HKDF queries, confining the adversary to one isolated instance (no cross-instance term). And `sn_key` is never used for AEAD, so the mask adds no second input path into the AEAD argument (preserves the KSW 2023 / Datta et al. 2026/1160 isolation). Bound therefore holds in isolation.

   - **sn_key independence from the AEAD key (HKDF-PRF argument).** `sn_key` and `client_write_key` are both `HKDF-Expand-Label` outputs of the *same* `traffic_secret_N`, differing only in the label (`"sn"` vs `"key"`). HKDF-Expand-Label is a PRF when built over a PRF `H` (here `HMAC-Ascon-Hash256`, whose PRF security is the sponge-HMAC claim of Formal target 3 / §4.1). Label-separated PRF outputs are computationally independent: an adversary given the AEAD key `client_write_key` cannot distinguish `sn_key` from a uniform 128-bit string except with advantage `≤ Adv^{PRF}_{HMAC-Ascon-Hash256}(q_kdf)` (negligible, `q_kdf` = number of HKDF-Expand calls). Consequently the mask PRF bound `q²/2¹⁹² + q/2¹²⁸` holds **independently of the AEAD key** — even if the AEAD key is known, the mask stays pseudorandom. The `"RNDIMSK_"` domain separator additionally isolates the mask's Ascon-P domain (`0x524e44494d534b5f`) from the AEAD (`0x00001000808C0001`) and the hash, so the three uses are domain-separated despite co-derivation. Composition: a combined adversary's advantage is bounded by `Adv_AEAD + Adv_mask + Adv^{PRF}_{HKDF}`, with no cross-leakage between sibling keys. (This replaces the weaker "sn_key is never used for AEAD" isolation note: the keys are co-derived but HKDF-independent.)
  - Cost: one Ascon-P^12 per record ≈ 40% of one Ascon-AEAD128 encryption (P^12+P^6+P^12). Option A would add a full second AEAD call — ~2.5x this cost — material on small CoAP records.
  - Honesty note for the paper: this is a NEW construction on the Ascon permutation, not a mode covered by SP 800-232. The paper supplies the PRF argument itself — a deliberate, defensible contribution (standalone proof in `mask-prf-proof.md`); this is exactly §6 formal target 2.
  - Fallback: **Option A — AEAD-based** (Mask = Ascon-AEAD128(sn_key, nonce=MASK_NONCE, M=ciphertext[0..15])): uses only SP 800-232-covered modes; costs a full second AEAD call per record. Keep as the conservative alternative in the paper if reviewers reject novel sponge use.
- Decryption path unchanged from RFC 9147: mask computed from received ciphertext[0..15] before decryption (works for both options); identical to the AES-ECB flow. Retransmission with identical ciphertext ⇒ identical mask ⇒ identical wire seq — consistent with §4.2.1.
- Cross-use isolation: sn_key is used ONLY for masking, never for AEAD — no (key, nonce) overlap with record encryption; mask depends on (sn_key, ciphertext) only, leaks nothing about plaintext.
- Committing property unaffected: mask key separate from AEAD key; KSW 2023 bounds apply unchanged. [TO FILL] in §6: the mask independence argument also covers Datta et al. 2026/1160-style padding interactions (no second input path into the AEAD).

### 4.3 Usage limits (RFC 9147 §4.5.3) — DERIVED (Phase 1)

- RFC 9147 §4.5.3: the suite MUST define limits for (a) records protected per key and (b) records failing authentication per key, before a key update is required. References [AEBounds], [ROBUST]. DTLS differs from TLS: failed records are silently discarded (no connection close), so forgery attempts are bounded only by the explicit limit — the implementation MUST count failed authentications per key.

| Limit | Value | Binding constraint | Resulting advantage |
| --- | --- | --- | --- |
| Records protected per key | 2^48 - 1 (≤64-B records); NIST 2^54-byte cap binds first for larger records | Protocol cap (seq_num space, RFC 9147 §4.2) / NIST SP 800-232 R6 | privacy ≤ 2^-92 |
| Bytes per key | min(2^62 protocol max, 2^54 NIST cap) = 2^54 (2^50 blocks) | NIST SP 800-232 R6 (binds for records > 64 B; 2^48-record protocol cap binds for ≤64-B records) | privacy ≤ 2^-92 |
| Records failing authentication per key | 2^48 | Protocol cap; 128-bit tag | forgery ≤ 2^-80 |

  **Implementation note (verified):** the wolfSSL fork enforces wolfSSL's
  conservative DTLS defaults rather than the 2^48 cap:
  `DTLS_AEAD_ASCON_FAIL_LIMIT = 2^16` (hard) and
  `DTLS_AEAD_ASCON_FAIL_KU_LIMIT = 2^15` (key-update)
  (`wolfssl/wolfssl/internal.h:1454-1455`, handled in
  `Dtls13CheckAEADFailLimit()` `dtls13.c:3250-3255`). 2^16 is stricter than
  2^48; at 2^16 failed attempts the cumulative forgery advantage is
  2^16 / 2^128 = 2^-112, far below the 2^-60 rule of thumb. The 2^48 protocol
  cap remains the theoretical maximum. **RESOLVED (option a):** keep 2^16/2^15
  in the reference implementation; the design's 2^48 stays the protocol max. This
  is a paper-claims decision, not a correctness one (see
  `dtls13-ascon-validation.md` §4.3).

Derivation:
- Confidentiality: Ascon-128a (the implemented Ascon-AEAD128) has r=128, c=192. PRF-indistinguishability advantage ~ q_b^2/2^192 + q/2^128 (q_b = rate blocks). Realized data cap is min(2^62-byte protocol max, 2^54-byte NIST SP 800-232 R6 cap) = 2^54 bytes = 2^50 rate blocks: 2^100/2^192 = 2^-92 (record-size-dependent binding: 2^48-record protocol cap binds for records ≤ 64 B; NIST 2^54-byte cap binds first for larger records). Not binding.
- Integrity: per-attempt forgery <= 2^-128 (128-bit tag); cumulative <= q_f/2^128. At q_f = 2^48: 2^-80, below the 2^-60 rule of thumb (cf. [AEBounds]). Not binding.
- Publishable observation: the binding usage constraint is record-size-dependent. For records ≤ 64 B the 2^48-record protocol cap binds (≤ 2^54 bytes, NIST satisfied); for larger records the NIST SP 800-232 R6 2^54-byte cap binds first (e.g., 2^40 records at max 2^14-B records). Ascon's usage limit is therefore NOT vacuous for large records — unlike AES-GCM (2^24.5 records) and AEAD_AES_128_CCM_8 (banned for DTLS: 2^48/2^64 = 2^-16), but the realized privacy bound (2^-92) stays far below the 2^-60 rule of thumb.
- Committing bound (KSW 2023, ePrint 2023/1525, Krämer–Struck–Weishäupl, TOSC 2024): unmodified Ascon-128 message-commitment security = 64-bit (committing advantage ≤ 2^-64, birthday bound). Our usage (≤ 2^48 records/key) is 16 bits below this bound. Not a usage-limit constraint; the zero-padding caveat of Datta et al. (2026/1160) does not apply (targets the committing zero-padding transform, not RFC 9147 nonce padding).
- Implementation requirement: count failed authentications per (epoch, key); force KeyUpdate / new epoch before either limit. In practice rekey cadence is set by deployment policy, since both limits exceed any realistic session.

## 5. Connection IDs

- RFC 9146 CIDs: a CID change does not re-key. Document that ciphersuite choice is orthogonal to CID handling; note where CID reassociation interacts with the nonce mapping (none expected — one line, for the record).

## 6. Security analysis plan (bounded, honest claims)

- Claim we will make: Ascon-AEAD128's committing security transfers to the DTLS record layer with the standard bounds from KSW 2023, subject to the zero-padding caveat (Datta et al., ePrint 2026/1160).
- Claim we will NOT make: that Ascon fixes TLS 1.3 key-confirmation (3SHKE, Albertini et al. 2020/1456) by itself — key-commitment fixes live in the handshake; the AEAD committing property is a defense-in-depth addition.
  - **Formal target 1 — record-layer security (precondition-verification, core):** verify the Ascon record layer satisfies the Robust Channels preconditions and cite FGJ20's DTLS 1.3 result — Theorems 7.1 (robust integrity, ROB-INT) & 7.2 (IND-CPA), combined via Proposition 5.9, all in §7 (ePrint 2020/718; Journal of Cryptology 2024) — given C1/C2; NOT a re-derivation of FGJ20's generic channel proof. The Ascon-specific hops are written explicitly in `robust-channels-game-hop.md`. Preconditions: (a) Ascon-AEAD128 is IND-CPA + INT-CTXT (C1/C2); (b) the nonce/epoch/seq state machine (§4.2) guarantees (key, nonce) uniqueness and sound anti-replay; (c) mask independence (below) keeps the reduction clean. Bound follows the theorem: Adv^{ROB-INT-IND-CCA}(Ch) ≤ Adv^{IND-CPA}_AEAD + Adv^{INT-CTXT}_AEAD(q_R), so C3 is NOT bounded by C1/C2 alone — the Adv^{INT-CTXT}_AEAD(q_R) term is the non-tight linear loss (≤ q_R·Adv^{INT-CTXT}_AEAD(1), q_R = enforced failed-auth limit 2^16 → ≤ 2^-112), exactly the robustness degradation FGJ20 identified.
    **Mechanization (2026-08):** the arithmetic core of this game-hop (the hybrid sum + Prop. 5.9 composition + concrete bounds + KeyUpdate load-bearing + mask no-cross-term) is machine-checked in `formal/coq/robust_channels.v` (no `Admitted`); the probability-theory game-hops are stated hypotheses (as in `mask_prf.v`'s `Hreducible`); see `robust-channels-game-hop.md` §"Mechanization status".
- **Formal target 2 — mask construction (new formal content, core):** the §4.2.1 keyed-sponge PRF. The paper supplies: (a) PRF bound q^2/2^c + q/2^k (c=192, k=128: negligible up to q ~ 2^96), derived in §4.2.1; (b) the ciphertext-dependence/privacy argument (wire seq pseudorandom to an observer without sn_key; a fixed mask would leak the record count — §4.2.1 analysis); (c) independence: `sn_key` is a distinct-label `HKDF-Expand-Label` output of the same traffic secret as the AEAD key; under the HKDF-PRF (HMAC-Ascon-Hash256) assumption the two keys are computationally independent (advantage `≤ Adv^{PRF}_{HMAC-Ascon-Hash256}`), so the mask PRF bound holds independently of the AEAD key — argued in §4.2.1, the `sn_key` independence subsection. The mask leaks nothing about plaintext, and the AEAD committing bounds (KSW 2023) apply unchanged (masks add no second input path into the AEAD — this covers the Datta et al. 2026/1160 zero-padding caveat). Tamarin models the mask as an opaque PRF and does NOT verify this keyed-sponge construction (see §129).
- **Formal target 3 — HMAC instantiation (argued, cited):** HMAC-Ascon-Hash256 (RFC 2104 over the sponge hash). Cite the sponge-HMAC/keyed-sponge PRF security literature (HMAC-SHA3 line; exact citation [TO VERIFY] in Phase 1); HKDF (RFC 5869) structure unchanged, only H replaced. Note NIST's future Ascon-MAC/PRF standard as the migration path.
- **Tamarin decision — paper proof is core; Tamarin model DONE (Phase 4 stretch).** Rationale: the state-machine invariants are simple and already stated (§4.2); Robust Channels supplies the model; the AEAD bounds are analytic. A hand model would duplicate existing analysis for little gain — but an executable one was still built: `tools/tamarin/dtls13-ascon-record.spthy` verifies 8 lemmas (psk/key secrecy, data secrecy C2S/S2C, **sequence-number privacy C2S/S2C** (symbolic, under the PRF assumption; the mask's cryptographic soundness is the analytic §4.2.1 / C4 result, NOT a Tamarin verification), and forced-KeyUpdate reachability) in ~1.25s under Tamarin 1.12.0. Scope is secrecy + seq-privacy only; the model treats the mask as an opaque PRF (`mask_fn` abstracting Ascon-P^12(domsep‖sn_key‖ct[0..15])) and does NOT exercise the keyed-sponge permutation. Authentication/integrity is established by the companion game-hop proof (`robust-channels-game-hop.md`), since pure Tamarin rules cannot express the MAC check without SAPIC/Maude equational theories.
- **Claim boundaries (honesty section, §6 closes with these):** claims made = AEAD bounds applied (not derived), record-layer reduction following Robust Channels, mask PRF bound + privacy argument (self-contained, novel), sponge-HMAC argument. Claims NOT made = no new AEAD theory, no 3SHKE fix (key commitment is defense-in-depth only; fixes live in the handshake per Albertini et al.), no confidentiality beyond RFC 9147's design goals for the mask, no forgery resistance beyond AEAD bounds.

## 7. Open questions (Phase 1 status)

1. **Q1 — resolved (by design):** In TLS 1.3 the ciphersuite's hash is used for the transcript, HKDF, and Finished. 0x006E therefore runs the ENTIRE handshake on Ascon-Hash256 (RFC 9846 §7.1). Consequence: the paper must cover handshake-side hashing (Finished, CertificateVerify, PSK binder), not only record protection. Secret-derivation mapping (RFC 9846 §7.1, Hash = Ascon-Hash256): external PSK → `early_secret = HKDF-Extract(0, psk)`; `binder_key = HKDF-Expand-Label(early_secret, "res binder", "", 32)` for the PSK binder; for `psk_ke` (no (EC)DHE) `client/server_traffic_secret_0 = Derive-Secret(early_secret, "c ap traffic"/"s ap traffic", "")` directly (no handshake-secret DHE step); `traffic_secret_{N+1}` via the `"traffic upd"` label per §4.3. These feed the §4.1 key schedule (labels `"key"`/`"iv"`/`"sn"`). Verified against RFC 9846 §7.1.
2. **Q2 — resolved:** Zero-padded nonce, no epoch bits. See §4.2.
3. **Q3 — resolved (format):** Follow RFC 9147 §4.5.3: two limits (records protected per key, records failing authentication per key), in the RFC 9001 §A.5 table style. See §4.3.
4. **Q4 — open:** Benchmark target. Candidates: RP2040 (Cortex-M0+) and ESP32-C3 (RV32IMC) — both cheap off-the-shelf. Decide in Phase 4.
5. **Q5 — direction decided:** Implementation base = mbedTLS 4.x (current: 4.2.0, 2026-07; 4.1 is LTS to 2029; DTLS 1.3 flight code present in the tree). Alternative: wolfSSL — already has KAT-tested `wc_AsconAEAD128` (merged 2025-01) and DTLS 1.3; adding the ciphersuite on top of existing primitives may be the fastest path. [TO FILL] At Phase 2 start: check the exact DTLS 1.3 API state of mbedTLS 4.x and wolfSSL experimental flags; pick the base with the least integration friction.

## 8. Milestones

- M1 (end of week 1): resolve open questions 1–3, 5 by reading RFC 9147 + SP 800-232. [TO FILL] Record answers below.
- M2 (end of week 3): complete design doc (all [TO FILL] filled) + one-page bounded security claim.
- M3 (end of week 4): design review gate — do we proceed to implementation (Phase 2) or adjust scope?

## 9. Sources log

| Source | What it gave us | Date fetched |
| ------ | --------------- | ------------ |
| IANA tls-parameters.txt | Four Ascon suites, DTLS-OK = Y, no reference drafts | 2026-08-13 |
| SP 800-232 final | Ascon-AEAD128 spec | 2026-08-13 |
| ePrint 2023/1525 (KSW) | Committing security bounds for Ascon | 2026-08-13 |
| ePrint 2026/1160 (Datta et al.) | Committing attacks on zero-padded Ascon — caveat | 2026-08-13 |
| ePrint 2020/718 (Robust Channels) | DTLS 1.3 record-layer security model | 2026-08-13 |
| RFC 9147 (full text) | §4: nonce uses 64-bit seq_num, epoch NOT included; §4.2.3: non-AES/ChaCha suites MUST define their own record-number encryption; §4.5.3: MUST define both usage limits; §4.2.1: retransmission MUST reuse epoch+key; anti-replay window per epoch | 2026-08-13 |
| draft-ochkas-cose-ascon-04 | COSE-layer Ascon precedent | 2026-08-13 |
| draft-denis-tls-aegis-06 | AEGIS ciphersuite draft (process template) | 2026-08-13 |
| mbedTLS releases API | 4.2.0 current (2026-07-07), 4.1 LTS to 2029, 3.6.7 LTS; DTLS flight code present | 2026-08-13 |
| wolfSSL PR #8307 (from sweep) | wc_AsconAEAD128 / wc_AsconHash256 merged, KAT-tested, behind HAVE_ASCON + experimental flag | 2026-08-13 |
