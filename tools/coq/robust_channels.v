(* robust_channels.v - Rocq/Coq mechanization of the arithmetic core of the
   Robust Channels game-hop proof for the Ascon-DTLS 1.3 record layer.

   Companion to mask_prf.v (which mechanizes the mask PRF bound, C4).
   This file mechanizes the *channel-security* composition (C3):
   robust-channels-game-hop.md.

   What is MACHINE-CHECKED here (no Admitted):
     1. channel_bound       - Prop. 5.9 + hybrid: total <= q_R*B_1 + B_conf
     2. concrete_enforced   - q_R=2^16: total <= 2^-92 + 2^-112 (scaled)
     3. concrete_max        - q_R=2^48: total <= 2^-92 + 2^-80  (scaled)
     4. keyupdate_loadbearing - 2^16 < 2^48 (mechanism is load-bearing)
     5. integrity_degradation - enforced integrity term < protocol-max term
     6. mask_no_crossterm  - disjoint-key mask adds no term to channel bound

   The probability-theory steps (the actual game-hop reductions:
   IND-CPA reduction, single-query INT-CTXT reduction, the hybrid
   telescoping, Proposition 5.9) are stated as HYPOTHESES - exactly as
   mask_prf.v states Hreducible for the keyed-sponge reduction.  The
   arithmetic that composes these into the final bound is fully proven.

   Scaling convention (identical to mask_prf.v):
     All advantages are natural numbers scaled by 2^128.
       Adv^{IND-CPA}   <= 2^-92   ->  scaled: <= 2^36
       Adv^{INT-CTXT}(1) <= 2^-128 ->  scaled: <= 1
       q_R = 2^16 (enforced)  ->  integrity term: 2^16 * 1 = 2^16  (2^-112)
       q_R = 2^48 (protocol max) ->  integrity term: 2^48 * 1 = 2^48  (2^-80)

   Compile:  coqc robust_channels.v
*)

From Stdlib Require Import Arith.PeanoNat Lia.

Open Scope nat_scope.

Definition exp2 (k:nat) : nat := Nat.pow 2 k.

(* ===================================================================== *)
(* Helper lemmas: exp2 is positive and strictly increasing.               *)
(* (Needed because nat is unary — 2^48 cannot be computed directly.)      *)
(* ===================================================================== *)

Lemma exp2_pos : forall n, 0 < exp2 n.
Proof.
  induction n as [| n IH].
  - unfold exp2. simpl. lia.
  - unfold exp2 in *. simpl. lia.
Qed.

Lemma exp2_succ : forall n, exp2 n < exp2 (S n).
Proof.
  intro n. unfold exp2 in *.
  pose proof (exp2_pos n) as Hpos. unfold exp2 in Hpos.
  simpl. lia.
Qed.

Lemma exp2_le_mono : forall m n, m <= n -> exp2 m <= exp2 n.
Proof.
  intros m n H.
  induction H as [| k Hk IH].
  - reflexivity.
  - pose proof (exp2_succ k) as Hsucc. lia.
Qed.

Lemma exp2_lt_mono : forall m n, m < n -> exp2 m < exp2 n.
Proof.
  intros m n H.
  apply Nat.lt_le_trans with (m := exp2 (S m)).
  - apply exp2_succ.
  - apply exp2_le_mono. lia.
Qed.

(* ===================================================================== *)
(* Part 1 - Generic channel bound (Proposition 5.9, FGJ20 + hybrid).      *)
(*                                                                        *)
(* Given:                                                                 *)
(*   Hhybrid  : Adv^{INT-CTXT}(q_R) <= q_R * Adv^{INT-CTXT}(1)           *)
(*              (the q_R-fold hybrid/telescoping sum, Hop 2)              *)
(*   Hchannel : Adv^{ROB-INT-IND-CCA} <= Adv^{INT-CTXT}(q_R) + Adv^{IND-CPA} *)
(*              (Prop. 5.9 + Thms 7.1/7.2, FGJ20)                         *)
(*   Hint1    : Adv^{INT-CTXT}(1) <= B_1     (C2, 128-bit tag)           *)
(*   Hconf    : Adv^{IND-CPA} <= B_conf      (C1, SP 800-232)            *)
(* Prove:                                                                  *)
(*   Adv^{ROB-INT-IND-CCA} <= q_R * B_1 + B_conf                          *)
(* ===================================================================== *)

Lemma channel_bound
  (q_R adv_intctxt_1 adv_intctxt_qR adv_indcpa adv_channel B_1 B_conf : nat)
  (Hhybrid  : adv_intctxt_qR <= q_R * adv_intctxt_1)
  (Hchannel : adv_channel <= adv_intctxt_qR + adv_indcpa)
  (Hint1    : adv_intctxt_1 <= B_1)
  (Hconf    : adv_indcpa <= B_conf) :
  adv_channel <= q_R * B_1 + B_conf.
Proof.
  eapply Nat.le_trans.
  - exact Hchannel.
  - apply Nat.add_le_mono.
    + eapply Nat.le_trans.
      * exact Hhybrid.
      * apply Nat.mul_le_mono_nonneg_l; [apply Nat.le_0_l | exact Hint1].
    + exact Hconf.
Qed.

(* ===================================================================== *)
(* Part 2 - Concrete scenario A: enforced KeyUpdate (q_R = 2^16).          *)
(*                                                                        *)
(*   C1 (IND-CPA):     Adv <= 2^-92    ->  scaled: <= 2^36               *)
(*   C2 (INT-CTXT(1)): Adv <= 2^-128   ->  scaled: <= 1                   *)
(*   q_R = 2^16 (enforced failed-auth limit, RFC 9846 section 4.7.3)      *)
(*                                                                        *)
(*   integrity term: 2^16 * 1 = 2^16   ->  2^-112                        *)
(*   total: 2^36 + 2^16                ->  2^-92 + 2^-112               *)
(* ===================================================================== *)

Theorem concrete_enforced
  (adv_intctxt_1 adv_intctxt_qR adv_indcpa adv_channel : nat)
  (Hhybrid  : adv_intctxt_qR <= exp2 16 * adv_intctxt_1)
  (Hchannel : adv_channel <= adv_intctxt_qR + adv_indcpa)
  (Hconf    : adv_indcpa <= exp2 36)
  (Hint1    : adv_intctxt_1 <= 1) :
  adv_channel <= exp2 36 + exp2 16.
Proof.
  pose proof (channel_bound (exp2 16) adv_intctxt_1 adv_intctxt_qR adv_indcpa
              adv_channel 1 (exp2 36) Hhybrid Hchannel Hint1 Hconf) as H.
  rewrite Nat.mul_1_r in H.
  lia.
Qed.

(* ===================================================================== *)
(* Part 3 - Concrete scenario B: protocol maximum (q_R = 2^48).            *)
(*                                                                        *)
(*   Same C1/C2 bounds, but q_R = 2^48 (protocol max, NO enforced         *)
(*   KeyUpdate).  This is what the bound degrades to without the          *)
(*   forced-KeyUpdate mechanism.                                          *)
(*                                                                        *)
(*   integrity term: 2^48 * 1 = 2^48   ->  2^-80                         *)
(*   total: 2^36 + 2^48                ->  2^-92 + 2^-80                *)
(* ===================================================================== *)

Theorem concrete_max
  (adv_intctxt_1 adv_intctxt_qR adv_indcpa adv_channel : nat)
  (Hhybrid  : adv_intctxt_qR <= exp2 48 * adv_intctxt_1)
  (Hchannel : adv_channel <= adv_intctxt_qR + adv_indcpa)
  (Hconf    : adv_indcpa <= exp2 36)
  (Hint1    : adv_intctxt_1 <= 1) :
  adv_channel <= exp2 36 + exp2 48.
Proof.
  pose proof (channel_bound (exp2 48) adv_intctxt_1 adv_intctxt_qR adv_indcpa
              adv_channel 1 (exp2 36) Hhybrid Hchannel Hint1 Hconf) as H.
  rewrite Nat.mul_1_r in H.
  lia.
Qed.

(* ===================================================================== *)
(* Part 4 - KeyUpdate is load-bearing.                                    *)
(*                                                                        *)
(* The forced-KeyUpdate mechanism (RFC 9846 section 4.7.3, enforced at     *)
(* 2^16) binds q_R to 2^16 rather than the protocol maximum 2^48.         *)
(* This is load-bearing: the integrity term at 2^16 is 2^-112, but       *)
(* without the mechanism it degrades to 2^-80 - a difference of 2^32.    *)
(* ===================================================================== *)

Lemma keyupdate_loadbearing :
  exp2 16 < exp2 48.
Proof. apply exp2_lt_mono. lia. Qed.

(* The integrity term at the protocol max (2^48) strictly exceeds the     *)
(* enforced limit (2^16): 2^48 * 1 > 2^16 * 1, i.e., 2^-80 > 2^-112.    *)
Lemma integrity_degradation :
  exp2 16 * 1 < exp2 48 * 1.
Proof.
  rewrite !Nat.mul_1_r. apply exp2_lt_mono. lia.
Qed.

(* ===================================================================== *)
(* Part 5 - The mask contributes no cross-term to the channel bound.       *)
(*                                                                        *)
(* The record-number mask uses sn_key, a key HKDF-derived with a distinct *)
(* label ("sn") from the AEAD key ("key"), and is used ONLY for masking   *)
(* - never for AEAD.  Under the HKDF-PRF independence assumption          *)
(* (design-01 section 4.2.1), the mask's PRF advantage does not enter     *)
(* the channel bound: the channel security reduces to AEAD (IND-CPA +     *)
(* INT-CTXT) only.  This is precondition (c) of the FGJ20 reduction       *)
(* (robust-channels-game-hop.md, Hop 1: "the mask contributes no          *)
(* cross-term").                                                          *)
(*                                                                        *)
(* The lemma makes the arithmetic consequence explicit: adv_mask does NOT  *)
(* appear in the bound.  The disjoint-key property is structural          *)
(* (argued in design-01 section 4.2.1), not arithmetic.                   *)
(* ===================================================================== *)

Lemma mask_no_crossterm
  (adv_mask adv_channel adv_intctxt_qR adv_indcpa : nat)
  (Hchannel : adv_channel <= adv_intctxt_qR + adv_indcpa) :
  (* adv_mask does NOT appear in the bound. *)
  adv_channel <= adv_intctxt_qR + adv_indcpa.
Proof. exact Hchannel. Qed.

(* ===================================================================== *)
(* Summary theorem: the full channel bound with enforced KeyUpdate.       *)
(*                                                                        *)
(* Combines channel_bound + C1/C2 + enforced q_R = 2^16 + mask disjoint.  *)
(* In real-valued form:                                                   *)
(*   Adv^{ROB-INT-IND-CCA}(Ch) <= 2^-92 + 2^-112                         *)
(* with the mask contributing zero (precondition (c) satisfied).           *)
(* ===================================================================== *)

Theorem channel_security_enforced
  (adv_mask adv_intctxt_1 adv_intctxt_qR adv_indcpa adv_channel : nat)
  (Hhybrid  : adv_intctxt_qR <= exp2 16 * adv_intctxt_1)
  (Hchannel : adv_channel <= adv_intctxt_qR + adv_indcpa)
  (Hconf    : adv_indcpa <= exp2 36)
  (Hint1    : adv_intctxt_1 <= 1) :
  (* adv_mask is absent: the mask adds no term. *)
  adv_channel <= exp2 36 + exp2 16.
Proof.
  apply concrete_enforced; assumption.
Qed.
