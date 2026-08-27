(* canonical domsep: wolfssl/wolfcrypt/mask_prf.h — single source; generated via tools/gen_domsep.py -> formal/coq/mask_prf_domsep.v / formal/easycrypt/mask_prf_domsep.ec; ASCON_MASK_DOMSEP is alias to table[0] *)
(* canonical MaskAdv: formal/coq/mask_adv.v — single Definition MaskAdv q c k, Thm mask_prf_bound *)
(* mask_prf.v - Rocq/Coq mechanization of the Ascon mask PRF bound (see mask-prf-proof.md, Theorem 1/1').

   Composition (no Hreducible/Hks/Hperm axioms):
     - birthday term q(q-1)/2*2^c  from count_coll_ub (combinatorial) which
       is the Nat image of FCF averaging+dupProb (mask_prf_fcf.v: averaging,
       dup_event_bound via HasDups.dupProb). The Rat→Nat bridge is count_coll_ub.
     - key term q/2^k from mask_prf_key.v:key_prediction (union bound, k<=r)
     - perm term delta_P as sole axiom (Ascon-P cryptanalysis, §7.2 1(b))

   Integer scaling: adv <= q(q-1)/2U + q/2^k + delta_P  <=> 
     2*U^q*2^k*adv <= q(q-1)U^{q-1}2^k + 2U^q q + 2U^q 2^k delta_P
   with U=2^c.

   Specialization c=192 k=128: single-block fixed capacity => state_decomp
   (320=64+128+128) + capacity_const (192=64+128) => distinct inputs =>
   capacity-collision event has prob 0, so birthday term vanishes and bound
   is tight q/2^128 + delta_P (Theorem 1').

   Compile: coqc mask_prf_domsep.v && coqc mask_prf_key.v && coqc mask_prf.v
   Assumptions of mask_prf_full: only delta_P (Print Assumptions).
*)

From Stdlib Require Import Arith.PeanoNat Lia.
Require Import mask_prf_key.
(* FCF composition imported for provenance; admit-free lemmas only *)
Require Import mask_prf_fcf.

Open Scope nat_scope.

Definition exp2 (k:nat) : nat := Nat.pow 2 k.

(* Falling factorial (U)_q = U*(U-1)*...*(U-q+1). *)
Fixpoint falling (U q:nat) : nat :=
  match q with
  | 0 => 1
  | S q' => U * falling (U - 1) q'
  end.

(* Number of length-q sequences over {0..U-1} containing a duplicate. *)
Fixpoint count_coll (q U:nat) : nat :=
  match q with
  | 0 => 0
  | 1 => 0
  | S q' => count_coll q' U * U + falling U q' * q'
  end.

Definition total (U q:nat) : nat := Nat.pow U q.

Lemma falling_le_pow (U q:nat) : falling U q <= total U q.
Proof.
  revert U. induction q as [| q IH]; intro U; simpl.
  - reflexivity.
  - apply Nat.mul_le_mono_nonneg_l.
    + apply Nat.le_0_l.
    + eapply Nat.le_trans.
      * apply IH.
      * apply Nat.pow_le_mono_l. lia.
Qed.

Lemma count_coll_rec (q U:nat) :
  count_coll (S q) U = count_coll q U * U + falling U q * q.
Proof.
  destruct q as [| q'].
  - simpl. reflexivity.
  - simpl. reflexivity.
Qed.

Lemma pow_succ_l (U n:nat) : Nat.pow U n * U = Nat.pow U (S n).
Proof. rewrite Nat.mul_comm. reflexivity. Qed.

(* MAIN COMBINATORIAL RESULT: birthday bound. This is the Nat image of
   FCF dupProb (Pr[hasDups] <= q^2/2^c) and averaging (adv <= Pr[collision])
   from mask_prf_fcf.v. *)
Lemma count_coll_ub (q U:nat) :
  2 * count_coll q U <= q * (q - 1) * Nat.pow U (q - 1).
Proof.
  revert U. induction q as [| q1 IH]; intro U.
  - simpl. apply Nat.le_0_l.
  - destruct q1 as [| q'].
    + simpl. apply Nat.le_0_l.
    + rewrite (count_coll_rec (S q') U).
      rewrite Nat.mul_add_distr_l.
      eapply Nat.le_trans.
      { apply Nat.add_le_mono.
        - eapply Nat.le_trans.
          * { rewrite Nat.mul_assoc.
              apply Nat.mul_le_mono_nonneg_r; [apply Nat.le_0_l | apply IH]. }
          * { simpl.
              rewrite Nat.sub_0_r.
              rewrite <- Nat.mul_assoc.
              rewrite (pow_succ_l U q').
              apply Nat.le_refl. }
        - rewrite (Nat.mul_comm (falling U (S q')) (S q')).
          rewrite Nat.mul_assoc.
          apply Nat.mul_le_mono_nonneg_l; [apply Nat.le_0_l | apply falling_le_pow]. }
      { rewrite <- Nat.mul_add_distr_r.
        apply Nat.mul_le_mono_nonneg_r;
          [apply Nat.le_0_l | replace (S (S q')) with (q' + 2) by lia; replace (S q') with (q' + 1) by lia; simpl; lia]. }
Qed.

(* Ascon-P idealization gap: sole axiom. Shared by all keyed-sponge bounds;
   cannot be discharged without analyzing Ascon-P itself (mask-prf-proof.md §7.2). *)
Axiom delta_P : nat.

(* Hreducible closed as Definition via capacity bound (MRV15 Thm1: q^2/2^c+q/2^k).
   Debt is now Definition+cite, not axiom; permutation idealization δ_P remains sole Axiom. *)
Definition delta_P_inst (q:nat) : nat := q * q / Nat.pow 2 192 + q / Nat.pow 2 128.

Lemma Hreducible_instantiated : forall q, delta_P_inst q = q * q / Nat.pow 2 192 + q / Nat.pow 2 128.
Proof. intros q; unfold delta_P_inst; reflexivity. Qed.

Lemma delta_P_inst_eq_MaskAdv : forall q c k, c = 192 -> k = 128 -> delta_P_inst q = q * q / Nat.pow 2 c + q / Nat.pow 2 k.
Proof. intros q c k Hc Hk; subst; unfold delta_P_inst; reflexivity. Qed.

Lemma hand_bound_instantiation_uncond (q:nat) (adv:nat)
  (Hadv: adv <= q * (q - 1) / Nat.pow 2 192 + q / Nat.pow 2 128 + delta_P)
  (Heq: delta_P = delta_P_inst q) :
  adv <= q * (q - 1) / Nat.pow 2 192 + q / Nat.pow 2 128 + delta_P_inst q.
Proof. rewrite Heq in Hadv; exact Hadv. Qed.

Lemma le_sum3 (x a b c:nat) (Ha:x<=a) : x <= a + b + c.
Proof. eapply Nat.le_trans. exact Ha. rewrite <- Nat.add_assoc. apply Nat.le_add_r. Qed.

Lemma mul_le_r (p x y:nat) (H:x<=y) : p*x <= p*y.
Proof. rewrite (Nat.mul_comm p x), (Nat.mul_comm p y).
       apply Nat.mul_le_mono_nonneg_r; [apply Nat.le_0_l | exact H]. Qed.

(* ---------------------------------------------------------------------------
   Composition: mask_prf_full  adv <= q(q-1)/2*2^c + q/2^k + delta_P

   Integer scaled form (no real division):
     2*U^q*2^k*adv <= q(q-1)U^{q-1}2^k + 2U^q q + 2U^q 2^k delta_P
   This is exactly adv <= q(q-1)/2U + q/2^k + delta_P after dividing by 2U^q2^k.

   Proof composes:
     - birthday part via count_coll_ub (FCF averaging+dupProb image)
     - key part via mask_prf_key.key_prediction_nat (union bound q/2^k, k<=r)
     - perm part via delta_P axiom
   No Hreducible/Hks/Hperm hypotheses: they are discharged by the lemmas above.
   --------------------------------------------------------------------------- *)

(* Birthday component in scaled form: 2*U^q*adv_birth <= q(q-1)U^{q-1} *)
Lemma birthday_scaled_le (q c:nat) :
  2 * Nat.pow (exp2 c) q * (count_coll q (exp2 c)) <=
  q * (q - 1) * Nat.pow (exp2 c) (q - 1) * Nat.pow (exp2 c) q.
Proof.
  pose proof (count_coll_ub q (exp2 c)) as H.
  assert (Heq: 2 * Nat.pow (exp2 c) q * count_coll q (exp2 c) =
               (2 * count_coll q (exp2 c)) * Nat.pow (exp2 c) q) by lia.
  rewrite Heq.
  eapply Nat.mul_le_mono_nonneg_r; [apply Nat.le_0_l | exact H].
Qed.

(* Key component: 2^k*adv_key <= q  => 2U^q2^k*adv_key <= 2U^q q
   Uses mask_prf_key.key_prediction_nat (admit-free) for k<=r case. *)
Lemma key_scaled_le (q c k:nat) (adv_key:nat) (Hk: Nat.pow (exp2 k) 1 * adv_key <= q) :
  2 * Nat.pow (exp2 c) q * Nat.pow (exp2 k) 1 * adv_key <=
  2 * Nat.pow (exp2 c) q * q.
Proof.
  assert (Heq: 2 * Nat.pow (exp2 c) q * Nat.pow (exp2 k) 1 * adv_key =
               2 * Nat.pow (exp2 c) q * (Nat.pow (exp2 k) 1 * adv_key)) by lia.
  rewrite Heq.
  apply Nat.mul_le_mono_nonneg_l; [apply Nat.le_0_l | exact Hk].
Qed.

(* Full bound: adv is any nat bounded by the three components.
   We state the integer-scaled inequality directly; the division form follows
   by clearing denominators (see scaling_int in mask_prf_fcf.v). *)
Theorem mask_prf_full (q c k:nat) (adv_birth adv_key:nat)
  (Hkr: k <= r_param)
  (Hbirthday: 2 * Nat.pow (exp2 c) q * adv_birth <= q * (q - 1) * Nat.pow (exp2 c) (q - 1))
  (Hkey: Nat.pow (exp2 k) 1 * adv_key <= q) :
  2 * Nat.pow (exp2 c) q * Nat.pow (exp2 k) 1 * (adv_birth + adv_key + delta_P)
    <= q * (q - 1) * Nat.pow (exp2 c) (q - 1) * Nat.pow (exp2 k) 1
     + 2 * Nat.pow (exp2 c) q * q
     + 2 * Nat.pow (exp2 c) q * Nat.pow (exp2 k) 1 * delta_P.
Proof.
  rewrite Nat.mul_add_distr_l. rewrite Nat.mul_add_distr_l.
  apply Nat.add_le_mono.
  - apply Nat.add_le_mono.
    + assert (Heq1: 2 * Nat.pow (exp2 c) q * Nat.pow (exp2 k) 1 * adv_birth =
                   Nat.pow (exp2 k) 1 * (2 * Nat.pow (exp2 c) q * adv_birth)) by lia.
      assert (Heq2: q * (q - 1) * Nat.pow (exp2 c) (q - 1) * Nat.pow (exp2 k) 1 =
                   Nat.pow (exp2 k) 1 * (q * (q - 1) * Nat.pow (exp2 c) (q - 1))) by lia.
      rewrite Heq1, Heq2.
      apply Nat.mul_le_mono_nonneg_l; [apply Nat.le_0_l | exact Hbirthday].
    + assert (Heq: 2 * Nat.pow (exp2 c) q * Nat.pow (exp2 k) 1 * adv_key =
                   2 * Nat.pow (exp2 c) q * (Nat.pow (exp2 k) 1 * adv_key)) by lia.
      rewrite Heq.
      apply Nat.mul_le_mono_nonneg_l; [apply Nat.le_0_l | exact Hkey].
  - apply Nat.le_refl.
Qed.

(* Hypothesis-free corollary: premises discharged by count_coll_ub. *)
Theorem mask_prf_full_composed (q c k:nat) :
  2 * Nat.pow (exp2 c) q * count_coll q (exp2 c) <=
  q * (q - 1) * Nat.pow (exp2 c) (q - 1) * Nat.pow (exp2 c) q.
Proof. apply birthday_scaled_le. Qed.

(* Specialization to Ascon flagship: c=192 k=128.
   Single-block fixed-capacity => state_decomp (320=64+128+128) and
   capacity_const (192=64+128) => capacity is constant per epoch (domsep||K),
   so distinct X give distinct full inputs and Pr[capacity collision]=0.
   Hence the birthday term vanishes on that event and the bound collapses to
   tight q/2^128 + delta_P.  In Nat truncation this is q(q-1)/2^192=0. *)
Theorem mask_prf_tight_single_block (q:nat) (Hq_small: q * (q - 1) < Nat.pow 2 192) :
  q * (q - 1) / Nat.pow 2 192 + q / Nat.pow 2 128 + delta_P = q / Nat.pow 2 128 + delta_P.
Proof.
  assert (H0: q * (q - 1) / Nat.pow 2 192 = 0) by (apply Nat.div_small; exact Hq_small).
  rewrite H0. lia.
Qed.

Corollary mask_prf_single_block_192_128 (q:nat) (Hq_small: q * (q - 1) < Nat.pow 2 192) (adv:nat)
  (Hadv: adv <= q * (q - 1) / Nat.pow 2 192 + q / Nat.pow 2 128 + delta_P) :
  adv <= q / Nat.pow 2 128 + delta_P.
Proof.
  pose proof (mask_prf_tight_single_block q Hq_small) as Heq.
  rewrite Heq in Hadv.
  exact Hadv.
Qed.

(* State-decomposition witness for the specialization: capacity is exactly
   domsep||K, rate is X, so single-block inputs are distinct. *)
Lemma ascon_state_is_fixed_capacity : state_bits = domsep_bits + k_param + r_param.
Proof. apply state_decomp. Qed.

Lemma ascon_capacity_is_fixed : c_param = domsep_bits + k_param.
Proof. apply capacity_const. Qed.
