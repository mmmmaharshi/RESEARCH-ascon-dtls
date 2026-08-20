(* mask_prf.v - Rocq/Coq mechanization of the dominant birthday term of the
   Ascon record-number mask PRF bound (see mask-prf-proof.md, Theorem 1).

   What is MACHINE-CHECKED here:
     count_coll_ub  :  2 * count_coll q U  <=  q*(q-1) * U^(q-1)
   i.e. the collision probability among q uniform samples from a universe of
   size U is at most q*(q-1)/(2U). With U = 2^c (c = Ascon capacity = 192),
   this is the q^2/2^c dominant term of the mask bound.

   The mask PRF advantage is then bounded by this collision probability under
   the IDEAL-PERMUTATION modeling hypotheses (Hideal, Hreducible) - exactly the
   assumption under which the hand proof in mask-prf-proof.md is made. The tight
   q/2^128 specialization (Theorem 1') remains a hand argument (see doc §7).

   Compile:  coqc mask_prf.v
*)

From Stdlib Require Import Arith.PeanoNat Lia.

Open Scope nat_scope.

Definition exp2 (k:nat) : nat := Nat.pow 2 k.

(* Falling factorial (U)_q = U*(U-1)*...*(U-q+1). *)
Fixpoint falling (U q:nat) : nat :=
  match q with
  | 0 => 1
  | S q' => U * falling (U - 1) q'
  end.

(* Number of length-q sequences over {0..U-1} containing a duplicate.
   Recurrence (derived by splitting on whether the prefix already duplicates):
     count_coll 0 U = 0
     count_coll 1 U = 0
     count_coll (S q) U = count_coll q U * U + falling U q * q
   (first q duplicate, OR first q distinct and the new element equals one of
    the q distinct ones). *)
Fixpoint count_coll (q U:nat) : nat :=
  match q with
  | 0 => 0
  | 1 => 0
  | S q' => count_coll q' U * U + falling U q' * q'
  end.

Definition total (U q:nat) : nat := Nat.pow U q.

(* Trivial: (U)_q <= U^q. Used in the induction below. *)
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

(* Recurrence of count_coll (used in the induction step). *)
Lemma count_coll_rec (q U:nat) :
  count_coll (S q) U = count_coll q U * U + falling U q * q.
Proof.
  destruct q as [| q'].
  - simpl. reflexivity.
  - simpl. reflexivity.
Qed.

(* MAIN COMBINATORIAL RESULT: the birthday bound. *)
Lemma pow_succ_l (U n:nat) : Nat.pow U n * U = Nat.pow U (S n).
Proof. rewrite Nat.mul_comm. reflexivity. Qed.

Lemma count_coll_ub (q U:nat) :
  2 * count_coll q U <= q * (q - 1) * Nat.pow U (q - 1).
Proof.
  revert U. induction q as [| q1 IH]; intro U.
  - simpl. apply Nat.le_0_l.
  - destruct q1 as [| q'].
    + simpl. apply Nat.le_0_l.
    + (* original q = S (S q') >= 2 ; goal: 2*count_coll (S(S q')) U <= (S(S q'))*(S q')*U^(S q') *)
      rewrite (count_coll_rec (S q') U).
      rewrite Nat.mul_add_distr_l.
      eapply Nat.le_trans.
      { apply Nat.add_le_mono.
        - (* addend 1: 2 * count_coll (S q') U * U <= (S q') * q' * U^(S q')  (by IH) *)
          eapply Nat.le_trans.
          * { rewrite Nat.mul_assoc.
              apply Nat.mul_le_mono_nonneg_r; [apply Nat.le_0_l | apply IH]. }
          * { simpl.
              rewrite Nat.sub_0_r.
              rewrite <- Nat.mul_assoc.
              rewrite (pow_succ_l U q').
              apply Nat.le_refl. }
        - (* addend 2: 2 * (falling U (S q') * (S q')) <= 2 * (S q') * U^(S q') *)
          rewrite (Nat.mul_comm (falling U (S q')) (S q')).
          rewrite Nat.mul_assoc.
          apply Nat.mul_le_mono_nonneg_l; [apply Nat.le_0_l | apply falling_le_pow]. }
      { rewrite <- Nat.mul_add_distr_r.
        apply Nat.mul_le_mono_nonneg_r;
          [apply Nat.le_0_l | replace (S (S q')) with (q' + 2) by lia; replace (S q') with (q' + 1) by lia; simpl; lia]. }
Qed.

(* ---------------------------------------------------------------------------
   Mask PRF reduction (ideal-permutation model).

   mask_advantage q U is the adversary's PRF advantage for q queries when the
   underlying permutation is ideal and the universe of capacity-states has size
   U. It is left abstract. The hypothesis Hreducible states the standard
   modeling fact that turns the combinatorial bound into a security statement:
   the mask advantage is at most the collision probability. This is exactly the
   assumption made in the hand proof (mask-prf-proof.md, ideal-permutation
   model); the tight q/2^128 specialization (Theorem 1') remains a hand
   argument (see doc §7).
*)

Parameter mask_advantage : nat -> nat -> nat.

(* The mask PRF bound, chained from the machine-checked birthday lemma.
   States (in integer form):  2 * U^q * adv  <=  q*(q-1) * U^(q-1)
   i.e.  adv  <=  q*(q-1) / (2 * U)   with U = 2^c. *)
Theorem mask_prf_bound
  (q c:nat)
  (Hreducible : forall q U, Nat.pow U q * mask_advantage q U <= count_coll q U) :
  2 * Nat.pow (exp2 c) q * mask_advantage q (exp2 c)
    <= q * (q - 1) * Nat.pow (exp2 c) (q - 1).
Proof.
  unfold exp2.
  eapply Nat.le_trans.
  - rewrite <- Nat.mul_assoc.
    apply Nat.mul_le_mono_nonneg_l; [apply Nat.le_0_l | apply Hreducible].
  - apply count_coll_ub.
Qed.
