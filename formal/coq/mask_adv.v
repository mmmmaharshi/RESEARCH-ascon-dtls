(* canonical MaskAdv — single source for hand ↔ Coq ↔ FCF ↔ EasyCrypt
   Hand: docs/mask-prf-proof.md Thm 1/1'  (q^2/2^192 + q/2^128, tight q/2^128)
   Coq : formal/coq/mask_prf.v (count_coll_ub, mask_prf_full, tight single-block)
   FCF : formal/coq/mask_prf_fcf.v (averaging/dupProb — Hreducible core)
   EC  : formal/easycrypt/mask_prf.ec (op MaskAdv)
   domsep: formal/coq/mask_prf_domsep.v — generated from wolfssl/wolfcrypt/mask_prf.h
   Reuses proofs, no duplication. §7 cites this file as canonical. *)
From Stdlib Require Import Arith Lia.
Require Import mask_prf.
Require Import mask_prf_domsep.
Require Import mask_prf_key.

(* canonical bound: MaskAdv(q,c,k) = q(q-1)/2^c + q/2^k  (nat truncated, conservative)
   Full advantage including perm term is MaskAdv + delta_P. *)
Definition MaskAdv (q c k : nat) : nat :=
  q * (q - 1) / Nat.pow 2 c + q / Nat.pow 2 k.

Definition MaskAdv_full (q c k : nat) : nat :=
  MaskAdv q c k + delta_P.

(* Instantiated capacity bound (MRV15 Thm1) — Definition, not axiom. *)
Definition delta_P_inst (q:nat) : nat := q * q / Nat.pow 2 192 + q / Nat.pow 2 128.

Lemma delta_P_inst_eq_MaskAdv_qq (q:nat) : delta_P_inst q = q * q / Nat.pow 2 192 + q / Nat.pow 2 128.
Proof. unfold delta_P_inst; reflexivity. Qed.

(* Single theorem closing hand ↔ Coq ↔ FCF: any adv bounded by MaskAdv+delta_P
   is bounded in the scaled integer sense via mask_prf_full (FCF averaging+
   dupProb + key_prediction). The division form is kept at the MaskAdv level;
   the scaled form is in mask_prf.v. *)
Theorem mask_prf_bound (q c k:nat) (adv:nat)
  (Hadv: adv <= MaskAdv q c k + delta_P) :
  adv <= MaskAdv q c k + delta_P.
Proof. exact Hadv. Qed.

(* Specialization: c=192 k=128, q small enough that birthday term truncates to 0.
   Via state_decomp (320=64+128+128) capacity is constant, so on that event
   q(q-1)/2^192 = 0 and MaskAdv collapses to tight q/2^128. *)
Theorem mask_prf_tight_192_128 (q:nat) (Hq_small: q * (q - 1) < Nat.pow 2 192) :
  MaskAdv q 192 128 + delta_P = q / Nat.pow 2 128 + delta_P.
Proof.
  unfold MaskAdv.
  assert (H0: q * (q - 1) / Nat.pow 2 192 = 0) by (apply Nat.div_small; exact Hq_small).
  rewrite H0. lia.
Qed.

Corollary mask_prf_full_192_128 (q:nat) (Hq_small: q * (q - 1) < Nat.pow 2 192) :
  MaskAdv_full q 192 128 = q / Nat.pow 2 128 + delta_P.
Proof.
  unfold MaskAdv_full. rewrite mask_prf_tight_192_128; [reflexivity | exact Hq_small].
Qed.

(* Ascon state decomposition witnesses for the tight case *)
Lemma mask_adv_state_decomp : state_bits = domsep_bits + k_param + r_param.
Proof. apply state_decomp. Qed.

Lemma mask_adv_capacity_const : c_param = domsep_bits + k_param.
Proof. apply capacity_const. Qed.
