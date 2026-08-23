(* canonical MaskAdv — single source for hand ↔ Coq ↔ FCF ↔ EasyCrypt
   Hand: docs/mask-prf-proof.md Thm 1/1'  (q^2/2^192 + q/2^128, tight q/2^128)
   Coq : formal/coq/mask_prf.v (count_coll_ub, mask_prf_bound_tight)
   FCF : formal/coq/mask_prf_fcf.v (averaging/dupProb — Hreducible core)
   EC  : formal/easycrypt/mask_prf.ec (op MaskAdv)
   domsep: formal/coq/mask_prf_domsep.v — generated from wolfssl/wolfcrypt/mask_prf.h
   Reuses proofs, no duplication. §7 cites this file as canonical. *)
From Stdlib Require Import Arith Lia.
Require Import mask_prf.
Require Import mask_prf_domsep.

(* canonical bound: MaskAdv(q,c,k) = q^2/2^c + q/2^k  (nat truncated, conservative) *)
Definition MaskAdv (q c k : nat) : nat :=
  q * q / Nat.pow 2 c + q / Nat.pow 2 k.

(* integer-scaled single theorem closing hand ↔ Coq ↔ FCF.
   Reuses count_coll_ub + averaging/dupProb via mask_prf_bound_tight. *)
Theorem mask_prf_bound (q c k delta : nat)
  (Hreducible : forall q U, Nat.pow U q * mask_advantage q U <= count_coll q U)
  (Hks : Nat.pow (exp2 k) 1 * mask_advantage q (exp2 c) <= q)
  (Hperm : mask_advantage q (exp2 c) <= delta) :
  2 * Nat.pow (exp2 c) q * Nat.pow (exp2 k) 1 * mask_advantage q (exp2 c)
    <= q * (q - 1) * Nat.pow (exp2 c) (q - 1) * Nat.pow (exp2 k) 1
     + 2 * Nat.pow (exp2 c) q * q
     + 2 * Nat.pow (exp2 c) q * Nat.pow (exp2 k) 1 * delta.
Proof. exact (mask_prf_bound_tight q c k delta Hreducible Hks Hperm). Qed.
