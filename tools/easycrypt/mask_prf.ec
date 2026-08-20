(* mask_prf.ec — EasyCrypt scaffold for the keyed-sponge record-number mask PRF.
 *
 * STATUS: SCAFFOLD / WORK-IN-PROGRESS. Requires EasyCrypt + Why3 + Alt-Ergo/Z3.
 * NOT machine-checked yet. The corresponding hand proof is in mask-prf-proof.md
 * (Theorems 1, 1', 2, 3). This file is the executable target for that proof.
 *
 * Goal (per mask-prf-proof.md):
 *   Thm 1  (conservative) : Adv <= q^2/2^192 + q/2^128 + delta_P
 *   Thm 1' (tight)        : Adv <= q/2^128 + delta_P   (single-block, fixed capacity)
 *   Thm 2  (PQ, QROM)     : Adv <= q^2/2^96  + q/2^64  + delta_P^Q
 *   Thm 3  (RFC dominance): bound(mask) < bound(RFC AES-ECB = q^2/2^128)  for all q
 *)

require import AllCore.
require import FSet.
require import Finite.

(* ------------------------------------------------------------------ *)
(* Finite state domain, abstracted (320-bit Ascon-P state).            *)
(* ------------------------------------------------------------------ *)
type state.

(* Ideal random permutation P and its inverse. In a complete proof this
   is instantiated with the finite-function permutation library (ffun)
   or an oracle game; here it is an abstract bijection. *)
module type PERM = {
  fun p   (x:state) : state
  fun pinv (y:state) : state
}.

axiom perm_bij (P <: PERM) :
  forall x, P.pinv(P.p x) = x /\ P.p(P.pinv x) = x.

(* ------------------------------------------------------------------ *)
(* Mask oracle. K : 128-bit key (sn_key). domsep : public constant.   *)
(* ct : 128-bit rate block = first 16 bytes of AEAD ciphertext.        *)
(* Mask_K(ct) = low16( P(domsep || K || ct) ).                         *)
(* pack : key -> block -> state  assembles the 320-bit state.          *)
(* proj : state -> block               extracts the low 16 bits.       *)
(* ------------------------------------------------------------------ *)
type key.
type block.
op  pack : key -> block -> state.
op  proj : state -> block.

module Mask (P:PERM) = {
  var k : key
  fun mask (ct:block) : block = {
    var s; s <- P.p (pack k ct); return proj s;
  }
}.

(* ------------------------------------------------------------------ *)
(* PRF experiments. Real oracle = Mask_K; Ideal oracle = random fn.    *)
(* (Full game wiring — challenger, query counting, adversary hook —    *)
(* is abbreviated in this scaffold; the structure is standard.)        *)
(* ------------------------------------------------------------------ *)
module type ADV = { fun distinguish () : bool }.

(* adv_ctr counts queries. q = max queries. *)
const q : int.
axiom q_pos : 0 < q.

(* Placeholder experiment signatures; concrete wiring filled in during
   mechanization. The distinguishing advantage is:
     `| Pr[Real.distinguish() @ &m : res] - Pr[Ideal.distinguish() @ &m : res] | *)
module type GAME = { fun distinguish () : bool }.

(* ------------------------------------------------------------------ *)
(* Lemma 1 (conservative bound).                                       *)
(* Proof plan:                                                         *)
(*   G0 real -> G1 replace Ascon-P by ideal perm P  (gap = delta_P)   *)
(*   G1 ideal-perm -> apply keyed-sponge PRF bound                     *)
(*        (Mennink-Reyhanitabar-Vizar ASIACRYPT'15;                    *)
(*         Dobraunig-Mennink ToSC'19/573; Mennink ToSC'18/449 Thm 1)  *)
(*        => q^2/2^192 + q/2^128                                       *)
(*   truncation (low 16 bits) only reduces advantage.                  *)
(* ------------------------------------------------------------------ *)
lemma mask_prf_conservative &m (A <: ADV) (P <: PERM) :
  `| Pr[GReal(P,Mask(P),A).distinguish() @ &m : res] -
     Pr[GIdeal(A).distinguish() @ &m : res] |
  <= (q * q)%r / (2^192) + q / (2^128) + delta_P.
proof.
  admit.   (* TODO: game hops; see plan above. *)
qed.

(* ------------------------------------------------------------------ *)
(* Lemma 1' (tight). Single-block, fixed-capacity instance has no      *)
(* inner collision, so the q^2/2^192 term is vacuous: Adv <= q/2^128.  *)
(* ------------------------------------------------------------------ *)
lemma mask_prf_tight &m (A <: ADV) (P <: PERM) :
  `| Pr[GReal(P,Mask(P),A).distinguish() @ &m : res] -
     Pr[GIdeal(A).distinguish() @ &m : res] |
  <= q / (2^128) + delta_P.
proof.
  admit.   (* TODO: argue capacity fixed => no collision => key-prediction only. *)
qed.

(* ------------------------------------------------------------------ *)
(* Lemma 2 (post-quantum, QROM). Exponents halved (Hosoyamada ToSC'25).*)
(* ------------------------------------------------------------------ *)
lemma mask_prf_pq &m (A <: ADV) (P <: PERM) :
  `| Pr[GReal(P,Mask(P),A).distinguish() @ &m : res] -
     Pr[GIdeal(A).distinguish() @ &m : res] |
  <= (q * q)%r / (2^96) + q / (2^64) + delta_P_q.
proof.
  admit.   (* TODO: QROM variant (pqeuclidean). *)
qed.

(* ------------------------------------------------------------------ *)
(* Lemma 3 (RFC 9147 §4.2.3 dominance). The RFC AES-ECB mask has      *)
(* Adv <= q^2/2^128. For every q, q^2/2^192 + q/2^128 < q^2/2^128, so  *)
(* our mask dominates. (Formalized by bounding both and comparing.)    *)
(* ------------------------------------------------------------------ *)
lemma mask_dominates_rfc &m (A <: ADV) (P <: PERM) :
  (q * q)%r / (2^192) + q / (2^128) + delta_P < (q * q)%r / (2^128) + delta_AES.
proof.
  admit.   (* TODO: algebraic comparison of the two bounds. *)
qed.
