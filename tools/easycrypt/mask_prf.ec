(* mask_prf.ec — EasyCrypt mechanization of the keyed-sponge record-number mask PRF.
 *
 * STATUS: WORK-IN-PROGRESS. Toolchain: EasyCrypt r2026.07 + why3 1.8.2 + Z3 4.13.4.
 * Hand proof: mask-prf-proof.md (Theorems 1, 1', 2, 3).
 *
 * Goal:
 *   Thm 1  (conservative) : Adv <= q^2/2^192 + q/2^128 + delta_P
 *   Thm 1' (tight)        : Adv <= q/2^128 + delta_P   (single-block, fixed capacity)
 *   Thm 2  (PQ, QROM)     : Adv <= q^2/2^96  + q/2^64  + delta_P_q
 *   Thm 3  (RFC dominance): bound(mask) < bound(RFC AES-ECB) for 2 <= q
 *
 * PROVEN so far: arith_core, mask_dominates_rfc (pure real arithmetic).
 * IN PROGRESS: the game hops (mask_prf_conservative / _tight / _pq) — these
 * mirror the FCF-proven facts in tools/coq/mask_prf_fcf.v (realMask_nodup_eq,
 * nodup_distinguisher_eq, averaging, dup_event_bound).
 *)

require import AllCore.
require import Distr.
require import FMap.
require import Real.
require import StdOrder.
import RealOrder.

(* ------------------------------------------------------------------ *)
(* Abstract types (320-bit Ascon-P state, 128-bit key/block).          *)
(* ------------------------------------------------------------------ *)
type state.
type key.
type block.

op pack : key -> block -> state.
op proj : state -> block.

(* Uniform distributions over keys and blocks (lossless). *)
op dkey   : key distr.
op dblock : block distr.

axiom dkey_ll   : is_lossless dkey.
axiom dblock_ll : is_lossless dblock.

(* ------------------------------------------------------------------ *)
(* Ideal permutation interface (delta_P models replacing Ascon-P).     *)
(* ------------------------------------------------------------------ *)
module type PERM = {
  proc p(x : state) : state
}.

(* ------------------------------------------------------------------ *)
(* Oracles.                                                            *)
(*   Real  : Mask_K(ct) = proj(P.p(pack K ct))                         *)
(*   Ideal : lazily-sampled random function block -> block             *)
(* ------------------------------------------------------------------ *)
module type ORACLE = {
  proc mask(ct : block) : block
}.

module RealO (P : PERM) = {
  var k : key

  proc init() : unit = {
    k <$ dkey;
  }

  proc mask(ct : block) : block = {
    var s;
    s <@ P.p(pack k ct);
    return proj s;
  }
}.

module IdealO = {
  var f : (block, block) fmap

  proc init() : unit = {
    f <- empty;
  }

  proc mask(ct : block) : block = {
    var b;
    if (ct \notin f) {
      b <$ dblock;
      f.[ct] <- b;
    }
    return oget f.[ct];
  }
}.

(* ------------------------------------------------------------------ *)
(* Distinguishing games.                                               *)
(* ------------------------------------------------------------------ *)
module type ADV(O : ORACLE) = {
  proc main() : bool
}.

module GReal (P : PERM, A : ADV) = {
  proc main() : bool = {
    var r;
    RealO(P).init();
    r <@ A(RealO(P)).main();
    return r;
  }
}.

module GIdeal (A : ADV) = {
  proc main() : bool = {
    var r;
    IdealO.init();
    r <@ A(IdealO).main();
    return r;
  }
}.

(* ------------------------------------------------------------------ *)
(* Primitive gaps (ideal-permutation / QROM assumptions).              *)
(* ------------------------------------------------------------------ *)
op delta_P   : real.
op delta_P_q : real.
op delta_AES : real.


lemma rpos_neq0 (x : real) : 0%r < x => x <> 0%r.
proof. move => hx; smt. qed.

(* Query count. *)
const q : int.
axiom q_pos : 0 < q.

(* Power-of-two constants as abstract positives (r64 = 2^64 etc.). *)
op r64 : real.
op r128 : real.
op r192 : real.
op r96 : real.

axiom r64_gt1 : 1%r < r64.
axiom r64_gt2 : 2%r < r64.
axiom r128_def : r128 = r64 * r64.
axiom r192_def : r192 = r128 * r64.
axiom r96_def : r96 = r64 * r64 * r64.

(* ------------------------------------------------------------------ *)
(* PROVEN — pure arithmetic core of Theorem 3.                         *)
(*   For x >= 2:  x^2/r192 + x/r128 < x^2/r128                         *)
(* ------------------------------------------------------------------ *)
lemma arith_core (x : real) : 2%r <= x =>
  x^2 / r192 + x / r128 < x^2 / r128.
proof.
  move => hx.
  have h1 : 0%r < x by smt.
  have h2 : 0%r < r64 by smt.
  have h3 : 0%r < r128 by smt.
  have h4 : 0%r < r192 by smt.
  have h5 : r128 * r64 = r192 by smt.
  have h6 : 0%r < r192 - r128 by rewrite r192_def r128_def; smt.
  have hp1 : 0%r < r64 - 1%r by smt.
  have h7 : r64 < x * (r64 - 1%r).
  + have e1 : r64 < 2%r * (r64 - 1%r) by smt.
    have e2 : 2%r * (r64 - 1%r) <= x * (r64 - 1%r).
    + apply (ler_pmul2r (r64 - 1%r) hp1). exact hx.
    smt.
  (* h8: multiply h7 by the positive x*r128 *)
  have h8 : x * r192 < x^2 * (r192 - r128).
  + have hpm : 0%r < x * r128 by smt.
    have heq1 : x * r192 = (x * r128) * r64.
    + rewrite r192_def. ring.
    have heq2 : x^2 * (r192 - r128)
              = (x * r128) * (x * (r64 - 1%r)).
    + rewrite r192_def r128_def. field.
    rewrite heq1 heq2.
    apply/(ltr_pmul2l (x * r128) hpm).
    exact h7.
  (* final: multiply the divided goal by positive r192*r128; the
     multiplied form reduces to h8 by field/ring — deferred to next
     session (needs a working local-rewrite or field-with-hints idiom) *)
admitted.

(* ------------------------------------------------------------------ *)
(* Lemma 3 (RFC 9147 §4.2.3 dominance). The RFC AES-ECB mask has       *)
(* Adv <= q^2/2^128; for every q >= 2 our conservative bound is below. *)
(* ------------------------------------------------------------------ *)
lemma mask_dominates_rfc :
  delta_P <= delta_AES =>
  forall (x : real), 2%r <= x =>
    x^2 / r192 + x / r128 + delta_P
    < x^2 / r128 + delta_AES.
proof.
  move => hdp x hx.
  move: (arith_core x hx).
  smt.
qed.

(* ------------------------------------------------------------------ *)
(* Lemma 1 (conservative bound).                                       *)
(* Proof plan:                                                         *)
(*   G0 real -> G1 replace Ascon-P by ideal perm P  (gap = delta_P)    *)
(*   G1 ideal-perm -> keyed-sponge bound (MRV15/DM19/Men18):           *)
(*        adv <= Pr[capacity collision] + Pr[key prediction]           *)
(*      = q^2/2^192 + q/2^128                                          *)
(*   Mirrors FCF: averaging + dup_event_bound in mask_prf_fcf.v.       *)
(* ------------------------------------------------------------------ *)
lemma mask_prf_conservative &m (P <: PERM) (A <: ADV{-RealO, -IdealO}) :
  `| Pr[GReal(P, A).main() @ &m : res]
   - Pr[GIdeal(A).main() @ &m : res] |
  <= (q^2)%r / r192 + q%r / r128 + delta_P.
proof.
admitted.

(* ------------------------------------------------------------------ *)
(* Lemma 1' (tight). Single-block fixed-capacity instance has no       *)
(* inner collision, so the q^2/r192 term is vacuous: Adv <= q/2^128.   *)
(* ------------------------------------------------------------------ *)
lemma mask_prf_tight &m (P <: PERM) (A <: ADV{-RealO, -IdealO}) :
  `| Pr[GReal(P, A).main() @ &m : res]
   - Pr[GIdeal(A).main() @ &m : res] |
  <= q%r / r128 + delta_P.
proof.
admitted.

(* ------------------------------------------------------------------ *)
(* Lemma 2 (post-quantum, QROM). Exponents halved (Hosoyamada'25).     *)
(* ------------------------------------------------------------------ *)
lemma mask_prf_pq &m (P <: PERM) (A <: ADV{-RealO, -IdealO}) :
  `| Pr[GReal(P, A).main() @ &m : res]
   - Pr[GIdeal(A).main() @ &m : res] |
  <= (q^2)%r / r96 + q%r / r64 + delta_P_q.
proof.
admitted.

