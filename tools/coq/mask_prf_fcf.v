Require Import FCF.FCF.
Require Import FCF.CompFold.
Require Import FCF.ProgramLogic.
Require Import FCF.HasDups.
Require Import FCF.RndInList.

Local Open Scope list_scope.

Section MaskPRF.
  Variable c k : nat.
  Definition D := Bvector c.
  Definition R := Bvector k.
  Definition DR := prod D R.

  Fixpoint in_keys (d : D) (f : list DR) : bool :=
    match f with
    | nil => false
    | (d0, _) :: f' => if eqb d d0 then true else in_keys d f'
    end.

  Fixpoint lookup (d : D) (f : list DR) : option R :=
    match f with
    | nil => None
    | (d0, r) :: f' => if eqb d d0 then Some r else lookup d f'
    end.

  Lemma in_keys_none :
    forall (d : D) (f : list DR),
      in_keys d f = false -> lookup d f = None.
  Proof.
    induction f; simpl; intros H.
    - reflexivity.
    - destruct a as [d0 r0]. simpl in H.
      destruct (eqbBvector d d0).
      + simpl in H. discriminate H.
      + simpl in H. simpl. apply IHf. exact H.
  Qed.

  Fixpoint realMask (f : list DR) (ls : list D) : Comp (list R) :=
    match ls with
    | nil => ret nil
    | d :: rest =>
      match lookup d f with
      | Some r => rs <-$ realMask f rest; ret (r :: rs)
      | None => r <-$ Rnd k; rs <-$ realMask ((d, r) :: f) rest; ret (r :: rs)
      end
    end.

  (* Ideal: independent uniform output per query (same bind shape as realMask). *)
  Fixpoint IdealMask (ls : list D) : Comp (list R) :=
    match ls with
    | nil => ret nil
    | d :: rest => r <-$ {0, 1} ^ k; rs <-$ IdealMask rest; ret (r :: rs)
    end.

  (* Dummy-free sequencing wrapper around comp_spec_seq. *)
  Lemma spec_seq : forall (A : Set) (eqda : EqDec A)
    (P : list R -> list R -> Prop)
    (c1 c2 : Comp A) (f1 f2 : A -> Comp (list R)),
    comp_spec eq c1 c2 ->
    (forall x, comp_spec P (f1 x) (f2 x)) ->
    comp_spec P (Bind c1 f1) (Bind c2 f2).
  Proof.
    intros A eqda P c1 c2 f1 f2 H1 H2.
    eapply comp_spec_seq.
    + exact nil.
    + exact nil.
    + exact H1.
    + intros a b _ _ Hab; subst; apply H2.
  Qed.

  (* Same, for boolean-valued continuations (distinguishers). *)
  Lemma spec_seq_bool : forall (A : Set) (eqda : EqDec A)
    (P : bool -> bool -> Prop)
    (c1 c2 : Comp A) (f1 f2 : A -> Comp bool),
    comp_spec eq c1 c2 ->
    (forall x, comp_spec P (f1 x) (f2 x)) ->
    comp_spec P (Bind c1 f1) (Bind c2 f2).
  Proof.
    intros A eqda P c1 c2 f1 f2 H1 H2.
    eapply comp_spec_seq.
    + exact true.
    + exact true.
    + exact H1.
    + intros a b _ _ Hab; subst; apply H2.
  Qed.

  Lemma rnd_refl : comp_spec (fun (x y : R) => x = y) (Rnd k) (Rnd k).
  Proof.
    apply eq_impl_comp_spec_eq.
    intros; reflexivity.
  Qed.

  Theorem realMask_nodup_eq :
    forall (ls : list D) (f : list DR),
      (forall d', in_keys d' f = true -> ~ In d' ls) ->
      NoDup ls ->
      comp_spec (fun (a : list R) (b : list R) => a = b)
                (realMask f ls)
                (IdealMask ls).
  Proof.
    induction ls; intros f Hdis Hnd.
    - simpl. eapply comp_spec_ret; reflexivity.
    - simpl.
      assert (Hna : in_keys a f = false).
      { case_eq (in_keys a f); intros Hcase.
        - exfalso. apply Hdis in Hcase. apply Hcase. apply in_eq.
        - reflexivity. }
      assert (Hnone : lookup a f = None). { apply in_keys_none. exact Hna. }
      rewrite Hnone. simpl.
      assert (Hnd' : NoDup ls). { inversion Hnd; subst; auto. }
      assert (Htail : forall (d' : D) (r0 : R),
                 in_keys d' ((a, r0) :: f) = true -> ~ In d' ls).
      { intros d' r0 Hk. simpl in Hk.
        destruct (eqbBvector d' a) eqn:Heq; simpl in Hk.
        + apply eqbBvector_sound in Heq. subst d'.
          inversion Hnd; subst; auto.
        + intro Hc. apply Hdis in Hk. apply Hk. apply in_cons. exact Hc. }
      eapply spec_seq.
      + apply rnd_refl.
      + intros r. eapply spec_seq.
        * apply (IHls ((a, r) :: f)).
          -- intros d' Hk. apply (Htail d' r). exact Hk.
          -- exact Hnd'.
        * intros x. eapply comp_spec_ret. reflexivity.
  Qed.

  (* Probability form: on collision-free queries the output distributions are
     identical, so any distinguisher has advantage exactly 0 there. *)
  Corollary nodup_evalDist_eq :
    forall (ls : list D) (f : list DR),
      (forall d', in_keys d' f = true -> ~ In d' ls) ->
      NoDup ls ->
      forall x, evalDist (realMask f ls) x == evalDist (IdealMask ls) x.
  Proof.
    intros ls f Hdis Hnd.
    apply (comp_spec_eq_impl_eq (eqd1 := list_EqDec (Bvector_EqDec k))
                                (eqd2 := list_EqDec (Bvector_EqDec k))).
    apply realMask_nodup_eq; assumption.
  Qed.

  (* Distinguisher lift: any boolean post-processing A of the outputs also has
     identical distributions on collision-free queries.  This is the per-fixed-ls
     instance of "advantage is 0 on the no-collision event" used by the hybrid
     argument; combined with FCF's HasDups.dupProb (Pr[hasDups] <= q^2/2^c) and a
     generic total-probability/averaging lemma, it yields adv <= Pr[collision]. *)
  Lemma nodup_distinguisher_eq :
    forall (ls : list D) (f : list DR),
      (forall d', in_keys d' f = true -> ~ In d' ls) ->
      NoDup ls ->
      forall (A : list R -> Comp bool),
        evalDist (r <-$ realMask f ls; A r) true ==
        evalDist (r <-$ IdealMask ls; A r) true.
  Proof.
    intros ls f Hdis Hnd A.
    eapply comp_spec_eq_impl_eq.
    eapply spec_seq_bool.
    - apply realMask_nodup_eq; assumption.
    - intros x. apply eq_impl_comp_spec_eq. intros; reflexivity.
  Qed.


  (* ===== §7.2(a): total-probability averaging lemma =====

     From the per-fixed-ls zero-advantage fact (nodup_distinguisher_eq) and the
     collision event, conclude the probability-form hybrid bound:
     adv(real) <= adv(ideal) + Pr[collision].  Combined with HasDups.dupProb
     (Pr[hasDups of q uniform samples] <= q^2/2^c) this discharges the last
     purely probabilistic hand step of Hreducible. *)

  (* q iid uniform capacity samples *)
  Fixpoint repeatRnd (q : nat) : Comp (list D) :=
    match q with
    | O => ret nil
    | S q' => d <-$ {0,1}^c; ls <-$ repeatRnd q'; ret (d :: ls)
    end.

  Definition DupEvent (q : nat) : Comp bool :=
    ls <-$ repeatRnd q; ret (hasDups (Bvector_EqDec c) ls).

  (* per-ls event probabilities and the collision indicator weight *)
  Definition rlp (A : list R -> Comp bool) (ls : list D) : Rat :=
    evalDist (Bind (realMask nil ls) A) true.
  Definition ilp (A : list R -> Comp bool) (ls : list D) : Rat :=
    evalDist (Bind (IdealMask ls) A) true.
  Definition dupw (ls : list D) : Rat :=
    (if hasDups (Bvector_EqDec c) ls then 1 else 0)%rat.

  (* Pr[ret b] is the indicator of b *)
  Lemma ret_bool_prob : forall (pf : eq_dec bool) (b : bool),
    evalDist (Ret pf b) true == (if b then 1 else 0)%rat.
  Proof.
    intros pf b. simpl. destruct b.
    - destruct (pf true true) as [He | He].
      + reflexivity.
      + exfalso. apply He. reflexivity.
    - destruct (pf false true) as [He | He].
      + exfalso. discriminate He.
      + reflexivity.
  Qed.

  (* pointwise-monotone sums (not in FCF's Fold) *)
  Lemma sumList_body_le :
    forall (A : Set) (ls : list A) (f g : A -> Rat),
      (forall a, In a ls -> f a <= g a) ->
      sumList ls f <= sumList ls g.
  Proof.
    intros A ls f g H.
    induction ls as [| a ls IH].
    - unfold sumList. simpl. apply leRat_refl.
    - rewrite (sumList_cons ls a f), (sumList_cons ls a g).
      eapply ratAdd_leRat_compat.
      + apply H. left. reflexivity.
      + apply IH. intros a' Ha'. apply H. right. exact Ha'.
  Qed.

  (* Generic total-probability averaging: if per-sample branch g is bounded by 1
     and coincides with h on collision-free samples, then the mixed game
     (g-branch) is at most the h-game plus the collision weight. *)
  Theorem averaging_gen :
    forall (q : nat) (g h : list D -> Comp bool),
      (forall ls, evalDist (g ls) true <= 1) ->
      (forall ls,
        hasDups (Bvector_EqDec c) ls = false ->
        evalDist (g ls) true == evalDist (h ls) true) ->
      evalDist (ls <-$ repeatRnd q; g ls) true <=
      (evalDist (ls <-$ repeatRnd q; h ls) true +
       evalDist (DupEvent q) true)%rat.
  Proof.
    intros q g h Hbnd Heq.
    set (S := getSupport (repeatRnd q)).
    set (w := evalDist (repeatRnd q)).
    (* total probability: expand each game over the capacity samples *)
    assert (Hreal : evalDist (ls <-$ repeatRnd q; g ls) true ==
                    sumList S (fun ls => w ls * evalDist (g ls) true)).
    { apply evalDist_seq_step. }
    assert (Hideal : evalDist (ls <-$ repeatRnd q; h ls) true ==
                     sumList S (fun ls => w ls * evalDist (h ls) true)).
    { apply evalDist_seq_step. }
    assert (Hdup : evalDist (DupEvent q) true ==
                   sumList S (fun ls => w ls * dupw ls)).
    { unfold DupEvent.
      eapply eqRat_trans with
        (r2 := sumList S
                 (fun ls => w ls *
                    evalDist (ret (hasDups (Bvector_EqDec c) ls)) true)).
      - apply evalDist_seq_step.
      - apply sumList_body_eq. intros a _. unfold dupw.
        destruct (hasDups (Bvector_EqDec c) a) eqn:E.
        + apply ratMult_eqRat_compat.
          * apply eqRat_refl.
          * apply (ret_bool_prob _).
        + apply ratMult_eqRat_compat.
          * apply eqRat_refl.
          * apply (ret_bool_prob _). }
    rewrite Hreal, Hideal, Hdup.
    (* split every sum into no-dups / has-dups parts *)
    assert (Hpart : forall f : list D -> Rat,
              sumList S f ==
              (sumList (filter (fun a => negb (hasDups (Bvector_EqDec c) a)) S) f +
               sumList (filter (hasDups (Bvector_EqDec c)) S) f)%rat).
    { intros f. eapply eqRat_trans.
      - apply sumList_filter_partition.
      - apply ratAdd_comm. }
    rewrite !Hpart.
    set (ND := filter (fun a => negb (hasDups (Bvector_EqDec c) a)) S).
    set (HD := filter (hasDups (Bvector_EqDec c)) S).
    (* on the no-dups part the two branches coincide exactly *)
    assert (Hndpt : forall ls, In ls ND ->
                    evalDist (g ls) true == evalDist (h ls) true).
    { intros ls Hin. unfold ND in Hin. apply filter_In in Hin.
      destruct Hin as [_ Hh]. apply negb_true_iff in Hh.
      apply Heq. exact Hh. }
    assert (Hnd_sum : sumList ND (fun ls => w ls * evalDist (g ls) true) ==
                      sumList ND (fun ls => w ls * evalDist (h ls) true)).
    { apply sumList_body_eq. intros a Ha.
      apply ratMult_eqRat_compat.
      - apply eqRat_refl.
      - apply Hndpt. exact Ha. }
    (* on the dups part the g branch is bounded by its weight *)
    assert (Hhd_rl : sumList HD (fun ls => w ls * evalDist (g ls) true) <=
                     sumList HD w).
    { eapply leRat_trans with (r2 := sumList HD (fun a => (w a * 1)%rat)).
      - apply sumList_body_le. intros a Ha.
        apply ratMult_leRat_compat.
        + apply leRat_refl.
        + apply Hbnd.
      - apply eqRat_impl_leRat. eapply eqRat_trans.
        + apply sumList_factor_constant_r.
        + apply ratMult_1_r. }
    (* the indicator sums collapse onto the collision-event weight *)
    assert (Hnd_ind0 : sumList ND (fun ls => w ls * dupw ls) == 0).
    { apply sumList_0. intros a Ha.
      unfold ND in Ha. apply filter_In in Ha. destruct Ha as [_ Hh].
      apply negb_true_iff in Hh. unfold dupw. rewrite Hh.
      change (w a * 0 == 0)%rat. apply ratMult_0_r. }
    assert (Hhd_ind1 : sumList HD (fun ls => w ls * dupw ls) ==
                       sumList HD w).
    { apply sumList_body_eq. intros a Ha.
      unfold HD in Ha. apply filter_In in Ha. destruct Ha as [_ Hh].
      unfold dupw. rewrite Hh. change (w a * 1 == w a)%rat. apply ratMult_1_r. }
    (* assemble: g = ND_h + HD_g <= ND_h + HD_h + HD_weight *)
    rewrite Hnd_sum, Hnd_ind0, Hhd_ind1.
    rewrite <- ratAdd_0_l.
    apply ratAdd_leRat_compat.
    - apply ratAdd_any_leRat_l. apply leRat_refl.
    - exact Hhd_rl.
  Qed.

  Theorem averaging :
    forall (q : nat) (A : list R -> Comp bool),
      evalDist (ls <-$ repeatRnd q; r <-$ realMask nil ls; A r) true <=
      (evalDist (ls <-$ repeatRnd q; r <-$ IdealMask ls; A r) true +
       evalDist (DupEvent q) true)%rat.
  Proof.
    intros q A.
    apply (averaging_gen q (fun ls => Bind (realMask nil ls) A)
                           (fun ls => Bind (IdealMask ls) A)).
    - intros ls. apply evalDist_le_1.
    - intros ls Hhd. unfold rlp, ilp.
      apply (nodup_distinguisher_eq ls nil).
      + intros d' Hd. discriminate.
      + destruct (hasDups_false_NoDup (Bvector_EqDec c) ls) as [Hb _].
        apply Hb. exact Hhd.
  Qed.

  (* Mirrored direction: swapping real/ideal gives the reverse inequality,
     since on collision-free samples the two games are IDENTICALLY
     distributed (equality is symmetric). *)
  Theorem averaging_sym :
    forall (q : nat) (A : list R -> Comp bool),
      evalDist (ls <-$ repeatRnd q; r <-$ IdealMask ls; A r) true <=
      (evalDist (ls <-$ repeatRnd q; r <-$ realMask nil ls; A r) true +
       evalDist (DupEvent q) true)%rat.
  Proof.
    intros q A.
    apply (averaging_gen q (fun ls => Bind (IdealMask ls) A)
                           (fun ls => Bind (realMask nil ls) A)).
    - intros ls. apply evalDist_le_1.
    - intros ls Hhd. unfold rlp, ilp. symmetry.
      apply (nodup_distinguisher_eq ls nil).
      + intros d' Hd. discriminate.
      + destruct (hasDups_false_NoDup (Bvector_EqDec c) ls) as [Hb _].
        apply Hb. exact Hhd.
  Qed.

  (* Signed advantage: |Pr[real] - Pr[ideal]| <= Pr[collision]. *)
  Lemma ratSubtract_add_cancel :
    forall (r s : Rat), ratSubtract (r + s)%rat r == s.
  Proof. intros r s. unfold ratSubtract, ratAdd. rattac. Qed.

  Lemma dist_le_of_bounds :
    forall r i d : Rat,
      r <= i + d ->
      i <= r + d ->
      ratDistance r i <= d.
  Proof.
    intros r i d H1 H2.
    assert (Hri : ratSubtract r i <= d).
    { eapply leRat_trans with (r2 := ratSubtract (r + d)%rat i).
      - apply ratSubtract_leRat_l. exact H1.
      - apply eqRat_impl_leRat. apply ratSubtract_add_cancel. }
    assert (Hir : ratSubtract i r <= d).
    { eapply leRat_trans with (r2 := ratSubtract (i + d)%rat r).
      - apply ratSubtract_leRat_l. exact H2.
      - apply eqRat_impl_leRat. apply ratSubtract_add_cancel. }
    unfold ratDistance, maxRat, minRat.
    case_eq (bleRat r i); intros Hc.
    - simpl. assumption.
    - simpl. assumption.
  Qed.

  Corollary averaging_dist :
    forall (q : nat) (A : list R -> Comp bool),
      ratDistance
        (evalDist (ls <-$ repeatRnd q; r <-$ realMask nil ls; A r) true)
        (evalDist (ls <-$ repeatRnd q; r <-$ IdealMask ls; A r) true) <=
      evalDist (DupEvent q) true.
  Proof.
    intros q A. apply ratDistance_le.
    - apply averaging.
    - apply averaging_sym.
  Qed.

  (* ===== Rat -> integer scaling =====

     FCF rationals are RatIntro (numerator : nat) (denominator : posnat), so
     clearing denominators is exactly FCF's leRat_mult: r <= b transports to
     num(r) * den(b) <= num(b) * den(r) in nat.  This is the bridge from the
     probability-form bound to an integer inequality between scaled counts. *)
  Lemma clear_denoms :
    forall (r b : Rat),
      match r, b with
      | RatIntro nr dr, RatIntro nb db =>
          (nr * posnatToNat db <= nb * posnatToNat dr)%nat
      end.
  Proof.
    intros r b. destruct r as [nr dr]; destruct b as [nb db].
    destruct dr as [drv drpos]; destruct db as [dbv dbpos].
    simpl.
    apply (leRat_mult nr nb drv dbv drpos dbpos).
    simpl. assumption.
  Qed.

  (* Integer form of the advantage bound: with rd = |Pr[real]-Pr[ideal]|
     and pb = Pr[collision], their cleared numerators satisfy the nat
     inequality fst(ratCD rd pb) <= snd(ratCD rd pb). *)
  Corollary scaling_int :
    forall (q : nat) (A : list R -> Comp bool),
      (fst (ratCD
        (ratDistance
           (evalDist (ls <-$ repeatRnd q; r <-$ realMask nil ls; A r) true)
           (evalDist (ls <-$ repeatRnd q; r <-$ IdealMask ls; A r) true))
        (evalDist (DupEvent q) true)) <=
       fst (snd (ratCD
        (ratDistance
           (evalDist (ls <-$ repeatRnd q; r <-$ realMask nil ls; A r) true)
           (evalDist (ls <-$ repeatRnd q; r <-$ IdealMask ls; A r) true))
        (evalDist (DupEvent q) true))))%nat.
  Proof.
    intros q A.
    pose proof (averaging_dist q A) as Hd.
    destruct (ratDistance
        (evalDist (ls <-$ repeatRnd q; r <-$ realMask nil ls; A r) true)
        (evalDist (ls <-$ repeatRnd q; r <-$ IdealMask ls; A r) true))
      as [nd dd].
    destruct (evalDist (DupEvent q) true) as [nb db].
    unfold ratCD. simpl.
    apply clear_denoms.
    assumption.
  Qed.

End MaskPRF.
