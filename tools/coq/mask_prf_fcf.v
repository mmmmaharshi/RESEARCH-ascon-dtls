Require Import FCF.FCF.
Require Import FCF.CompFold.
Require Import FCF.ProgramLogic.

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

End MaskPRF.
