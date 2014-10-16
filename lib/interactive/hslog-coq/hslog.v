(* --------------------------------------------------------------------  *)
Require Import ssreflect eqtype ssrbool ssrnat ssrfun seq.
Require Import fintype choice tuple ssralg ssrint zmodp.

Set Implicit Arguments.
Unset Strict Implicit.
Unset Printing Implicit Defensive.

Import GRing.Theory.

Local Open Scope ring_scope.

(* -------------------------------------------------------------------- *)
Require String.

Local Open Scope string_scope.
Delimit Scope string_scope with S.

Ltac Case id := idtac id.

(* -------------------------------------------------------------------- *)
Section ExtraSeq.
  Variable T : eqType.

  Definition rems (T : eqType) xs s := foldr (@rem T) s xs.

  Lemma rev_inj: injective (@rev T).
  Proof. by elim=> [|x s ih] [|x' s'] /(congr1 rev); rewrite !revK. Qed.

  Lemma catIs (s1 s2 r1 r2 : seq T):
    size s1 = size s2 -> s1 ++ r1 = s2 ++ r2 -> s1 = s2.
  Proof. by move=> eq_sz /eqP; rewrite eqseq_cat // => /andP [/eqP]. Qed.    

  Lemma catsI (s1 s2 r1 r2 : seq T):
    size s1 = size s2 -> s1 ++ r1 = s2 ++ r2 -> r1 = r2.
  Proof. by move=> eq_sz /eqP; rewrite eqseq_cat // => /andP [_ /eqP]. Qed.

  Lemma catI (s1 s2 r1 r2 : seq T):
    size s1 = size s2 -> s1 ++ r1 = s2 ++ r2 -> [/\ s1 = s2 & r1 = r2].
  Proof. by move=> eq_sz eq; have/catsI ->// := eq; move/catIs: eq=> ->. Qed.    

  Lemma catIts (n : nat) (s1 s2 : n.-tuple T) (r1 r2 : seq T):
    s1 ++ r1 = s2 ++ r2 -> s1 = s2.
  Proof. by move/catIs; rewrite ?size_tuple => /(_ (erefl _)) /(val_inj). Qed.

  Lemma size_take_le (n : nat) (s : seq T):
    size (take n s) <= n.
  Proof. by rewrite size_take; case: ltnP. Qed.
End ExtraSeq.

Local Notation "s1  @@  s2" := (cat s1 s2)
  (right associativity, at level 30, only parsing).

(* -------------------------------------------------------------------- *)
Section FinInj.
  Variable T : finType.
  Variable U : eqType.
  Variable f : T -> option U.

  Parameter fin_inj:
       uniq (pmap f (enum T))
    -> forall (x1 x2 : T), f x1 != None -> f x2 != None ->
         f x1 = f x2 -> x1 = x2.
End FinInj.

(* -------------------------------------------------------------------- *)
Notation byte    := 'Z_256.
Notation bytes   := (seq byte).
Notation "n %:I" := (nosimpl (@inZp 256.-1 n)) (at level 2, format "n %:I").

(* -------------------------------------------------------------------- *)
Notation log := bytes (only parsing).

(* -------------------------------------------------------------------- *)
Section BytesOf.
  Variable T : Type.
  Variable f : T -> bytes.
  Variable n : nat.

  Hypothesis size_f: forall x, size (f x) = n.+1.
  Hypothesis f_inj : injective f.

  Definition bytesof (xs : seq T) :=
    nosimpl (flatten [seq f x | x <- xs]).

  Lemma bytesof_nil: bytesof [::] = [::].
  Proof. by []. Qed.

  Lemma bytesof_cons x xs: bytesof (x :: xs) = f x ++ bytesof xs.
  Proof. by []. Qed.

  Lemma size_bytesof (xs : seq T):
    size (bytesof xs) = (n.+1 * (size xs))%N.
  Proof.
    rewrite size_flatten; set szs := shape _.
    have ->: szs = nseq (size xs) n.+1%N.
      rewrite {}/szs; elim: xs => [|x xs ih] //=.
      by rewrite ih size_f.
    by rewrite sumn_nseq.
  Qed.

  Lemma bytesof_inj: injective bytesof.
  Proof.
    elim=> [|x1 xs1 ih] [|x2 xs2] //=;
      try by move/(congr1 size)=> /=; rewrite !size_bytesof.
    rewrite !bytesof_cons => eq; have/catIs := eq.
    rewrite !size_f => /(_ (erefl _)); move/f_inj=> <-.
    by move/catsI: eq; rewrite !size_f => /(_ (erefl _)) /ih <-.
  Qed.
End BytesOf.

Implicit Arguments size_bytesof [T f].
Implicit Arguments bytesof_inj [T f x1 x2].

(* -------------------------------------------------------------------- *)
Parameter IntBytes: forall (sz : nat), nat -> bytes.

Hypothesis IntBytes_inj: forall (sz : nat) (n1 n2 : nat),
     (n1 <= (2^(sz * 8)).-1)
  -> (n2 <= (2^(sz * 8)).-1)
  -> IntBytes sz n1 = IntBytes sz n2
  -> n1 = n2.

Hypothesis size_IntBytes: forall (sz : nat) (n : nat),
  size (IntBytes sz n) = sz.

(* -------------------------------------------------------------------- *)
Definition VLBytes (sz : nat) (b : bytes) :=
  let b   := take (2^(sz * 8)).-1 b in
  let bsz := IntBytes sz (size b) in
  bsz ++ b.

Lemma VLBytes_inj (n : nat) (b1 b2 : bytes):
     (size b1 <= (2^(n * 8)).-1)
  -> (size b2 <= (2^(n * 8)).-1)
  -> VLBytes n b1 = VLBytes n b2 -> b1 = b2.
Proof.
  move=> szb1 szb2; rewrite /VLBytes !take_oversize //.
  by move/catsI; rewrite !size_IntBytes; apply.
Qed.

(* -------------------------------------------------------------------- *)
Lemma catIB (n : nat) (p1 p2 : bytes) (l1 l2 : log):
     VLBytes n p1 ++ l1 = VLBytes n p2 ++ l2
  -> [/\ VLBytes n p1 = VLBytes n p2 & l1 = l2].
Proof.
  move=> eq; have: size (VLBytes n p1) = size (VLBytes n p2).
    move: eq; rewrite -2!catA => /catI []; rewrite ?size_IntBytes //.
    move/IntBytes_inj; rewrite !size_take_le => /(_ erefl erefl).
    by move=> eq_sz /catI [] // eq _; rewrite /VLBytes eq_sz eq.
  by move=> eq_sz; case/catI: eq.
Qed.

(* -------------------------------------------------------------------- *)
Inductive HandshakeType : Type :=
| HT_hello_request
| HT_client_hello
| HT_server_hello
| HT_certificate
| HT_server_key_exchange
| HT_certificate_request
| HT_server_hello_done
| HT_certificate_verify
| HT_client_key_exchange
| HT_finished.

(* -------------------------------------------------------------------- *)
Definition HTBytes ht : bytes :=
  match ht with
  | HT_hello_request       => [::  0%:I]
  | HT_client_hello        => [::  1%:I]
  | HT_server_hello        => [::  2%:I]
  | HT_certificate         => [:: 11%:I]
  | HT_server_key_exchange => [:: 12%:I]
  | HT_certificate_request => [:: 13%:I]
  | HT_server_hello_done   => [:: 14%:I]
  | HT_certificate_verify  => [:: 15%:I]
  | HT_client_key_exchange => [:: 16%:I]
  | HT_finished            => [:: 20%:I]
  end.

(* -------------------------------------------------------------------- *)
Lemma size_HTBytes ht: size (HTBytes ht) = 1%N.
Proof. by case: ht. Qed.

(* -------------------------------------------------------------------- *)
Lemma HTBytes_inj ht1 ht2: HTBytes ht1 = HTBytes ht2 -> ht1 = ht2.
Proof. by case: ht1 ht2=> [] []. Qed.

(* -------------------------------------------------------------------- *)
Inductive ProtocolVersion : Type :=
  | SSL_3p0 | TLS_1p0 | TLS_1p1 | TLS_1p2.

(* -------------------------------------------------------------------- *)
Definition PVBytes pv : bytes :=
  match pv with
  | SSL_3p0 => [:: 3%:I; 0%:I ]
  | TLS_1p0 => [:: 3%:I; 1%:I ]
  | TLS_1p1 => [:: 3%:I; 2%:I ]
  | TLS_1p2 => [:: 3%:I; 3%:I ]
  end.

(* -------------------------------------------------------------------- *)
Lemma size_PVBytes pv: size (PVBytes pv) = 2%N.
Proof. by case: pv. Qed.

(* -------------------------------------------------------------------- *)
Lemma PVBytes_inj: injective PVBytes.
Proof. by case=> [] []. Qed.

(* -------------------------------------------------------------------- *)
Definition MessageBytes_r (ht : HandshakeType) (b : bytes) : bytes :=
  (HTBytes ht) ++ (VLBytes 3 b).

Module Type MessageBytesSig.
  Parameter MessageBytes: HandshakeType -> bytes -> bytes.
  Hypothesis MessageBytesE: MessageBytes = MessageBytes_r.
End MessageBytesSig.

Module MessageBytes: MessageBytesSig.
  Definition MessageBytes := MessageBytes_r.

  Lemma MessageBytesE: MessageBytes = MessageBytes_r.
  Proof. by []. Qed.
End MessageBytes.

Notation MessageBytes := MessageBytes.MessageBytes.
Canonical messagebytes_unlock := Unlockable MessageBytes.MessageBytesE.

(* -------------------------------------------------------------------- *)
Lemma MessageBytes_inj1 ht1 b1 ht2 b2:
  MessageBytes ht1 b1 = MessageBytes ht2 b2 -> ht1 = ht2.
Proof.
  rewrite unlock => /catIs eq; apply/HTBytes_inj.
  by apply/eq; rewrite !size_HTBytes.
Qed.

Lemma MessageBytes_inj2 ht1 b1 ht2 b2:
     (size b1 <= (2^24).-1)%N
  -> (size b2 <= (2^24).-1)%N
  -> MessageBytes ht1 b1 = MessageBytes ht2 b2 -> b1 = b2.
Proof. 
  rewrite unlock; move=> szb1 szb2 /catsI; rewrite !size_HTBytes.
  by move/(_ erefl)/VLBytes_inj => -/(_ szb1 szb2); apply.
Qed.

Lemma MessageBytes_inj2_take ht1 b1 ht2 b2:
     MessageBytes ht1 b1 = MessageBytes ht2 b2
  -> take (2^24).-1 b1 = take (2^24).-1 b2.
Proof.
  rewrite unlock /MessageBytes_r => /catsI; rewrite !size_HTBytes.
  move/(_ erefl); rewrite /VLBytes => /catsI; apply.
  by rewrite !size_IntBytes.
Qed.

(* -------------------------------------------------------------------- *)
Lemma catIL ht1 ht2 p1 p2 l1 l2:
     MessageBytes ht1 p1 ++ l1 = MessageBytes ht2 p2 ++ l2
  -> [/\ MessageBytes ht1 p1 = MessageBytes ht2 p2 & l1 = l2].
Proof.
  rewrite !unlock /MessageBytes_r -2!catA; case/catI.
    by rewrite !size_HTBytes.
  by move=> <- /catIB [<- <-].
Qed.

Lemma catILs ht1 ht2 p1 p2 l1 l2:
  MessageBytes ht1 p1 ++ l1 = MessageBytes ht2 p2 ++ l2 -> l1 = l2.
Proof. by case/catIL. Qed.

Lemma catsIL ht1 ht2 p1 p2 l1 l2:
     MessageBytes ht1 p1 ++ l1 = MessageBytes ht2 p2 ++ l2
  -> MessageBytes ht1 p1 = MessageBytes ht2 p2.
Proof. by case/catIL. Qed.

(* -------------------------------------------------------------------- *)
Inductive Compression : Type :=
| NullCompression.

(* -------------------------------------------------------------------- *)
Definition CPBytes c :=
  match c with
  | NullCompression => [:: 0%:I]
  end.

(* -------------------------------------------------------------------- *)
Lemma size_CPBytes c: size (CPBytes c) = 1%N.
Proof. by case: c. Qed.

(*-------------------------------------------------------------------- *)
Lemma CPBytes_inj: injective CPBytes.
Proof. by case=> [] []. Qed.

(* -------------------------------------------------------------------- *)
Notation MCPBytes := (bytesof CPBytes).

(* -------------------------------------------------------------------- *)
Definition MCPBytes_nil  := bytesof_nil  CPBytes.
Definition MCPBytes_cons := bytesof_cons CPBytes.

(* -------------------------------------------------------------------- *)
Lemma size_MCPBytes cs: size (MCPBytes cs) = (size cs).
Proof. by rewrite (size_bytesof 0) ?mul1n //; apply/size_CPBytes. Qed.

(* -------------------------------------------------------------------- *)
Lemma MCPBytes_inj: injective MCPBytes.
Proof. by apply/(bytesof_inj 0)/CPBytes_inj/size_CPBytes. Qed.

(* -------------------------------------------------------------------- *)
Inductive HashAlg : Type :=
| MD5
| SHA
| SHA256
| SHA384.

(* -------------------------------------------------------------------- *)
Definition HashAlgBytes ha : bytes :=
  match ha with
  | MD5    => [:: 1%:I ]
  | SHA    => [:: 2%:I ]
  | SHA256 => [:: 4%:I ]
  | SHA384 => [:: 5%:I ]
  end. 

(* -------------------------------------------------------------------- *)
Scheme Equality for HashAlg.

Lemma HashAlg_eqP (ha1 ha2 : HashAlg):
  reflect (ha1 = ha2) (HashAlg_beq ha1 ha2).
Proof.
  apply: (iffP idP).
    by apply/internal_HashAlg_dec_bl.
    by apply/internal_HashAlg_dec_lb.
Qed.

Definition HashAlg_eqMixin := EqMixin HashAlg_eqP.
Canonical  HashAlg_eqType  := Eval hnf in EqType HashAlg HashAlg_eqMixin.

(* -------------------------------------------------------------------- *)
Definition HashAlg_enum := [:: MD5; SHA; SHA256; SHA384].

Definition nat_of_hashalg ha := index ha HashAlg_enum.
Definition hashalg_of_nat id := nth None [seq Some ha | ha <- HashAlg_enum] id.

Lemma hashalg_of_natK: pcancel nat_of_hashalg hashalg_of_nat.
Proof. by case. Qed.

Definition HashAlg_choiceMixin := PcanChoiceMixin hashalg_of_natK.
Canonical  HashAlg_choiceType  := ChoiceType HashAlg HashAlg_choiceMixin.

Definition HashAlg_countMixin := PcanCountMixin hashalg_of_natK.
Canonical  HashAlg_countType  := CountType HashAlg HashAlg_countMixin.

Lemma HashAlg_enumP: @Finite.axiom HashAlg_eqType HashAlg_enum.
Proof. by case. Qed.

Definition HashAlg_finMixin := FinMixin HashAlg_enumP.
Canonical  HashAlg_finType  := FinType HashAlg HashAlg_finMixin.

(* -------------------------------------------------------------------- *)
Inductive SigAlg : Type :=
| SA_RSA
| SA_DSA 
| SA_ECDSA.

(* -------------------------------------------------------------------- *)
Definition SigAlgBytes sa :=
  match sa with
  | SA_RSA   => [:: 1%:I ]
  | SA_DSA   => [:: 2%:I ]
  | SA_ECDSA => [:: 3%:I ]
  end.

(* -------------------------------------------------------------------- *)
Scheme Equality for SigAlg.

Lemma SigAlg_eqP (sa1 sa2 : SigAlg):
  reflect (sa1 = sa2) (SigAlg_beq sa1 sa2).
Proof.
  apply: (iffP idP).
    by apply/internal_SigAlg_dec_bl.
    by apply/internal_SigAlg_dec_lb.
Qed.

Definition SigAlg_eqMixin := EqMixin SigAlg_eqP.
Canonical  SigAlg_eqType  := Eval hnf in EqType SigAlg SigAlg_eqMixin.

(* -------------------------------------------------------------------- *)
Definition SigAlg_enum := [:: SA_RSA; SA_DSA; SA_ECDSA].

Definition nat_of_sigalg ha := index ha SigAlg_enum.
Definition sigalg_of_nat id := nth None [seq Some ha | ha <- SigAlg_enum] id.

Lemma sigalg_of_natK: pcancel nat_of_sigalg sigalg_of_nat.
Proof. by case. Qed.

Definition SigAlg_choiceMixin := PcanChoiceMixin sigalg_of_natK.
Canonical  SigAlg_choiceType  := ChoiceType SigAlg SigAlg_choiceMixin.

Definition SigAlg_countMixin := PcanCountMixin sigalg_of_natK.
Canonical  SigAlg_countType  := CountType SigAlg SigAlg_countMixin.

Lemma SigAlg_enumP: @Finite.axiom SigAlg_eqType SigAlg_enum.
Proof. by case. Qed.

Definition SigAlg_finMixin := FinMixin SigAlg_enumP.
Canonical  SigAlg_finType  := FinType SigAlg SigAlg_finMixin.

(* -------------------------------------------------------------------- *)
Notation SigHashAlg := (SigAlg * HashAlg)%type.

(* -------------------------------------------------------------------- *)
Definition SigHashAlgBytes (sah : SigHashAlg) :=
  let: (sa, ha) := sah in HashAlgBytes ha ++ SigAlgBytes sa. 

(* -------------------------------------------------------------------- *)
Inductive SCSVsuite : Type :=
| TLS_EMPTY_RENEGOTIATION_INFO_SCSV.

(* -------------------------------------------------------------------- *)
Lemma all_SCSVsuite (d : SCSVsuite):
  d = TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
Proof. by case: d. Qed.

(* -------------------------------------------------------------------- *)
Scheme Equality for SCSVsuite.

Lemma SCSVsuite_eqP (ss1 ss2 : SCSVsuite):
  reflect (ss1 = ss2) (SCSVsuite_beq ss1 ss2).
Proof.
  apply: (iffP idP).
    by apply/internal_SCSVsuite_dec_bl.
    by apply/internal_SCSVsuite_dec_lb.
Qed.

Definition SCSVsuite_eqMixin := EqMixin SCSVsuite_eqP.
Canonical  SCSVsuite_eqType  := Eval hnf in EqType SCSVsuite SCSVsuite_eqMixin.

(* -------------------------------------------------------------------- *)
Definition SCSVsuite_enum := [:: TLS_EMPTY_RENEGOTIATION_INFO_SCSV].

Definition nat_of_SCSVsuite ss := index ss SCSVsuite_enum.
Definition SCSVsuite_of_nat id := nth None [seq Some ss | ss <- SCSVsuite_enum] id.

Lemma SCSVsuite_of_natK: pcancel nat_of_SCSVsuite SCSVsuite_of_nat.
Proof. by case. Qed.

Definition SCSVsuite_choiceMixin := PcanChoiceMixin SCSVsuite_of_natK.
Canonical  SCSVsuite_choiceType  := ChoiceType SCSVsuite SCSVsuite_choiceMixin.

Definition SCSVsuite_countMixin := PcanCountMixin SCSVsuite_of_natK.
Canonical  SCSVsuite_countType  := CountType SCSVsuite SCSVsuite_countMixin.

Lemma SCSVsuite_enumP: @Finite.axiom SCSVsuite_eqType SCSVsuite_enum.
Proof. by case. Qed.

Definition SCSVsuite_finMixin := FinMixin SCSVsuite_enumP.
Canonical  SCSVsuite_finType  := FinType SCSVsuite SCSVsuite_finMixin.

(* -------------------------------------------------------------------- *)
Inductive CipherAlg : Type :=
| RC4_128
| TDES_EDE_CBC
| AES_128_CBC
| AES_256_CBC.

(* -------------------------------------------------------------------- *)
Scheme Equality for CipherAlg.

Lemma CipherAlg_eqP (ca1 ca2 : CipherAlg):
  reflect (ca1 = ca2) (CipherAlg_beq ca1 ca2).
Proof.
  apply: (iffP idP).
    by apply/internal_CipherAlg_dec_bl.
    by apply/internal_CipherAlg_dec_lb.
Qed.

Definition CipherAlg_eqMixin := EqMixin CipherAlg_eqP.
Canonical  CipherAlg_eqType  := Eval hnf in EqType CipherAlg CipherAlg_eqMixin.

(* -------------------------------------------------------------------- *)
Definition CipherAlg_enum := [:: RC4_128; TDES_EDE_CBC; AES_128_CBC; AES_256_CBC].

Definition nat_of_CipherAlg ca := index ca CipherAlg_enum.
Definition CipherAlg_of_nat id := nth None [seq Some ca | ca <- CipherAlg_enum] id.

Lemma CipherAlg_of_natK: pcancel nat_of_CipherAlg CipherAlg_of_nat.
Proof. by case. Qed.

Definition CipherAlg_choiceMixin := PcanChoiceMixin CipherAlg_of_natK.
Canonical  CipherAlg_choiceType  := ChoiceType CipherAlg CipherAlg_choiceMixin.

Definition CipherAlg_countMixin := PcanCountMixin CipherAlg_of_natK.
Canonical  CipherAlg_countType  := CountType CipherAlg CipherAlg_countMixin.

Lemma CipherAlg_enumP: @Finite.axiom CipherAlg_eqType CipherAlg_enum.
Proof. by case. Qed.

Definition CipherAlg_finMixin := FinMixin CipherAlg_enumP.
Canonical  CipherAlg_finType  := FinType CipherAlg CipherAlg_finMixin.

(* -------------------------------------------------------------------- *)
Inductive AEADAlg : Type :=
| AES_128_GCM
| AES_256_GCM.

(* -------------------------------------------------------------------- *)
Scheme Equality for AEADAlg.

Lemma AEADAlg_eqP (ae1 ae2 : AEADAlg):
  reflect (ae1 = ae2) (AEADAlg_beq ae1 ae2).
Proof.
  apply: (iffP idP).
    by apply/internal_AEADAlg_dec_bl.
    by apply/internal_AEADAlg_dec_lb.
Qed.

Definition AEADAlg_eqMixin := EqMixin AEADAlg_eqP.
Canonical  AEADAlg_eqType  := Eval hnf in EqType AEADAlg AEADAlg_eqMixin.

(* -------------------------------------------------------------------- *)
Definition AEADAlg_enum := [:: AES_128_GCM; AES_256_GCM].

Definition nat_of_AEADAlg ae := index ae AEADAlg_enum.
Definition AEADAlg_of_nat id := nth None [seq Some ae | ae <- AEADAlg_enum] id.

Lemma AEADAlg_of_natK: pcancel nat_of_AEADAlg AEADAlg_of_nat.
Proof. by case. Qed.

Definition AEADAlg_choiceMixin := PcanChoiceMixin AEADAlg_of_natK.
Canonical  AEADAlg_choiceType  := ChoiceType AEADAlg AEADAlg_choiceMixin.

Definition AEADAlg_countMixin := PcanCountMixin AEADAlg_of_natK.
Canonical  AEADAlg_countType  := CountType AEADAlg AEADAlg_countMixin.

Lemma AEADAlg_enumP: @Finite.axiom AEADAlg_eqType AEADAlg_enum.
Proof. by case. Qed.

Definition AEADAlg_finMixin := FinMixin AEADAlg_enumP.
Canonical  AEADAlg_finType  := FinType AEADAlg AEADAlg_finMixin.

(* -------------------------------------------------------------------- *)
Inductive KexAlg : Type :=
| RSA
| DH_DSS
| DH_RSA
| DHE_DSS
| DHE_RSA
| DH_anon.

(* -------------------------------------------------------------------- *)
Scheme Equality for KexAlg.

Lemma KexAlg_eqP (ae1 ae2 : KexAlg):
  reflect (ae1 = ae2) (KexAlg_beq ae1 ae2).
Proof.
  apply: (iffP idP).
    by apply/internal_KexAlg_dec_bl.
    by apply/internal_KexAlg_dec_lb.
Qed.

Definition KexAlg_eqMixin := EqMixin KexAlg_eqP.
Canonical  KexAlg_eqType  := Eval hnf in EqType KexAlg KexAlg_eqMixin.

(* -------------------------------------------------------------------- *)
Definition KexAlg_enum := [::  RSA; DH_DSS; DH_RSA; DHE_DSS; DHE_RSA; DH_anon].

Definition nat_of_KexAlg ka := index ka KexAlg_enum.
Definition KexAlg_of_nat id := nth None [seq Some ka | ka <- KexAlg_enum] id.

Lemma KexAlg_of_natK: pcancel nat_of_KexAlg KexAlg_of_nat.
Proof. by case. Qed.

Definition KexAlg_choiceMixin := PcanChoiceMixin KexAlg_of_natK.
Canonical  KexAlg_choiceType  := ChoiceType KexAlg KexAlg_choiceMixin.

Definition KexAlg_countMixin := PcanCountMixin KexAlg_of_natK.
Canonical  KexAlg_countType  := CountType KexAlg KexAlg_countMixin.

Lemma KexAlg_enumP: @Finite.axiom KexAlg_eqType KexAlg_enum.
Proof. by case. Qed.

Definition KexAlg_finMixin := FinMixin KexAlg_enumP.
Canonical  KexAlg_finType  := FinType KexAlg KexAlg_finMixin.

(* -------------------------------------------------------------------- *)
Inductive CSAuthEncAlg : Type :=
| CS_MtE  of CipherAlg * HashAlg
| CS_AEAD of AEADAlg   * HashAlg.

(* -------------------------------------------------------------------- *)
Definition CSAuthEncAlg_eqb csae1 csae2 :=
  match csae1, csae2 with
  | CS_MtE  d1, CS_MtE  d2 => d1 == d2
  | CS_AEAD d1, CS_AEAD d2 => d1 == d2
  | _         , _          => false
  end.

(* -------------------------------------------------------------------- *)
Lemma CSAuthEncAlg_eqP csae1 csae2:
  reflect (csae1 = csae2) (CSAuthEncAlg_eqb csae1 csae2).
Proof.
  case: csae1 csae2=> []d1 []d2 /=; try by constructor.
  + by case: eqP=> e; constructor; [rewrite e|case].
  + by case: eqP=> e; constructor; [rewrite e|case].
Qed.

Definition CSAuthEncAlg_eqMixin := EqMixin CSAuthEncAlg_eqP.
Canonical  CSAuthEncAlg_eqType  := EqType CSAuthEncAlg CSAuthEncAlg_eqMixin.

(* -------------------------------------------------------------------- *)
Definition CSAuthEncAlg_enum := Eval compute in
     [seq CS_MtE  (d1, d2) | d1 <- CipherAlg_enum, d2 <- HashAlg_enum]
  ++ [seq CS_AEAD (d1, d2) | d1 <- AEADAlg_enum  , d2 <- HashAlg_enum].

Definition nat_of_CSAuthEncAlg csae := index csae CSAuthEncAlg_enum.

Definition CSAuthEncAlg_of_nat id :=
  nth None [seq Some csae | csae <- CSAuthEncAlg_enum] id.

Lemma CSAuthEncAlg_of_natK: pcancel nat_of_CSAuthEncAlg CSAuthEncAlg_of_nat.
Proof. by do! (case || move=> ?). Qed.

Definition CSAuthEncAlg_choiceMixin := PcanChoiceMixin CSAuthEncAlg_of_natK.
Canonical  CSAuthEncAlg_choiceType  := ChoiceType CSAuthEncAlg CSAuthEncAlg_choiceMixin.

Definition CSAuthEncAlg_countMixin := PcanCountMixin CSAuthEncAlg_of_natK.
Canonical  CSAuthEncAlg_countType  := CountType CSAuthEncAlg CSAuthEncAlg_countMixin.

Lemma CSAuthEncAlg_enumP: @Finite.axiom CSAuthEncAlg_eqType CSAuthEncAlg_enum.
Proof. by do! (case || move=> ?). Qed.

Definition CSAuthEncAlg_finMixin := FinMixin CSAuthEncAlg_enumP.
Canonical  CSAuthEncAlg_finType  := FinType CSAuthEncAlg CSAuthEncAlg_finMixin.

(* -------------------------------------------------------------------- *)
Inductive CipherSuite : Type :=
| NullCipherSuite
| CSCipherSuite      of KexAlg * CSAuthEncAlg
| OnlyMACCipherSuite of KexAlg * HashAlg
| SCSV               of SCSVsuite.

(* -------------------------------------------------------------------- *)
Definition CipherSuite_eqb cs1 cs2 :=
  match cs1, cs2 with
  | NullCipherSuite      , NullCipherSuite       => true
  | CSCipherSuite      d1, CSCipherSuite      d2 => d1 == d2
  | OnlyMACCipherSuite d1, OnlyMACCipherSuite d2 => d1 == d2
  | SCSV               d1, SCSV               d2 => d1 == d2
  | _                    , _                     => false
  end.

(* -------------------------------------------------------------------- *)
Lemma CipherSuite_eqP cs1 cs2:
  reflect (cs1 = cs2) (CipherSuite_eqb cs1 cs2).
Proof.
  case: cs1; case: cs2=> //=; try by constructor.
  + by move=> ??; case: eqP=> e; constructor; [rewrite e|case].
  + by move=> ??; case: eqP=> e; constructor; [rewrite e|case].
  + move=> d1 d2; rewrite [d1]all_SCSVsuite [d2]all_SCSVsuite.
    by rewrite eqxx; constructor.
Qed.

Definition CipherSuite_eqMixin := EqMixin CipherSuite_eqP.
Canonical  CipherSuite_eqType  := EqType CipherSuite CipherSuite_eqMixin.

(* -------------------------------------------------------------------- *)
Definition CipherSuite_enum := Eval compute in
     [:: NullCipherSuite; SCSV TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
  ++ [seq CSCipherSuite      (d1, d2) | d1 <- KexAlg_enum, d2 <- CSAuthEncAlg_enum]
  ++ [seq OnlyMACCipherSuite (d1, d2) | d1 <- KexAlg_enum, d2 <- HashAlg_enum].

Definition nat_of_CipherSuite cs := index cs CipherSuite_enum.

Definition CipherSuite_of_nat id :=
  nth None [seq Some cs | cs <- CipherSuite_enum] id.

Lemma CipherSuite_of_natK: pcancel nat_of_CipherSuite CipherSuite_of_nat.
Proof. by do! (case || move=> ?); vm_compute. Qed.

Definition CipherSuite_choiceMixin := PcanChoiceMixin CipherSuite_of_natK.
Canonical  CipherSuite_choiceType  := ChoiceType CipherSuite CipherSuite_choiceMixin.

Definition CipherSuite_countMixin := PcanCountMixin CipherSuite_of_natK.
Canonical  CipherSuite_countType  := CountType CipherSuite CipherSuite_countMixin.

Lemma CipherSuite_enumP: @Finite.axiom CipherSuite_eqType CipherSuite_enum.
Proof. by do! (case || move=> ?); vm_compute. Qed.

Definition CipherSuite_finMixin := FinMixin CipherSuite_enumP.
Canonical  CipherSuite_finType  := FinType CipherSuite CipherSuite_finMixin.

(* -------------------------------------------------------------------- *)
Definition CSBytes cs : option bytes :=
  match cs with
  | NullCipherSuite                                       => Some [:: (* 00 *) 000%:I; (* 00 *) 000%:I ]

  | OnlyMACCipherSuite (RSA, MD5)                         => Some [:: (* 00 *) 000%:I; (* 01 *) 001%:I ]
  | OnlyMACCipherSuite (RSA, SHA)                         => Some [:: (* 00 *) 000%:I; (* 02 *) 002%:I ]
  | OnlyMACCipherSuite (RSA, SHA256)                      => Some [:: (* 00 *) 000%:I; (* 3B *) 059%:I ]

  | CSCipherSuite (RSA, CS_MtE (RC4_128, MD5))            => Some [:: (* 00 *) 000%:I; (* 04 *) 004%:I ]
  | CSCipherSuite (RSA, CS_MtE (RC4_128, SHA))            => Some [:: (* 00 *) 000%:I; (* 05 *) 005%:I ]
  | CSCipherSuite (RSA, CS_MtE (TDES_EDE_CBC, SHA))       => Some [:: (* 00 *) 000%:I; (* 0A *) 010%:I ]
  | CSCipherSuite (RSA, CS_MtE (AES_128_CBC, SHA))        => Some [:: (* 00 *) 000%:I; (* 2F *) 047%:I ]
  | CSCipherSuite (RSA, CS_MtE (AES_256_CBC, SHA))        => Some [:: (* 00 *) 000%:I; (* 35 *) 053%:I ]
  | CSCipherSuite (RSA, CS_MtE (AES_128_CBC, SHA256))     => Some [:: (* 00 *) 000%:I; (* 3C *) 060%:I ]
  | CSCipherSuite (RSA, CS_MtE (AES_256_CBC, SHA256))     => Some [:: (* 00 *) 000%:I; (* 3D *) 061%:I ]

  | CSCipherSuite (DH_DSS, CS_MtE (TDES_EDE_CBC, SHA))    => Some [:: (* 00 *) 000%:I; (* 0D *) 013%:I ]
  | CSCipherSuite (DH_RSA, CS_MtE (TDES_EDE_CBC, SHA))    => Some [:: (* 00 *) 000%:I; (* 10 *) 016%:I ]
  | CSCipherSuite (DHE_DSS, CS_MtE (TDES_EDE_CBC, SHA))   => Some [:: (* 00 *) 000%:I; (* 13 *) 019%:I ]
  | CSCipherSuite (DHE_RSA, CS_MtE (TDES_EDE_CBC, SHA))   => Some [:: (* 00 *) 000%:I; (* 16 *) 022%:I ]

  | CSCipherSuite (DH_DSS, CS_MtE (AES_128_CBC, SHA))     => Some [:: (* 00 *) 000%:I; (* 30 *) 048%:I ]
  | CSCipherSuite (DH_RSA, CS_MtE (AES_128_CBC, SHA))     => Some [:: (* 00 *) 000%:I; (* 31 *) 049%:I ]
  | CSCipherSuite (DHE_DSS, CS_MtE (AES_128_CBC, SHA))    => Some [:: (* 00 *) 000%:I; (* 32 *) 050%:I ]
  | CSCipherSuite (DHE_RSA, CS_MtE (AES_128_CBC, SHA))    => Some [:: (* 00 *) 000%:I; (* 33 *) 051%:I ]

  | CSCipherSuite (DH_DSS, CS_MtE (AES_256_CBC, SHA))     => Some [:: (* 00 *) 000%:I; (* 36 *) 054%:I ]
  | CSCipherSuite (DH_RSA, CS_MtE (AES_256_CBC, SHA))     => Some [:: (* 00 *) 000%:I; (* 37 *) 055%:I ]
  | CSCipherSuite (DHE_DSS, CS_MtE (AES_256_CBC, SHA))    => Some [:: (* 00 *) 000%:I; (* 38 *) 056%:I ]
  | CSCipherSuite (DHE_RSA, CS_MtE (AES_256_CBC, SHA))    => Some [:: (* 00 *) 000%:I; (* 39 *) 057%:I ]

  | CSCipherSuite (DH_DSS, CS_MtE (AES_128_CBC, SHA256))  => Some [:: (* 00 *) 000%:I; (* 3E *) 062%:I ]
  | CSCipherSuite (DH_RSA, CS_MtE (AES_128_CBC, SHA256))  => Some [:: (* 00 *) 000%:I; (* 3F *) 063%:I ]
  | CSCipherSuite (DHE_DSS, CS_MtE (AES_128_CBC, SHA256)) => Some [:: (* 00 *) 000%:I; (* 40 *) 064%:I ]
  | CSCipherSuite (DHE_RSA, CS_MtE (AES_128_CBC, SHA256)) => Some [:: (* 00 *) 000%:I; (* 67 *) 103%:I ]

  | CSCipherSuite (DH_DSS, CS_MtE (AES_256_CBC, SHA256))  => Some [:: (* 00 *) 000%:I; (* 68 *) 104%:I ]
  | CSCipherSuite (DH_RSA, CS_MtE (AES_256_CBC, SHA256))  => Some [:: (* 00 *) 000%:I; (* 69 *) 105%:I ]
  | CSCipherSuite (DHE_DSS, CS_MtE (AES_256_CBC, SHA256)) => Some [:: (* 00 *) 000%:I; (* 6A *) 106%:I ]
  | CSCipherSuite (DHE_RSA, CS_MtE (AES_256_CBC, SHA256)) => Some [:: (* 00 *) 000%:I; (* 6B *) 107%:I ]

  | CSCipherSuite (DH_anon, CS_MtE (RC4_128, MD5))        => Some [:: (* 00 *) 000%:I; (* 18 *) 024%:I ]
  | CSCipherSuite (DH_anon, CS_MtE (TDES_EDE_CBC, SHA))   => Some [:: (* 00 *) 000%:I; (* 1B *) 027%:I ]
  | CSCipherSuite (DH_anon, CS_MtE (AES_128_CBC, SHA))    => Some [:: (* 00 *) 000%:I; (* 34 *) 052%:I ]
  | CSCipherSuite (DH_anon, CS_MtE (AES_256_CBC, SHA))    => Some [:: (* 00 *) 000%:I; (* 3A *) 058%:I ]
  | CSCipherSuite (DH_anon, CS_MtE (AES_128_CBC, SHA256)) => Some [:: (* 00 *) 000%:I; (* 6C *) 108%:I ]
  | CSCipherSuite (DH_anon, CS_MtE (AES_256_CBC, SHA256)) => Some [:: (* 00 *) 000%:I; (* 6D *) 109%:I ]

  | CSCipherSuite (RSA,     CS_AEAD(AES_128_GCM, SHA256)) => Some [:: (* 00 *) 000%:I; (* 9C *) 156%:I ]
  | CSCipherSuite (RSA,     CS_AEAD(AES_256_GCM, SHA384)) => Some [:: (* 00 *) 000%:I; (* 9D *) 157%:I ]
  | CSCipherSuite (DHE_RSA, CS_AEAD(AES_128_GCM, SHA256)) => Some [:: (* 00 *) 000%:I; (* 9E *) 158%:I ]
  | CSCipherSuite (DHE_RSA, CS_AEAD(AES_256_GCM, SHA384)) => Some [:: (* 00 *) 000%:I; (* 9F *) 159%:I ]
  | CSCipherSuite (DH_RSA,  CS_AEAD(AES_128_GCM, SHA256)) => Some [:: (* 00 *) 000%:I; (* A0 *) 160%:I ]
  | CSCipherSuite (DH_RSA,  CS_AEAD(AES_256_GCM, SHA384)) => Some [:: (* 00 *) 000%:I; (* A1 *) 161%:I ]
  | CSCipherSuite (DHE_DSS, CS_AEAD(AES_128_GCM, SHA256)) => Some [:: (* 00 *) 000%:I; (* A2 *) 162%:I ]
  | CSCipherSuite (DHE_DSS, CS_AEAD(AES_256_GCM, SHA384)) => Some [:: (* 00 *) 000%:I; (* A3 *) 163%:I ]
  | CSCipherSuite (DH_DSS,  CS_AEAD(AES_128_GCM, SHA256)) => Some [:: (* 00 *) 000%:I; (* A4 *) 164%:I ]
  | CSCipherSuite (DH_DSS,  CS_AEAD(AES_256_GCM, SHA384)) => Some [:: (* 00 *) 000%:I; (* A5 *) 165%:I ]
  | CSCipherSuite (DH_anon, CS_AEAD(AES_128_GCM, SHA256)) => Some [:: (* 00 *) 000%:I; (* A6 *) 166%:I ]
  | CSCipherSuite (DH_anon, CS_AEAD(AES_256_GCM, SHA384)) => Some [:: (* 00 *) 000%:I; (* A7 *) 167%:I ]

  | SCSV (TLS_EMPTY_RENEGOTIATION_INFO_SCSV)              => Some [:: (* 00 *) 000%:I; (* FF *) 255%:I ]

  | _ => None
  end.

(* -------------------------------------------------------------------- *)
Lemma size_CSBytes cs: odflt 2%N (omap size (CSBytes cs)) = 2%N.
Proof.
  case: cs; first by done.
  + by do 6! case; vm_compute.
  + by do 3! case; vm_compute.
  + by case.
Qed.

(* -------------------------------------------------------------------- *)
Lemma CSBytes_inj cs1 cs2:
     CSBytes cs1 != None
  -> CSBytes cs2 != None
  -> CSBytes cs1 = CSBytes cs2
  -> cs1 = cs2.
Proof.
  move=> h1 h2; apply/fin_inj=> //.
  by rewrite enumT Finite.EnumDef.enumDef; vm_compute.
Qed.

(* -------------------------------------------------------------------- *)
Definition valid_CipherSuite (cs : CipherSuite) :=
  (CSBytes cs != None).

Structure ValidCipherSuite : Type
  := ValidCS { csval :> CipherSuite; _ : valid_CipherSuite csval }.

Canonical ValidCipherSuite_subType := Eval hnf in [subType for csval].

Definition vcs_eqMixin := Eval hnf in [eqMixin of ValidCipherSuite by <:].
Canonical  vcs_eqType  := Eval hnf in EqType _ vcs_eqMixin.

(* -------------------------------------------------------------------- *)
Definition VCSBytes (cs : ValidCipherSuite) := odflt [::] (CSBytes cs).

(* -------------------------------------------------------------------- *)
Lemma size_VCSBytes cs: size (VCSBytes cs) = 2%N.
Proof.
  rewrite /VCSBytes; case: cs=> cs /=; move: (size_CSBytes cs).
  by rewrite /valid_CipherSuite; case: (CSBytes _).
Qed.

(* -------------------------------------------------------------------- *)
Lemma VCSBytes_inj: injective VCSBytes.
Proof.
  case=> [cs1 v1] [cs2 v2] h; apply/eqP; rewrite eqE /=.
  apply/eqP/CSBytes_inj.
    by move/negbTE: {h} v1 => ->. by move/negbTE: {h} v2 => ->.
  move: v1 v2 h; rewrite /valid_CipherSuite /VCSBytes /=.
  by case: (CSBytes _)=> //; case: (CSBytes _)=> //= c1 c2 _ _ ->.
Qed.

(* -------------------------------------------------------------------- *)
Definition random    := 32.-tuple byte.
Definition sessionID := 32.-tuple byte.

(* -------------------------------------------------------------------- *)
Parameter Cert : Type.
Parameter CSChainBytes : seq Cert -> bytes.

Notation CertChain := (seq Cert).

(* -------------------------------------------------------------------- *)
Inductive PMS : Type := PMS_RSA | PMS_DHE.

(* -------------------------------------------------------------------- *)
Record SessionInfo := mkSessionInfo {
  si_init_crand       : random;
  si_init_srand       : random;
  si_protocol_version : ProtocolVersion;
  si_cipher_suite     : ValidCipherSuite;
  si_compression      : Compression;
  si_pmsId            : PMS;
  si_clientID         : CertChain;
  si_clientSigAlg     : SigHashAlg;
  si_serverID         : CertChain;
  si_serverSigAlg     : SigHashAlg;
  si_client_auth      : bool;
  si_sessionID        : sessionID
}.

(* -------------------------------------------------------------------- *)
Inductive SI_Field : Type :=
| SI_init_crand
| SI_init_srand
| SI_protocol_version
| SI_cipher_suite
| SI_compression
| SI_pmsId
| SI_clientID
| SI_clientSigAlg
| SI_serverID
| SI_serverSigAlg
| SI_client_auth
| SI_sessionID.

(* -------------------------------------------------------------------- *)
Scheme Equality for SI_Field.

Lemma SIField_eqP (si1 si2 : SI_Field):
  reflect (si1 = si2) (SI_Field_beq si1 si2).
Proof.
  apply: (iffP idP).
    by apply/internal_SI_Field_dec_bl.
    by apply/internal_SI_Field_dec_lb.
Qed.

Definition SIField_eqMixin := EqMixin SIField_eqP.
Canonical  SIField_eqType  := Eval hnf in EqType SI_Field SIField_eqMixin.

(* -------------------------------------------------------------------- *)
Definition SI_Fields := [::
  SI_init_crand      ;
  SI_init_srand      ;
  SI_protocol_version;
  SI_cipher_suite    ;
  SI_compression     ;
  SI_pmsId           ;
  SI_clientID        ;
  SI_clientSigAlg    ;
  SI_serverID        ;
  SI_serverSigAlg    ;
  SI_client_auth     ;
  SI_sessionID
].

(* -------------------------------------------------------------------- *)
Lemma SI_Fields_enumP: Finite.axiom SI_Fields.
Proof. by case. Qed.

(* -------------------------------------------------------------------- *)
Definition SI_FieldEq sif :=
  match sif return SessionInfo -> SessionInfo -> Prop with
  | SI_init_crand       => fun si si' => si.(si_init_crand      ) = si'.(si_init_crand      )
  | SI_init_srand       => fun si si' => si.(si_init_srand      ) = si'.(si_init_srand      )
  | SI_protocol_version => fun si si' => si.(si_protocol_version) = si'.(si_protocol_version)
  | SI_cipher_suite     => fun si si' => si.(si_cipher_suite    ) = si'.(si_cipher_suite    )
  | SI_compression      => fun si si' => si.(si_compression     ) = si'.(si_compression     )
  | SI_pmsId            => fun si si' => si.(si_pmsId           ) = si'.(si_pmsId           )
  | SI_clientID         => fun si si' => si.(si_clientID        ) = si'.(si_clientID        )
  | SI_clientSigAlg     => fun si si' => si.(si_clientSigAlg    ) = si'.(si_clientSigAlg    )
  | SI_serverID         => fun si si' => si.(si_serverID        ) = si'.(si_serverID        )
  | SI_serverSigAlg     => fun si si' => si.(si_serverSigAlg    ) = si'.(si_serverSigAlg    )
  | SI_client_auth      => fun si si' => si.(si_client_auth     ) = si'.(si_client_auth     )
  | SI_sessionID        => fun si si' => si.(si_sessionID       ) = si'.(si_sessionID       )
  end.

(* -------------------------------------------------------------------- *)
Fixpoint SI_FieldEqs sifs si si' :=
  match sifs with
  | [::]        => True
  | [:: sif]    => SI_FieldEq sif si si'
  | sif :: sifs => (SI_FieldEq sif si si' * SI_FieldEqs sifs si si')%type
  end.

(* -------------------------------------------------------------------- *)
Definition EqExceptPmsID (si si' : SessionInfo) := Eval simpl in
  SI_FieldEqs (rem SI_pmsId SI_Fields) si si'.

(* -------------------------------------------------------------------- *)
Definition EqExceptClientID (si si' : SessionInfo) := Eval simpl in
  SI_FieldEqs (rem SI_clientID SI_Fields) si si'.

(* -------------------------------------------------------------------- *)
Definition EqExceptClientSigAlg (si si' : SessionInfo) := Eval simpl in
  SI_FieldEqs (rem SI_clientSigAlg SI_Fields) si si'.

(* -------------------------------------------------------------------- *)
Definition EqExceptPmsClientID (si si' : SessionInfo) := Eval simpl in
  SI_FieldEqs (rems [:: SI_pmsId; SI_clientID; SI_clientSigAlg] SI_Fields) si si'.

(* -------------------------------------------------------------------- *)
Definition EqExceptServerID (si si' : SessionInfo) := Eval simpl in
  SI_FieldEqs (rem SI_serverID SI_Fields) si si'.

(* -------------------------------------------------------------------- *)
Definition EqExceptServerSigAlg (si si' : SessionInfo) := Eval simpl in
  SI_FieldEqs (rem SI_serverSigAlg SI_Fields) si si'.

(* -------------------------------------------------------------------- *)
Definition EqExceptClientAuth (si si' : SessionInfo) := Eval simpl in 
  SI_FieldEqs (rem SI_client_auth SI_Fields) si si'.

(* -------------------------------------------------------------------- *)
Definition DHEParamBytes (p g y : bytes) :=
  VLBytes 2 p ++ VLBytes 2 g ++ VLBytes 2 y.

(* -------------------------------------------------------------------- *)
Definition DigitallySignedBytes (sa : SigHashAlg) (p : bytes) (pv : ProtocolVersion) :=
  match pv with
  | TLS_1p2 => SigHashAlgBytes sa ++ VLBytes 2 p
  | _       => VLBytes 2 p
  end.

(* -------------------------------------------------------------------- *)
Definition ServerHelloMsg
  (pv : ProtocolVersion)
  (rd : random)
  (id : sessionID)
  (cs : ValidCipherSuite)
  (cp : Compression)
  (ex : bytes)
:=
  MessageBytes HT_server_hello (
      (PVBytes pv) ++ rd ++ id
   ++ (VCSBytes cs)
   ++ (CPBytes  cp)
   ++ ex).

(* -------------------------------------------------------------------- *)
Definition ServerHelloDoneMsg (b : bytes) :=
  MessageBytes HT_server_hello_done b.

(* -------------------------------------------------------------------- *)
Definition ClientHelloMsg
  (pv : ProtocolVersion)
  (rd : random)
  (id : sessionID)
  (cs : seq CipherSuite)
  (cp : seq Compression)
  (ex : bytes)
:=
  MessageBytes HT_client_hello (
      (PVBytes pv) ++ rd ++ id
   ++ (flatten (pmap CSBytes cs))
   ++ (MCPBytes cp)
   ++ ex).

(* -------------------------------------------------------------------- *)
Definition ServerKeyExchangeMsg_DHE pv (p g y : bytes) a (sign : bytes) :=
  MessageBytes HT_server_key_exchange
    (DHEParamBytes p g y ++ DigitallySignedBytes a sign pv).

(* -------------------------------------------------------------------- *)
Definition ClientKeyExchangeMsg_RSA pv (encpms : bytes) :=
  match pv with
  | SSL_3p0 => MessageBytes HT_client_key_exchange encpms
  | _       => MessageBytes HT_client_key_exchange (VLBytes 2 encpms)
  end.

(* -------------------------------------------------------------------- *)
Definition ClientKeyExchangeMsg_DHE (b : bytes) :=
  MessageBytes HT_client_key_exchange (VLBytes 2 b).

(* --------------------------------------------------------------------  *)
Definition CertificateVerifyMsg pv (sa : SigHashAlg) (sign : bytes) :=
  MessageBytes HT_certificate_verify (DigitallySignedBytes sa sign pv).

(* -------------------------------------------------------------------- *)
Definition CertificateMsg (cs : CertChain) :=
  MessageBytes HT_certificate (VLBytes 3 (CSChainBytes cs)).

(* -------------------------------------------------------------------- *)
Definition ClientFinishedMsg (cvd : bytes) := MessageBytes HT_finished cvd.
Definition ServerFinishedMsg (svd : bytes) := MessageBytes HT_finished svd.

(* -------------------------------------------------------------------- *)
Inductive CertType : Type :=
| RSA_sign
| DSA_sign
| RSA_fixed_dh
| DSA_fixed_dh.

(* -------------------------------------------------------------------- *)
Parameter CertificateRequestBody:
  ProtocolVersion -> seq CertType -> seq SigHashAlg -> seq bytes -> bytes.

Definition CertificateRequestMsg
  (pv : ProtocolVersion)
  (cs : seq CertType)
  (sa : seq SigHashAlg)
  (cn : seq bytes)
:=
  MessageBytes HT_certificate_request
    (CertificateRequestBody pv cs sa cn).

(* ==================================================================== *)
Inductive ServerLogBeforeClientCertificateRSA
  (si : SessionInfo)
  (pv : ProtocolVersion)
  (lg : log)
: Prop :=
| ServerLogBeforeClientCertificateRSA_Auth csl cml csess ex1 ex2 ctl sal nl of
     si.(si_client_auth)
   & lg =
          (ClientHelloMsg pv si.(si_init_crand) csess csl cml ex1)
       ++ (ServerHelloMsg si.(si_protocol_version) si.(si_init_srand) si.(si_sessionID)
                          si.(si_cipher_suite) si.(si_compression) ex2)
       ++ (CertificateMsg si.(si_serverID))
       ++ (CertificateRequestMsg si.(si_protocol_version) ctl sal nl)
       ++ (ServerHelloDoneMsg [::])

| ServerLogBeforeClientCertificateRSA_NoAuth cs cm sess ex1 ex2 of
      ~~ si.(si_client_auth)
    & lg =
           (ClientHelloMsg pv si.(si_init_crand) sess cs cm ex1)
        ++ (ServerHelloMsg si.(si_protocol_version) si.(si_init_srand) si.(si_sessionID)
                           si.(si_cipher_suite) si.(si_compression) ex2)
        ++ (CertificateMsg si.(si_serverID))
        ++ (ServerHelloDoneMsg [::]).

(* -------------------------------------------------------------------- *)
Inductive ServerLogBeforeClientCertificateDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeClientCertificateDHE_Auth
    cpv csl cml csess ex1 ex2 ctl sal nl p g y a sign
  of
      si.(si_client_auth)
    & lg =
            (ClientHelloMsg cpv si.(si_init_crand) csess csl cml ex1)
         ++ (ServerHelloMsg si.(si_protocol_version) si.(si_init_srand) si.(si_sessionID)
                            si.(si_cipher_suite) si.(si_compression) ex2)
         ++ (CertificateMsg si.(si_serverID))
         ++ (ServerKeyExchangeMsg_DHE si.(si_protocol_version) p g y a sign)
         ++ (CertificateRequestMsg si.(si_protocol_version) ctl sal nl)
         ++ (ServerHelloDoneMsg [::])

| ServerLogBeforeClientCertificateDHE_NoAuth
    pv cs cm sess ex1 ex2 p g y a sign
  of
     ~~ si.(si_client_auth)
   & lg =
           (ClientHelloMsg pv si.(si_init_crand) sess cs cm ex1)
        ++ (ServerHelloMsg si.(si_protocol_version) si.(si_init_srand) si.(si_sessionID)
                           si.(si_cipher_suite) si.(si_compression) ex2)
        ++ (CertificateMsg si.(si_serverID))
        ++ (ServerKeyExchangeMsg_DHE si.(si_protocol_version) p g y a sign)
        ++ (ServerHelloDoneMsg [::]).

(* -------------------------------------------------------------------- *)
Inductive ServerLogBeforeClientKeyExchangeRSA
  (si : SessionInfo)
  (pv : ProtocolVersion)
  (lg : log)
: Prop :=
| ServerLogBeforeClientKeyExchangeRSA_Auth lg' si' of
      si.(si_client_auth)
    & lg = lg' ++ CertificateMsg si.(si_clientID)
    & EqExceptClientID si' si
    & ServerLogBeforeClientCertificateRSA si' pv lg'

| ServerLogBefireClientKeyExchangeRSA_NoAuth of
      ~~ si.(si_client_auth)
    & ServerLogBeforeClientCertificateRSA si pv lg.

(* -------------------------------------------------------------------- *)
Inductive ServerLogBeforeClientKeyExchangeDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeClientKeyExchangeDHE_Auth lg' si' of
      si.(si_client_auth)
    & lg = lg' ++ CertificateMsg si.(si_clientID)
    & EqExceptClientID si' si
    & ServerLogBeforeClientCertificateDHE si' lg'

| ServerLogBefireClientKeyExchangeDHE_NoAuth of
      ~~ si.(si_client_auth)
    & ServerLogBeforeClientCertificateDHE si lg.

(* -------------------------------------------------------------------- *)
(* Parameter RSAPMS: CertChain -> ProtocolVersion -> 48.-tuple byte -> bytes. *)

Inductive ServerLogBeforeClientCertificateVerifyRSA
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeClientCertificateVerifyRSA_E
    si' pv lg' encpms
  of
     lg = lg' ++ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms
   & si.(si_pmsId) = PMS_RSA
   & EqExceptPmsID si' si
   & ServerLogBeforeClientKeyExchangeRSA si' pv lg'.

(* -------------------------------------------------------------------- *)
(* Parameter DHEPMS: forall (p g gs gc r : bytes), bytes. *)

Inductive ServerLogBeforeClientCertificateVerifyDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeClientCertificateVerifyDHE_E
    si' lg' gc
  of
      lg = lg' ++ ClientKeyExchangeMsg_DHE gc
    & si.(si_pmsId) = PMS_DHE
    & EqExceptPmsID si' si
    & ServerLogBeforeClientKeyExchangeDHE si' lg'.

(* -------------------------------------------------------------------- *)
Definition ServerLogBeforeClientCertificateVerify
  (si : SessionInfo)
  (lg : log)
: Prop :=
     (ServerLogBeforeClientCertificateVerifyRSA si lg)
  \/ (ServerLogBeforeClientCertificateVerifyDHE si lg).

(* -------------------------------------------------------------------- *)
Inductive ServerLogBeforeClientFinished
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeClientFinished_Auth si' lg' a sign of
      si.(si_client_auth)
    & lg = lg' ++ CertificateVerifyMsg si.(si_protocol_version) a sign
    & EqExceptClientSigAlg si' si
    & ServerLogBeforeClientCertificateVerify si' lg'

| ServerLogBeforeClientFinished_NoAuth of
       ~~ si.(si_client_auth)
    & ServerLogBeforeClientCertificateVerify si lg.

(* -------------------------------------------------------------------- *)
Inductive ServerLogBeforeServerFinished
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeServerFinished_E lg' cvd of
      lg = lg' ++ ClientFinishedMsg cvd
    & ServerLogBeforeClientFinished si lg'.

(* ==================================================================== *)
Inductive ClientLogBeforeServerHello
  (cr : random)
  (lg : log)
: Prop :=
| ClientLogBeforeServerHello_E pv csid cs cm ex1 of
    lg = ClientHelloMsg pv cr csid cs cm ex1.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeServerCertificate
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeServerCertificate_E lg' ex2 of
     lg = lg' ++ ServerHelloMsg si.(si_protocol_version) si.(si_init_srand) si.(si_sessionID)
                                si.(si_cipher_suite) si.(si_compression) ex2
   & ClientLogBeforeServerHello si.(si_init_crand) lg'.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeCertificateRequestRSA
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeCertificateRequestRSA_E si' lg' of
     lg = lg' ++ CertificateMsg si.(si_serverID)
   & EqExceptServerID si si'
   & ClientLogBeforeServerCertificate si' lg'.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeServerKeyExchangeDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeServerKeyExchangeDHE_E si' lg' of
     lg = lg' ++ CertificateMsg si.(si_serverID)
   & EqExceptServerID si si'
   & ClientLogBeforeServerCertificate si' lg'.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeCertificateRequestDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeCertificateRequestDHE_E si' lg' p g y a pv sign of
     lg = lg' ++ ServerKeyExchangeMsg_DHE pv p g y a sign
   & EqExceptServerSigAlg si' si
   & ClientLogBeforeServerKeyExchangeDHE si' lg'.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeServerHelloDoneRSA
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeServerHelloDoneRSA_Auth si' lg' ctl sal pv nl of
     si.(si_client_auth)
   & lg = lg' ++ CertificateRequestMsg pv ctl sal nl
   & EqExceptClientAuth si' si
   & ClientLogBeforeCertificateRequestRSA si' lg'

| ClientLogBeforeServerHelloDoneRSA_NoAuth si' of
     ~~ si.(si_client_auth)
   & EqExceptClientAuth si' si
   & ClientLogBeforeCertificateRequestRSA si' lg.

(* -------------------------------------------------------------------- *)
Inductive ClientLogAfterServerHelloDoneRSA
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogAfterServerHelloDoneRSA_E lg' b of
     lg = lg' ++ ServerHelloDoneMsg b
   & ClientLogBeforeServerHelloDoneRSA si lg'.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeServerHelloDoneDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeServerHelloDoneDHE_Auth si' lg' pv ctl sal nl of
     si.(si_client_auth)
   & lg = lg' ++ CertificateRequestMsg pv ctl sal nl
   & EqExceptClientAuth si' si
   & ClientLogBeforeCertificateRequestDHE si' lg'

| ClientLogBeforeServerHelloDoneDHE_NoAuth si' of
     ~~ si.(si_client_auth)
   & EqExceptClientAuth si' si
   & ClientLogBeforeCertificateRequestDHE si' lg.

(* -------------------------------------------------------------------- *)
Inductive ClientLogAfterServerHelloDoneDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogAfterServerHelloDoneDHE_E lg' b of
     lg = lg' ++ ServerHelloDoneMsg b
   & ClientLogBeforeServerHelloDoneDHE si lg'.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeClientFinishedRSA
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeClientFinishedRSA_Auth si' lg' encpms a sign of
     si.(si_client_auth) & si.(si_pmsId) = PMS_RSA & si.(si_clientID) <> [::]
   & lg = lg' ++ CertificateMsg si.(si_clientID)
              ++ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms
              ++ CertificateVerifyMsg si.(si_protocol_version) a sign
   & EqExceptPmsClientID si' si
   & ClientLogAfterServerHelloDoneRSA si' lg'

| ClientLogBeforeClientFinishedRSA_TryNoAuth si' lg' encpms of
     si.(si_client_auth) & si.(si_pmsId) = PMS_RSA & si.(si_clientID) = [::]
   & lg = lg' ++ CertificateMsg si.(si_clientID)
              ++ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms
   & EqExceptPmsClientID si' si
   & ClientLogAfterServerHelloDoneRSA si' lg'

| ClientLogBeforeClientFinishedRSA_NoAuth si' lg' encpms of
     ~~ si.(si_client_auth) & si.(si_pmsId) = PMS_RSA
   & lg = lg' ++ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms
   & EqExceptPmsClientID si' si
   & ClientLogAfterServerHelloDoneRSA si' lg'.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeClientFinishedDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeClientFinishedDHE_Auth si' lg' b a sign of
     si.(si_client_auth) & si.(si_pmsId) = PMS_DHE & si.(si_clientID) <> [::]
   & lg = lg' ++ CertificateMsg si.(si_clientID)
              ++ ClientKeyExchangeMsg_DHE b
              ++ CertificateVerifyMsg si.(si_protocol_version) a sign
   & EqExceptPmsClientID si' si
   & ClientLogAfterServerHelloDoneDHE si' lg'

| ClientLogBeforeClientFinishedDHE_TryNoAuth si' lg' b of
     si.(si_client_auth) & si.(si_pmsId) = PMS_DHE & si.(si_clientID) = [::]
   & lg = lg' ++ CertificateMsg si.(si_clientID)
              ++ ClientKeyExchangeMsg_DHE b
   & EqExceptPmsClientID si' si
   & ClientLogAfterServerHelloDoneDHE si' lg'

| ClientLogBeforeClientFinishedDHE_NoAuth si' lg' b of
     ~~ si.(si_client_auth) & si.(si_pmsId) = PMS_DHE
   & lg = lg' ++ ClientKeyExchangeMsg_DHE b
   & EqExceptPmsClientID si' si
   & ClientLogAfterServerHelloDoneDHE si' lg'.

(* -------------------------------------------------------------------- *)
Definition ClientLogBeforeClientFinished si log :=
     ClientLogBeforeClientFinishedRSA si log
  \/ ClientLogBeforeClientFinishedDHE si log.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeServerFinished
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeServerFinished_E lg' cvd of
    lg = lg' ++ ClientFinishedMsg cvd.

(* ==================================================================== *)
(* resumption log predicates *)

Inductive ServerLogBeforeServerFinishedResume
  (cr : random)
  (sr : random)
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeServerFinishedResume_E cpv csl cml ex1 ex2 csid of
    lg =    ClientHelloMsg cpv cr csid csl cml ex1
         ++ ServerHelloMsg si.(si_protocol_version) sr si.(si_sessionID)
                           si.(si_cipher_suite) si.(si_compression) ex2.

(* -------------------------------------------------------------------- *)
Inductive ServerLogBeforeClientFinishedResume
  (cr : random)
  (sr : random)
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeClientFinishedResume_E lg' svd of
      lg = lg' ++ ServerFinishedMsg svd
    & ServerLogBeforeServerFinishedResume cr sr si lg'.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeServerFinishedResume
  (cr : random)
  (sr : random)
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeServerFinishedResume_E lg' ex2 of
      lg = lg' ++ ServerHelloMsg si.(si_protocol_version) sr si.(si_sessionID)
                                 si.(si_cipher_suite) si.(si_compression) ex2
    & ClientLogBeforeServerHello cr lg'.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeClientFinishedResume
  (cr : random)
  (sr : random)
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeClientFinishedResume_E lg' svd of
      lg = lg' ++ ServerFinishedMsg svd
    & ClientLogBeforeServerFinishedResume cr sr si lg'.

(* ==================================================================== *)
Inductive ClientLogBeforeClientFinishedRSA_spec
  (si : SessionInfo)
  (lg : log)
: PMS -> bool -> Prop :=
| ClientLogBeforeClientFinishedRSA_Auth_spec
    pv1 csid cs cm ex1 ex2 pv2 ctl sal nl donemsg encpms sa sign
  of
      si.(si_client_auth) &
    lg =
       ClientHelloMsg pv1 si.(si_init_crand) csid cs cm ex1
    @@ ServerHelloMsg si.(si_protocol_version) si.(si_init_srand)
                      si.(si_sessionID) si.(si_cipher_suite)
                      si.(si_compression) ex2
    @@ CertificateMsg si.(si_serverID)
    @@ CertificateRequestMsg pv2 ctl sal nl
    @@ ServerHelloDoneMsg donemsg
    @@ CertificateMsg si.(si_clientID)
    @@ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms
    @@ CertificateVerifyMsg si.(si_protocol_version) sa sign
  : ClientLogBeforeClientFinishedRSA_spec si lg PMS_RSA true

| ClientLogBeforeClientFinishedRSA_TryNoAuth_spec
    pv1 csid cs cm ex1 ex2 pv2 ctl sla nl donemsg encpms
  of
     si.(si_client_auth) &
   lg =
       ClientHelloMsg pv1 si.(si_init_crand) csid cs cm ex1
    @@ ServerHelloMsg si.(si_protocol_version) si.(si_init_srand)
                      si.(si_sessionID) si.(si_cipher_suite)
                      si.(si_compression) ex2
    @@ CertificateMsg si.(si_serverID)
    @@ CertificateRequestMsg pv2 ctl sla nl
    @@ ServerHelloDoneMsg donemsg
    @@ CertificateMsg si.(si_clientID)
    @@ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms
  : ClientLogBeforeClientFinishedRSA_spec si lg PMS_RSA true

| ClientLogBeforeClientFinishedRSA_NoAuth_spec
    pv csid cs cm ex1 ex2 donemsg encpms
  of
     ~~ si.(si_client_auth) &
   lg =
       ClientHelloMsg pv si.(si_init_crand) csid cs cm ex1
    @@ ServerHelloMsg si.(si_protocol_version) si.(si_init_srand)
                      si.(si_sessionID) si.(si_cipher_suite)
                      si.(si_compression) ex2
    @@ CertificateMsg si.(si_serverID)
    @@ ServerHelloDoneMsg donemsg
    @@ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms
  : ClientLogBeforeClientFinishedRSA_spec si lg PMS_RSA false.

(* -------------------------------------------------------------------- *)
Lemma ClientLogBeforeClientFinishedRSA_P si lg:
     ClientLogBeforeClientFinishedRSA      si lg
  -> ClientLogBeforeClientFinishedRSA_spec si lg si.(si_pmsId) si.(si_client_auth).
Proof. case.
  + move=> si1 lg1 encpms sa sign auth eqpms _ -> eq1.
    case=> lg2 donemsg -> []; last by rewrite eq1 auth.
    move=> si2 lg3 ctl sal pv2 nl _ -> eq2.
    case=> si3 lg4 -> eq3; case=> lg5 ex2 ->.
    case=> pv1 csid cs cm ex1 ->; rewrite eqpms auth.
    by econstructor 1 => //; rewrite !catA -!(eq1, eq2, eq3).
  + move=> si1 lg1 encpms auth eqpms _ -> eq1.
    case=> lg2 donemsg -> []; last by rewrite eq1 auth.
    move=> si2 lg3 ctl sla pv2 nl _ -> eq2.
    case=> si3 lg4 -> eq3; case=> lg5 ex2 ->.
    case=> pv1 csid cs cm ex1 ->; rewrite eqpms auth.
    by econstructor 2 => //; rewrite !catA -!(eq1, eq2, eq3).
  + move=> si1 lg1 encpms Nauth eqpms -> eq1.
    case=> lg2 donemsg -> []; first by rewrite eq1 (negbTE Nauth).
    move=> si2 _ eq2; case=> si3 lg3 -> eq3; case=> lg4 ex2 ->.
    case=> pv csid cs cm ex1 ->; rewrite (negbTE Nauth) eqpms.
    by econstructor 3 => //; rewrite !catA -!(eq1, eq2, eq3).
Qed.

(* ==================================================================== *)
Inductive ClientLogBeforeClientFinishedDHE_spec
  (si : SessionInfo)
  (lg : log)
: PMS -> bool -> Prop :=
| ClientLogBeforeClientFinishedDHE_Auth_spec
    pv1 csid cs cm ex1 ex2 pv2 p g y dhea dhesign pv3 ctl sal nl donemsg dhe sa sign
  of
     si.(si_client_auth)
  &  lg =
       ClientHelloMsg pv1 (si_init_crand si) csid cs cm ex1
    @@ ServerHelloMsg (si_protocol_version si) (si_init_srand si)
                      (si_sessionID si) (si_cipher_suite si)
                      (si_compression si) ex2
    @@ CertificateMsg (si_serverID si)
    @@ ServerKeyExchangeMsg_DHE pv2 p g y dhea dhesign
    @@ CertificateRequestMsg pv3 ctl sal nl
    @@ ServerHelloDoneMsg donemsg
    @@ CertificateMsg (si_clientID si)
    @@ ClientKeyExchangeMsg_DHE dhe
    @@ CertificateVerifyMsg (si_protocol_version si) sa sign
  : ClientLogBeforeClientFinishedDHE_spec si lg PMS_DHE true

| ClientLogBeforeClientFinishedDHE_TryNoAuth_spec
    pv1 csid cs cm ex1 ex2 pv2 p g y dhea dhesig pv3 ctl nal nl donemsg dhe
  of
     si.(si_client_auth)
   & lg =
        ClientHelloMsg pv1 (si_init_crand si) csid cs cm ex1
     @@ ServerHelloMsg (si_protocol_version si) (si_init_srand si)
                       (si_sessionID si) (si_cipher_suite si)

                       (si_compression si) ex2
     @@ CertificateMsg (si_serverID si)
     @@ ServerKeyExchangeMsg_DHE pv2 p g y dhea dhesig
     @@ CertificateRequestMsg pv3 ctl nal nl
     @@ ServerHelloDoneMsg donemsg
     @@ CertificateMsg (si_clientID si)
     @@ ClientKeyExchangeMsg_DHE dhe
  : ClientLogBeforeClientFinishedDHE_spec si lg PMS_DHE true

| ClientLogBeforeClientFinishedDHE_NoAuth_spec
    pv1 csid cs cm ex1 ex2 pv2 p g y dhea dhesign donemsg dhe
  of
     ~~ si.(si_client_auth)
   & lg =
        ClientHelloMsg pv1 (si_init_crand si) csid cs cm ex1
     @@ ServerHelloMsg (si_protocol_version si) (si_init_srand si)
                       (si_sessionID si) (si_cipher_suite si)
                       (si_compression si) ex2
     @@ CertificateMsg (si_serverID si)
     @@ ServerKeyExchangeMsg_DHE pv2 p g y dhea dhesign
     @@ ServerHelloDoneMsg donemsg
     @@ ClientKeyExchangeMsg_DHE dhe
  : ClientLogBeforeClientFinishedDHE_spec si lg PMS_DHE false.

(* -------------------------------------------------------------------- *)
Lemma ClientLogBeforeClientFinishedDHE_P si lg:
     ClientLogBeforeClientFinishedDHE      si lg
  -> ClientLogBeforeClientFinishedDHE_spec si lg si.(si_pmsId) si.(si_client_auth).
Proof. case.
  + move=> si1 lg1 dhe sa sign auth eqpms _ -> eq1.
    case=> lg2 donemsg ->; case; last by rewrite eq1 auth.
    move=> si2 lg3 pv2 ctl sal nl _ -> eq2.
    case=> si3 lg4 p g y a pv dhesign -> eq3.
    case=> si4 lg5 -> eq4; case=> lg6 ex2 ->.
    case=> pv1 csid cs cm ex1 ->; rewrite eqpms auth.
    by econstructor 1 => //; rewrite !catA -!(eq1, eq2, eq3, eq4).
  + move=> si1 lg1 dhe auth eqpms _ -> eq1; case=> lg2 donemsg ->.
    case=> [si2 lg3 pv3 ctl nal nl _ -> eq2|]; last by rewrite eq1 auth.
    case=> si3 lg4 p g y dhea pv2 dhesig -> eq3.
    case=> si4 lg5 -> eq4; case=> lg6 ex2 ->.
    case=> pv1 csid cs cm ex1 ->; rewrite auth eqpms.
    by econstructor 2 => //; rewrite !catA -!(eq1, eq2, eq3, eq4).
  + move=> si1 lg1 dhe Nauth eqpms -> eq1.
    case=> lg2 donemsg ->; case; first by rewrite eq1 (negbTE Nauth).
    move=> si2 _ eq2; case=> si3 lg3 p g y dhea pv2 dhesign -> eq3.
    case=> si4 lg4 -> eq4; case=> lg5 ex2 ->.
    case=> pv1 csid cs cm ex1 ->; rewrite (negbTE Nauth) eqpms.
    by econstructor 3 => //; rewrite !catA -!(eq1, eq2, eq3, eq4).
Qed.

(* ==================================================================== *)
Inductive ServerLogBeforeClientCertificateVerifyRSA_spec
  (si : SessionInfo)
  (lg : log)
: PMS -> bool -> Prop :=
| ServerLogBeforeClientCertificateVerifyRSA_Auth_spec
    pv csess csl cml ex1 ex2 ctl sal nl encpms
  of
      si.(si_client_auth)
   & lg =
         ClientHelloMsg pv (si_init_crand si) csess csl cml ex1
      @@ ServerHelloMsg (si_protocol_version si) (si_init_srand si)
                        (si_sessionID si) (si_cipher_suite si)
                        (si_compression si) ex2
      @@ CertificateMsg (si_serverID si)
      @@ CertificateRequestMsg (si_protocol_version si) ctl sal nl
      @@ ServerHelloDoneMsg [::]
      @@ CertificateMsg (si_clientID si)
      @@ ClientKeyExchangeMsg_RSA (si_protocol_version si) encpms
   : ServerLogBeforeClientCertificateVerifyRSA_spec si lg PMS_RSA true

| ServerLogBeforeClientCertificateVerifyRSA_NoAuth_spec
    pv sess cs cm ex1 ex2 encpms
  of
     ~~ si.(si_client_auth)
   & lg = 
         ClientHelloMsg pv (si_init_crand si) sess cs cm ex1
      @@ ServerHelloMsg (si_protocol_version si) (si_init_srand si)
                        (si_sessionID si) (si_cipher_suite si)
                        (si_compression si) ex2
      @@ CertificateMsg (si_serverID si)
      @@ ServerHelloDoneMsg [::]
      @@ ClientKeyExchangeMsg_RSA (si_protocol_version si) encpms
   : ServerLogBeforeClientCertificateVerifyRSA_spec si lg PMS_RSA false.

(* -------------------------------------------------------------------- *)
Lemma ServerLogBeforeClientCertificateVerifyRSA_P si lg:
     ServerLogBeforeClientCertificateVerifyRSA      si lg
  -> ServerLogBeforeClientCertificateVerifyRSA_spec si lg si.(si_pmsId) si.(si_client_auth).
Proof. case.
  move=> si1 pv lg1 encpms -> eqpms eq1; case.
  + move=> lg2 si2 auth -> eq2; case; last by rewrite eq2 auth.
    move=> csl cml csess ex1 ex2 ctl sal nl _ ->.
    rewrite -!eq1 auth eqpms; econstructor 1.
      by rewrite -!eq1 auth.
    by rewrite ?catA ?(eq1, eq2) //.
  + move=> Nauth; case; first by rewrite -eq1 (negbTE Nauth).
    move=> cs cm sess ex1 ex2 _ ->; rewrite eqpms -!eq1 (negbTE Nauth).
    econstructor 2; first by rewrite -eq1 (negbTE Nauth).
   by rewrite ?catA ?eq1.
Qed.

(* ==================================================================== *)
Inductive ServerLogBeforeClientCertificateVerifyDHE_spec
  (si : SessionInfo)
  (lg : log)
: PMS -> bool -> Prop :=
| ServerLogBeforeClientCertificateVerifyDHE_Auth_spec
    cpv csess csl cml ex1 ex2 p g y dhea dhesign ctl sal nl gc
  of
     si.(si_client_auth)
   & lg =
         ClientHelloMsg cpv (si_init_crand si) csess csl cml ex1
      @@ ServerHelloMsg (si_protocol_version si) (si_init_srand si)
                        (si_sessionID si) (si_cipher_suite si)
                        (si_compression si) ex2
      @@ CertificateMsg (si_serverID si)
      @@ ServerKeyExchangeMsg_DHE (si_protocol_version si) p g y dhea dhesign
      @@ CertificateRequestMsg (si_protocol_version si) ctl sal nl
      @@ ServerHelloDoneMsg [::]
      @@ CertificateMsg (si_clientID si)
      @@ ClientKeyExchangeMsg_DHE gc
  : ServerLogBeforeClientCertificateVerifyDHE_spec si lg PMS_DHE true

| ServerLogBeforeClientCertificateVerifyDHE_NoAuth_spec
    pv sess cs cm ex1 ex2 p g y dhea dhesign gc
  of
    ~~ si.(si_client_auth)
  & lg =
        ClientHelloMsg pv (si_init_crand si) sess cs cm ex1
     @@ ServerHelloMsg (si_protocol_version si) (si_init_srand si)
                       (si_sessionID si) (si_cipher_suite si)
                       (si_compression si) ex2
     @@ CertificateMsg (si_serverID si)
     @@ ServerKeyExchangeMsg_DHE (si_protocol_version si) p g y dhea dhesign
     @@ ServerHelloDoneMsg [::]
     @@ ClientKeyExchangeMsg_DHE gc
  : ServerLogBeforeClientCertificateVerifyDHE_spec si lg PMS_DHE false.

(* -------------------------------------------------------------------- *)
Lemma ServerLogBeforeClientCertificateVerifyDHE_P si lg:
     ServerLogBeforeClientCertificateVerifyDHE      si lg
  -> ServerLogBeforeClientCertificateVerifyDHE_spec si lg si.(si_pmsId) si.(si_client_auth).
Proof. case.
 move=> si1 lg1 gc -> eqpms eq1; case.
 + move=> lg2 si2 auth -> eq2; case; last by rewrite eq2 auth.
   move=> cpv csl cml csess ex1 ex2 ctl sal nl p g y dhea dhesign.
   move=> _ ->; rewrite eqpms -!eq1 auth; econstructor 1.
     by rewrite -!eq1 auth. by rewrite -?catA !(eq1, eq2).
 + move=> Nauth; case; first by rewrite (negbTE Nauth).
   move=> pv cs cm sess ex1 ex2 p g y dhea dhesign _ ->.
   rewrite eqpms -!eq1 (negbTE Nauth); econstructor 2.
     by rewrite -!eq1 (negbTE Nauth). by rewrite -?catA ?eq1.
Qed.

(* ==================================================================== *)
(* INVERSION LEMMAS                                                     *)
(* ==================================================================== *)

(* -------------------------------------------------------------------- *)
Lemma TraceNonConfusion si1 si2 lg lg':
     ServerLogBeforeClientCertificateVerify si1 lg
  -> ClientLogBeforeClientFinished          si2 (lg ++ lg')
  -> [/\ si1.(si_pmsId)       = si2.(si_pmsId)
       & si1.(si_client_auth) = si2.(si_client_auth)].
Proof.                          (* ~45sec *)
  by do! case=> ?; repeat (
    match goal with
    | h: ServerLogBeforeClientCertificateVerifyRSA _ _ |- _ =>
        case/ServerLogBeforeClientCertificateVerifyRSA_P: h
    | h: ServerLogBeforeClientCertificateVerifyDHE _ _ |- _ =>
        case/ServerLogBeforeClientCertificateVerifyDHE_P: h
    | h: ClientLogBeforeClientFinishedRSA _ _ |- _ =>
        case/ClientLogBeforeClientFinishedRSA_P: h
    | h: ClientLogBeforeClientFinishedDHE _ _ |- _ =>
        case/ClientLogBeforeClientFinishedDHE_P: h
    end); try (by split; reflexivity);
    do? move=> ?; subst lg; (absurd false; first done);
    (match goal with x : _ = _ |- _ => move: x end); rewrite -!catA;
    do? (try (by move/catsIL/MessageBytes_inj1); move/catILs).
Qed.

(* -------------------------------------------------------------------- *)
Ltac take_tail E :=
  match goal with
  | |- take ?sz1 (?x1 ++ _) = take ?sz2 (?x2 ++ _) -> _ =>
      rewrite [X in X=_]take_cat [X in _=X]take_cat;
        try (have ->: sz1 < size x1 = false by rewrite 1?E);
        try (have ->: sz2 < size x2 = false by rewrite 1?E);
      match goal with |- _ ++ _ = _ ++ _ -> _ => idtac end
  end.

Ltac invert_log E n :=
  match n with
  | 0%N => idtac
  | _   => do n! (take_tail E; move/catsI; rewrite ?E => /(_ erefl))
  end;
  take_tail E; move/catI; rewrite ?E => /(_ erefl) [].

Definition E := (size_tuple, size_PVBytes, size_VCSBytes, size_CPBytes).

(* -------------------------------------------------------------------- *)
Lemma ClientHelloMsgI pv1 pv2 cr1 cr2 sess1 sess2 cs1 cs2 cm1 cm2 ex1 ex2:
       ClientHelloMsg pv1 cr1 sess1 cs1 cm1 ex1
     = ClientHelloMsg pv2 cr2 sess2 cs2 cm2 ex2
  -> cr1 = cr2.
Proof. by move/MessageBytes_inj2_take; invert_log E 1%N => /val_inj. Qed.

(* -------------------------------------------------------------------- *)
Lemma ServerHelloMsgI pv1 pv2 rd1 rd2 id1 id2 cs1 cs2 cp1 cp2 ex1 ex2:
        ServerHelloMsg pv1 rd1 id1 cs1 cp1 ex1
      = ServerHelloMsg pv2 rd2 id2 cs2 cp2 ex2
  -> [/\ pv1 = pv2, rd1 = rd2, id1 = id2, cs1 = cs2 & cp1 = cp2 ].
Proof.
  move/MessageBytes_inj2_take.
  invert_log E 0%N => /PVBytes_inj ->.
  invert_log E 0%N => /val_inj ->.
  invert_log E 0%N => /val_inj ->.
  invert_log E 0%N => /VCSBytes_inj ->.
  invert_log E 0%N => /CPBytes_inj ->.
  done.
Qed.

(* -------------------------------------------------------------------- *)
Definition EQSI si si' := Eval simpl in
  SI_FieldEqs
    [:: SI_init_crand      ;
        SI_init_srand      ;
        SI_protocol_version;
        SI_cipher_suite    ;
        SI_compression     ;
        SI_pmsId           ;
        SI_client_auth     ;
        SI_sessionID       ]
    si si'.

Theorem I1 si1 si2 lg:
     ClientLogBeforeClientFinished si1 lg
  -> ServerLogBeforeClientFinished si2 lg
  -> EQSI si1 si2.
Proof.
  move=> clog; case.
  + (* RSA *)
    move=> si2' lg2' a sign auth_si2 lgE eq2 slog; subst lg.
    case: (TraceNonConfusion slog clog) => eqpms eq_auth.
    case: slog; case: clog; rewrite -eq2 in auth_si2.
    * case/ClientLogBeforeClientFinishedRSA_P; last first.
        by rewrite -eq_auth auth_si2.
      - admit.
      - do 14! move=> ?; move=> auth_si1 lg2'E.
        case/ServerLogBeforeClientCertificateVerifyRSA_P; last first.
          by rewrite auth_si2.
        do 10! move=> ?; move=> _ lg2'E'; move: lg2'E.
        rewrite lg2'E' -!catA /EQSI eq2; case/catIL.
        move/ClientHelloMsgI; rewrite !eq2 => ->; case/catIL.
        case/ServerHelloMsgI=> -> -> -> -> ->.
        rewrite -[si_client_auth si2]eq2 eq_auth.
        by rewrite -[si_pmsId si2]eq2 eqpms.
    * by move=> clog slog; move: eqpms;
        case/ClientLogBeforeClientFinishedDHE_P: clog;
        case/ServerLogBeforeClientCertificateVerifyRSA_P: slog.
    * by move=> clog slog; move: eqpms;
        case/ClientLogBeforeClientFinishedRSA_P: clog;
        case/ServerLogBeforeClientCertificateVerifyDHE_P: slog.
    * case/ClientLogBeforeClientFinishedDHE_P; last first.
        by rewrite -eq_auth auth_si2.
      - admit.
      - do 20! move=> ?; move=> auth_si1 lg2'E.
        case/ServerLogBeforeClientCertificateVerifyDHE_P; last first.
          by rewrite auth_si2.
        do 15! move=> ?; move=> auth_si2' lg2'E'; move: lg2'E.
        rewrite lg2'E' -!catA /EQSI eq2; case/catIL.
        move/ClientHelloMsgI; rewrite !eq2 => ->; case/catIL.
        case/ServerHelloMsgI=> -> -> -> -> ->.
        rewrite -[si_client_auth si2]eq2 eq_auth.
        by rewrite -[si_pmsId si2]eq2 eqpms.
  + (* DHE *)
    move=> Nauth_si2 slog; rewrite -[lg]cats0 in clog.
    case: (TraceNonConfusion slog clog) => eqpms eq_auth.
    rewrite cats0 in clog; case: slog; case: clog.
    * case/ClientLogBeforeClientFinishedRSA_P.
      - by rewrite -eq_auth (negbTE Nauth_si2).
      - by rewrite -eq_auth (negbTE Nauth_si2).
      move=> pv csid cs cm ex1 ex2 donemsg encpms _ lgE.
      case/ServerLogBeforeClientCertificateVerifyRSA_P.
      - by rewrite (negbTE Nauth_si2).
      move=> pv' sess cs' cm' ex1' ex2' encpms' _.
      rewrite {}lgE /EQSI; case/catIL => /ClientHelloMsgI ->.
      by case/catIL=> /ServerHelloMsgI [-> -> -> -> ->].
    * by move=> clog slog; move: eqpms;
        case/ClientLogBeforeClientFinishedDHE_P: clog;
        case/ServerLogBeforeClientCertificateVerifyRSA_P: slog.
    * by move=> clog slog; move: eqpms;
        case/ClientLogBeforeClientFinishedRSA_P: clog;
        case/ServerLogBeforeClientCertificateVerifyDHE_P: slog.
    * case/ClientLogBeforeClientFinishedDHE_P.
      - by rewrite -eq_auth (negbTE Nauth_si2).
      - by rewrite -eq_auth (negbTE Nauth_si2).
      move=> pv1 csid cs cm ex1 ex2 pv2 p g y dhea dhesign domemsg dhe _ lgE.
      case/ServerLogBeforeClientCertificateVerifyDHE_P.
      - by rewrite (negbTE Nauth_si2).
      move=> pv' sess cs' cm' ex1' ex2' p' g' y' dhea' dhesign' gc.
      move=> _; rewrite {}lgE /EQSI; case/catIL => /ClientHelloMsgI ->.
      by case/catIL=> /ServerHelloMsgI [-> -> -> -> ->].
Qed.

(*
*** Local Variables: ***
*** coq-load-path: ("ssreflect" ".") ***
*** End: ***
 *)
