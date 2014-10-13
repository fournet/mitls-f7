(* --------------------------------------------------------------------  *)
Require Import ssreflect eqtype ssrbool ssrnat ssrfun seq.
Require Import fintype choice tuple ssralg ssrint zmodp.

Set Implicit Arguments.
Unset Strict Implicit.
Unset Printing Implicit Defensive.

Import GRing.Theory.

Local Open Scope ring_scope.

(* -------------------------------------------------------------------- *)
Section ExtraSeq.
  Variable T : Type.

  Lemma rev_inj: injective (@rev T).
  Proof. by elim=> [|x s ih] [|x' s'] /(congr1 rev); rewrite !revK. Qed.

  Lemma catIs (s1 s2 r1 r2 : seq T):
    size s1 = size s2 -> s1 ++ r1 = s2 ++ r2 -> s1 = s2.
  Proof.
    elim: s1 s2 => [|x1 s1 ih] [|x2 s2] //=.
    by case=> eq_sz [<- /ih ->].
  Qed.    

  Lemma catsI (s1 s2 r1 r2 : seq T):
    size s1 = size s2 -> s1 ++ r1 = s2 ++ r2 -> r1 = r2.
  Proof.
    move=> eq_sz eq; have: size (rev r1) = size (rev r2).
      move/(congr1 size): eq; rewrite !size_cat eq_sz => /eqP.
      by rewrite eqn_add2l !size_rev => /eqP ->.
    move/catIs=> eq_rev; apply/rev_inj/(eq_rev (rev s1) (rev s2)).
    by rewrite -!rev_cat eq.
  Qed.
End ExtraSeq.

(* -------------------------------------------------------------------- *)
Notation   byte    := 'Z_256.
Notation   bytes   := (seq byte).
Notation   "n %:I" := (nosimpl (@inZp 256.-1 n)) (at level 2, format "n %:I").

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
     (n1 < 2^(sz * 8))
  -> (n2 < 2^(sz * 8))
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
     (size b1 < 2^(n * 8))
  -> (size b2 < 2^(n * 8))
  -> VLBytes n b1 = VLBytes n b2 -> b1 = b2.
Proof.
  move=> szb1 szb2; rewrite /VLBytes !take_oversize; first last.
    by rewrite -ltnS prednK // expn_gt0.
    by rewrite -ltnS prednK // expn_gt0.
  by move/catsI; rewrite !size_IntBytes; apply.
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
Definition MessageBytes (ht : HandshakeType) (b : bytes) :=
  (HTBytes ht) ++ (VLBytes 3 b).

(* -------------------------------------------------------------------- *)
Lemma MessageBytes_inj1 ht1 b1 ht2 b2:
  MessageBytes ht1 b1 = MessageBytes ht2 b2 -> ht1 = ht2.
Proof. by move=> /catIs eq; apply/HTBytes_inj/eq; rewrite !size_HTBytes. Qed.

Lemma MessageBytes_inj2 ht1 b1 ht2 b2:
     (size b1 < 2^24)%N
  -> (size b2 < 2^24)%N
  -> MessageBytes ht1 b1 = MessageBytes ht2 b2 -> b1 = b2.
Proof. 
  move=> szb1 szb2 /catsI; rewrite !size_HTBytes => /(_ (erefl _)).
  by move/VLBytes_inj => -/(_ szb1 szb2); apply.
Qed.

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

Scheme Equality for SigAlg.

(* -------------------------------------------------------------------- *)
Definition SigAlgBytes sa :=
  match sa with
  | SA_RSA   => [:: 1%:I ]
  | SA_DSA   => [:: 2%:I ]
  | SA_ECDSA => [:: 3%:I ]
  end.

(* -------------------------------------------------------------------- *)
Notation SigHashAlg := (SigAlg * HashAlg)%type.

(* -------------------------------------------------------------------- *)
Definition SigHashAlgBytes (sah : SigHashAlg) :=
  let: (sa, ha) := sah in HashAlgBytes ha ++ SigAlgBytes sa. 

(* -------------------------------------------------------------------- *)
Inductive SCSVsuite : Type :=
| TLS_EMPTY_RENEGOTIATION_INFO_SCSV.

Scheme Equality for SCSVsuite.

(* -------------------------------------------------------------------- *)
Inductive CipherAlg : Type :=
| RC4_128
| TDES_EDE_CBC
| AES_128_CBC
| AES_256_CBC.

Scheme Equality for CipherAlg.

(* -------------------------------------------------------------------- *)
Inductive AEADAlg : Type :=
| AES_128_GCM
| AES_256_GCM.

Scheme Equality for AEADAlg.

(* -------------------------------------------------------------------- *)
Inductive KexAlg : Type :=
| RSA
| DH_DSS
| DH_RSA
| DHE_DSS
| DHE_RSA
| DH_anon.

Scheme Equality for KexAlg.

(* -------------------------------------------------------------------- *)
Inductive CSAuthEncAlg : Type :=
| CS_MtE  of CipherAlg * HashAlg
| CS_AEAD of AEADAlg   * HashAlg.

(* -------------------------------------------------------------------- *)
Inductive CipherSuite : Type :=
| NullCipherSuite
| CSCipherSuite      of KexAlg * CSAuthEncAlg
| OnlyMACCipherSuite of KexAlg * HashAlg
| SCSV               of SCSVsuite.

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
Proof. Abort.

(* -------------------------------------------------------------------- *)
Definition random    := 32.-tuple byte.
Definition sessionID := 32.-tuple byte.

(* -------------------------------------------------------------------- *)
Parameter Cert : Type.
Parameter CSChainBytes : seq Cert -> bytes.

Notation CertChain := (seq Cert).

(* -------------------------------------------------------------------- *)
Record SessionInfo := mkSessionInfo {
  si_init_crand       : random;
  si_init_srand       : random;
  si_protocol_version : ProtocolVersion;
  si_cipher_suite     : seq CipherSuite;
  si_compression      : seq Compression;
  si_extensions       : bytes;
  si_pmsId            : bytes;
  si_session_hash     : bytes;
  si_clientID         : CertChain;
  si_clientSigAlg     : SigHashAlg;
  si_serverID         : CertChain;
  si_serverSigAlg     : SigHashAlg;
  si_client_auth      : bool;
  si_sessionID        : sessionID
}.

(* -------------------------------------------------------------------- *)
Definition EqExceptPmsID (si si' : SessionInfo) :=
     si.(si_init_crand      ) = si'.(si_init_crand      )
  /\ si.(si_init_srand      ) = si'.(si_init_srand      )
  /\ si.(si_protocol_version) = si'.(si_protocol_version)
  /\ si.(si_cipher_suite    ) = si'.(si_cipher_suite    )
  /\ si.(si_compression     ) = si'.(si_compression     )
  /\ si.(si_extensions      ) = si'.(si_extensions      )
  /\ si.(si_session_hash    ) = si'.(si_session_hash    )
  /\ si.(si_clientID        ) = si'.(si_clientID        )
  /\ si.(si_clientSigAlg    ) = si'.(si_clientSigAlg    )
  /\ si.(si_serverID        ) = si'.(si_serverID        )
  /\ si.(si_serverSigAlg    ) = si'.(si_serverSigAlg    )
  /\ si.(si_client_auth     ) = si'.(si_client_auth     )
  /\ si.(si_sessionID       ) = si'.(si_sessionID       ).

(* -------------------------------------------------------------------- *)
Definition EqExceptClientID (si si' : SessionInfo) :=
     si.(si_init_crand      ) = si'.(si_init_crand      )
  /\ si.(si_init_srand      ) = si'.(si_init_srand      )
  /\ si.(si_protocol_version) = si'.(si_protocol_version)
  /\ si.(si_cipher_suite    ) = si'.(si_cipher_suite    )
  /\ si.(si_compression     ) = si'.(si_compression     )
  /\ si.(si_extensions      ) = si'.(si_extensions      )
  /\ si.(si_pmsId           ) = si'.(si_pmsId           )
  /\ si.(si_session_hash    ) = si'.(si_session_hash    )
  /\ si.(si_clientSigAlg    ) = si'.(si_clientSigAlg    )
  /\ si.(si_serverID        ) = si'.(si_serverID        )
  /\ si.(si_serverSigAlg    ) = si'.(si_serverSigAlg    )
  /\ si.(si_client_auth     ) = si'.(si_client_auth     )
  /\ si.(si_sessionID       ) = si'.(si_sessionID       ).

(* -------------------------------------------------------------------- *)
Definition EqExceptPmsClientID (si si' : SessionInfo) :=
     si.(si_init_crand      ) = si'.(si_init_crand      )
  /\ si.(si_init_srand      ) = si'.(si_init_srand      )
  /\ si.(si_protocol_version) = si'.(si_protocol_version)
  /\ si.(si_cipher_suite    ) = si'.(si_cipher_suite    )
  /\ si.(si_compression     ) = si'.(si_compression     )
  /\ si.(si_extensions      ) = si'.(si_extensions      )
  /\ si.(si_session_hash    ) = si'.(si_session_hash    )
  /\ si.(si_serverID        ) = si'.(si_serverID        )
  /\ si.(si_serverSigAlg    ) = si'.(si_serverSigAlg    )
  /\ si.(si_client_auth     ) = si'.(si_client_auth     )
  /\ si.(si_sessionID       ) = si'.(si_sessionID       ).

(* -------------------------------------------------------------------- *)
Definition EqExceptServerID (si si' : SessionInfo) :=
     si.(si_init_crand      ) = si'.(si_init_crand      )
  /\ si.(si_init_srand      ) = si'.(si_init_srand      )
  /\ si.(si_protocol_version) = si'.(si_protocol_version)
  /\ si.(si_cipher_suite    ) = si'.(si_cipher_suite    )
  /\ si.(si_compression     ) = si'.(si_compression     )
  /\ si.(si_extensions      ) = si'.(si_extensions      )
  /\ si.(si_pmsId           ) = si'.(si_pmsId           )
  /\ si.(si_session_hash    ) = si'.(si_session_hash    )
  /\ si.(si_clientID        ) = si'.(si_clientID        )
  /\ si.(si_clientSigAlg    ) = si'.(si_clientSigAlg    )
  /\ si.(si_serverSigAlg    ) = si'.(si_serverSigAlg    )
  /\ si.(si_client_auth     ) = si'.(si_client_auth     )
  /\ si.(si_sessionID       ) = si'.(si_sessionID       ).

(* -------------------------------------------------------------------- *)
Definition EqExceptClientSigAlg (si si' : SessionInfo) :=
     si.(si_init_crand      ) = si'.(si_init_crand      )
  /\ si.(si_init_srand      ) = si'.(si_init_srand      )
  /\ si.(si_protocol_version) = si'.(si_protocol_version)
  /\ si.(si_cipher_suite    ) = si'.(si_cipher_suite    )
  /\ si.(si_compression     ) = si'.(si_compression     )
  /\ si.(si_extensions      ) = si'.(si_extensions      )
  /\ si.(si_pmsId           ) = si'.(si_pmsId           )
  /\ si.(si_session_hash    ) = si'.(si_session_hash    )
  /\ si.(si_clientID        ) = si'.(si_clientID        )
  /\ si.(si_serverID        ) = si'.(si_serverID        )
  /\ si.(si_serverSigAlg    ) = si'.(si_serverSigAlg    )
  /\ si.(si_client_auth     ) = si'.(si_client_auth     )
  /\ si.(si_sessionID       ) = si'.(si_sessionID       ).

(* -------------------------------------------------------------------- *)
Definition EqExceptServerSigAlg (si si' : SessionInfo) :=
     si.(si_init_crand      ) = si'.(si_init_crand      )
  /\ si.(si_init_srand      ) = si'.(si_init_srand      )
  /\ si.(si_protocol_version) = si'.(si_protocol_version)
  /\ si.(si_cipher_suite    ) = si'.(si_cipher_suite    )
  /\ si.(si_compression     ) = si'.(si_compression     )
  /\ si.(si_extensions      ) = si'.(si_extensions      )
  /\ si.(si_pmsId           ) = si'.(si_pmsId           )
  /\ si.(si_session_hash    ) = si'.(si_session_hash    )
  /\ si.(si_clientID        ) = si'.(si_clientID        )
  /\ si.(si_clientSigAlg    ) = si'.(si_clientSigAlg    )
  /\ si.(si_serverID        ) = si'.(si_serverID        )
  /\ si.(si_client_auth     ) = si'.(si_client_auth     )
  /\ si.(si_sessionID       ) = si'.(si_sessionID       ).

(* -------------------------------------------------------------------- *)
Definition EqExceptClientAuth (si si' : SessionInfo) :=
     si.(si_init_crand      ) = si'.(si_init_crand      )
  /\ si.(si_init_srand      ) = si'.(si_init_srand      )
  /\ si.(si_protocol_version) = si'.(si_protocol_version)
  /\ si.(si_cipher_suite    ) = si'.(si_cipher_suite    )
  /\ si.(si_compression     ) = si'.(si_compression     )
  /\ si.(si_extensions      ) = si'.(si_extensions      )
  /\ si.(si_pmsId           ) = si'.(si_pmsId           )
  /\ si.(si_session_hash    ) = si'.(si_session_hash    )
  /\ si.(si_clientID        ) = si'.(si_clientID        )
  /\ si.(si_clientSigAlg    ) = si'.(si_clientSigAlg    )
  /\ si.(si_serverID        ) = si'.(si_serverID        )
  /\ si.(si_serverSigAlg    ) = si'.(si_serverSigAlg    )
  /\ si.(si_sessionID       ) = si'.(si_sessionID       ).

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
  (cs : seq CipherSuite)
  (cp : seq Compression)
  (ex : bytes)
:=
  MessageBytes HT_server_hello (
      (PVBytes pv) ++ rd ++ id
   ++ (flatten (pmap CSBytes cs))
   ++ (MCPBytes cp)
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

| ServerLogBeforeClientCertificateRSA_NoAth cs cm sess ex1 ex2 of
      ~~ si.(si_client_auth)
    & lg =
           (ClientHelloMsg pv si.(si_init_crand) sess cs cm ex1)
        ++ (ServerHelloMsg si.(si_protocol_version) si.(si_init_srand) si.(si_sessionID)
                           si.(si_cipher_suite) si.(si_compression) ex2)
        ++ (CertificateMsg si.(si_serverID))
        ++ (ServerHelloDoneMsg [::])
.

(* -------------------------------------------------------------------- *)
Inductive ServerLogBeforeClientCertificateDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeClientCertificateDHE_Auth
    crand cpv csl cml csess ex1 ex2 ctl sal nl p g y a sign
  of
      si.(si_client_auth)
    & lg =
            (ClientHelloMsg cpv crand csess csl cml ex1)
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
    & ServerLogBeforeClientCertificateRSA si' pv lg'
    & EqExceptClientID si' si
    & lg = lg' ++ CertificateMsg si.(si_clientID)

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
    & ServerLogBeforeClientCertificateDHE si' lg'
    & EqExceptClientID si' si
    & lg = lg' ++ CertificateMsg si.(si_clientID)

| ServerLogBefireClientKeyExchangeDHE_NoAuth of
      ~~ si.(si_client_auth)
    & ServerLogBeforeClientCertificateDHE si lg.

(* -------------------------------------------------------------------- *)
Parameter RSAPMS: CertChain -> ProtocolVersion -> 48.-tuple byte -> bytes.

Inductive ServerLogBeforeClientCertificateVerifyRSA
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeClientCertificateVerifyRSA_E
    si' pv r lg' encpms
  of
     ServerLogBeforeClientKeyExchangeRSA si' pv lg'
   & EqExceptPmsID si' si
   & si.(si_pmsId) = RSAPMS si.(si_serverID) pv r
   & lg = lg' ++ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms.

(* -------------------------------------------------------------------- *)
Parameter DHEPMS: forall (p g gs gc r : bytes), bytes.

Inductive ServerLogBeforeClientCertificateVerifyDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeClientCertificateVerifyDHE_E
    si' lg' p g gc gs r
  of 
      ServerLogBeforeClientKeyExchangeDHE si' lg'
    & EqExceptPmsID si' si
    & si.(si_pmsId) = DHEPMS p g gs gc r
    & lg = lg' ++ ClientKeyExchangeMsg_DHE gc.

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
    & ServerLogBeforeClientCertificateVerify si' lg'
    & EqExceptClientSigAlg si' si
    & lg = lg' ++ CertificateVerifyMsg si.(si_protocol_version) a sign

| ServerLogBeforeClientFinished_NoAuth of
       ~~ si.(si_client_auth)
    & ServerLogBeforeClientCertificateVerify si lg.

(* -------------------------------------------------------------------- *)
Inductive ServerLogBeforeServerFinished
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ServerLogBeforeServerFinished_E lg' cvd of
      ServerLogBeforeClientFinished si lg'
    & lg = lg' ++ ClientFinishedMsg cvd.

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
| ClientLogBeforeServerCertificate_E lg' cr ex2 of
     ClientLogBeforeServerHello cr lg'
   & lg = lg' ++ ServerHelloMsg si.(si_protocol_version) si.(si_init_srand) si.(si_sessionID)
                                si.(si_cipher_suite) si.(si_compression) ex2.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeCertificateRequestRSA
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeCertificateRequestRSA_E si' lg' of
     ClientLogBeforeServerCertificate si' lg'
   & EqExceptServerID si si'
   & lg = lg' ++ CertificateMsg si.(si_serverID).

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeServerKeyExchangeDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeServerKeyExchangeDHE_E si' lg' of
     ClientLogBeforeServerCertificate si' lg'
   & EqExceptServerID si si'
   & lg = lg' ++ CertificateMsg si.(si_serverID).

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeCertificateRequestDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeCertificateRequestDHE_E si' lg' p g y a pv sign of
     ClientLogBeforeServerKeyExchangeDHE si' lg'
   & EqExceptServerSigAlg si' si
   & lg = lg' ++ ServerKeyExchangeMsg_DHE pv p g y a sign.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeServerHelloDoneRSA
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeServerHelloDoneRSA_Auth si' lg' ctl sal pv nl of
     si.(si_client_auth)
   & ClientLogBeforeCertificateRequestRSA si' lg'
   & EqExceptClientAuth si' si
   & lg = lg' ++ CertificateRequestMsg pv ctl sal nl

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
     ClientLogBeforeServerHelloDoneRSA si lg'
   & lg = lg' ++ ServerHelloDoneMsg b.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeServerHelloDoneDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeServerHelloDoneDHE_Auth si' lg' pv ctl sal nl of
     si.(si_client_auth)
   & ClientLogBeforeCertificateRequestDHE si' lg'
   & EqExceptClientAuth si' si
   & lg = lg' ++ CertificateRequestMsg pv ctl sal nl

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
     ClientLogBeforeServerHelloDoneDHE si lg'
   & lg = lg' ++ ServerHelloDoneMsg b.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeCertificateVerifyRSA_Auth
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeCertificateVerifyRSA_Auth_E si' lg' encpms of
     ClientLogAfterServerHelloDoneRSA si' lg'
   & si'.(si_client_auth)
   & EqExceptPmsClientID si' si
   & lg = lg' ++ CertificateMsg si.(si_clientID)
              ++ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeCertificateVerifyDHE_Auth
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeCertificateVerifyDHE_Auth_E si' lg' b of
     ClientLogAfterServerHelloDoneDHE si' lg'
   & si'.(si_client_auth)
   & EqExceptPmsClientID si' si
   & lg = lg' ++ CertificateMsg si.(si_clientID)
              ++ ClientKeyExchangeMsg_DHE b.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeClientFinishedRSA
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeClientFinishedRSA_Auth si' lg' encpms a sign of
     si.(si_client_auth) = true & si.(si_clientID) <> [::]
   & ClientLogAfterServerHelloDoneRSA si' lg'
   & EqExceptPmsClientID si' si
   & lg = lg' ++ CertificateMsg si.(si_clientID)
              ++ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms
              ++ CertificateVerifyMsg si.(si_protocol_version) a sign

| ClientLogBeforeClientFinishedRSA_TryNoAuth si' lg' encpms of
     si.(si_client_auth) = true & si.(si_clientID) = [::]
   & ClientLogAfterServerHelloDoneRSA si' lg'
   & EqExceptPmsClientID si' si
   & lg = lg' ++ CertificateMsg si.(si_clientID)
              ++ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms

| ClientLogBeforeClientFinishedRSA_NoAuth si' lg' encpms of
     ~~ si.(si_client_auth)
   & ClientLogAfterServerHelloDoneRSA si' lg'
   & EqExceptPmsClientID si' si
   & lg = lg' ++ ClientKeyExchangeMsg_RSA si.(si_protocol_version) encpms.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeClientFinishedDHE
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeClientFinishedDHE_Auth si' lg' b a sign of
     si.(si_client_auth) & si.(si_clientID) <> [::]
   & ClientLogAfterServerHelloDoneDHE si' lg'
   & EqExceptPmsClientID si' si
   & lg = lg' ++ CertificateMsg si.(si_clientID)
              ++ ClientKeyExchangeMsg_DHE b
              ++ CertificateVerifyMsg si.(si_protocol_version) a sign

| ClientLogBeforeClientFinishedDHE_TryNoAuth_E si' lg' b of
     si.(si_client_auth) & si.(si_clientID) = [::]
   & ClientLogAfterServerHelloDoneDHE si' lg'
   & EqExceptPmsClientID si' si
   & lg = lg' ++ CertificateMsg si.(si_clientID)
              ++ ClientKeyExchangeMsg_DHE b

| ClientLogBeforeClientFinishedDHE_NoAuth si' lg' b of
     ~~ si.(si_client_auth)
   & ClientLogAfterServerHelloDoneDHE si' lg'
   & EqExceptPmsClientID si' si
   & lg = lg' ++ ClientKeyExchangeMsg_DHE b.

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
      ServerLogBeforeServerFinishedResume cr sr si lg'
    & lg = lg' ++ ServerFinishedMsg svd.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeServerFinishedResume
  (cr : random)
  (sr : random)
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeServerFinishedResume_E lg' ex2 of
      ClientLogBeforeServerHello cr lg'
    & lg = lg' ++ ServerHelloMsg si.(si_protocol_version) sr si.(si_sessionID)
                                 si.(si_cipher_suite) si.(si_compression) ex2.

(* -------------------------------------------------------------------- *)
Inductive ClientLogBeforeClientFinishedResume
  (cr : random)
  (sr : random)
  (si : SessionInfo)
  (lg : log)
: Prop :=
| ClientLogBeforeClientFinishedResume_E lg' svd of
      ClientLogBeforeServerFinishedResume cr sr si lg'
    & lg = lg' ++ ServerFinishedMsg svd.

(* ==================================================================== *)
(* INVERSION LEMMAS                                                     *)
(* ==================================================================== *)
Theorem I1 si1 si2 lg:
     ClientLogBeforeClientFinished si1 lg
  -> ServerLogBeforeClientFinished si2 lg
  -> si1 = si2.
