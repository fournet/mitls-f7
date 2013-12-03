(*
 * Proof of Theorem 2 in the Technical Report
 *
 * Theorem: if the pre-master secret KEM used in the TLS handshake is
 * both One-Way and Non-Randomizable under Plaintext-Checking Attacks,
 * then the master secret KEM, seen as an agile labeled KEM, is
 * Indistinguishable under Replayable Chosen-Ciphertext Attacks in the
 * ROM for the underlying agile KEF.
 *
 *)
require import Bool.
require import Int.
require import Real.
require import FMap.
require import Pair.
import FSet.
import OptionGet.

lemma eq_except_in_dom : 
  forall (m1 m2:('a, 'b) map) (x y:'a),
   eq_except m1 m2 x => x <> y => (in_dom y m1 <=> in_dom y m2) 
by [].

lemma eq_except_set :
  forall (m1 m2:('a, 'b) map) (x y:'a) (z:'b),
   eq_except m1 m2 x => eq_except m1.[y <- z] m2.[y <- z] x 
by [].

lemma nosmt triple_neq : forall (x1 x2:'a) (y1 y2:'b) (z1 z2:'c),
  x1 <> x2 \/ y1 <> y2 \/ z1 <> z2 => (x1, (y1, z1)) <> (x2, (y2, z2))
by [].

theory Agile_KEF.

 type parameter.
 type secret.
 type key.

 op key : key distr.
 
 axiom lossless_key : Distr.weight key = 1%r.

 module type KEF = {
  fun init() : unit {*}
  fun extract(p:parameter, s:secret) : key
 }.

 module type Oracles = {
  fun extract(p:parameter, s:secret) : key
 }.

end Agile_KEF.


theory Agile_Labeled_KEM.

 type parameter.
 type pkey.
 type skey.
 type key.
 type label.
 type ciphertext.

 op key : key distr.

 axiom lossless_key : Distr.weight key = 1%r.

 module type KEM = {
  fun init() : unit {*}
  fun keygen() : pkey * skey
  fun enc(p:parameter, pk:pkey, t:label) : key * ciphertext
  fun dec(p:parameter, sk:skey, t:label, c:ciphertext) : key
 }.

 theory RCCA.

  const P : parameter set.

  const p' : parameter.

  axiom p'_in_P : mem p' P.

  module type Oracles = {
   fun dec(p:parameter, t:label, c:ciphertext) : key option
  }.

  module type Adversary(O:Oracles) = {
   fun choose(pk:pkey) : label
   fun guess(c:ciphertext, k:key) : bool
  }.
  
  module RCCA(KEM:KEM, A:Adversary) = {
   var pk : pkey
   var sk : skey
   var keys : key set
   var labels : label set
   
   module O = {  
    fun dec(p:parameter, t:label, c:ciphertext) : key option = {
      var k : key;
      var maybe_k : key option = None;
      if (!mem t labels /\ mem p P) { 
        labels = add t labels;
        k = KEM.dec(p, sk, t, c);
        maybe_k = if (!mem k keys) then Some k else None;
      }
      return maybe_k;
    }
   }
   
   module A = A(O)
  
   fun main() : bool = {
     var b, b', valid : bool;
     var k0, k1 : key;
     var c : ciphertext;
     var t : label;
     KEM.init();
     (pk, sk) = KEM.keygen();
     keys = FSet.empty;
     labels = FSet.empty;
     t = A.choose(pk);
     valid = !mem t labels; 
     (k0, c) = KEM.enc(p', pk, t);
     k1 = $key;
     b = ${0,1};
     keys = add k0 (add k1 keys);
     b' = A.guess(c, if b then k1 else k0);
     return (b = b' /\ valid);
   }
  }.

 end RCCA.


 theory OW_PCA.

  const P : parameter set.

  const p' : parameter.

  axiom p'_in_P : mem p' P.

  module type Oracles = {
   fun check(p:parameter, k:key, t:label, c:ciphertext) : bool
  }.

  module type Adversary(O:Oracles) = {
   fun choose(pk:pkey) : label
   fun guess(c:ciphertext) : key 
  }.

  module OW_PCA(KEM:KEM, A:Adversary) = {
   var sk : skey

   module O = {
    fun check(p:parameter, k:key, t:label, c:ciphertext) : bool = {
      var k' : key;
      k' = KEM.dec(p, sk, t, c);
      return (k' = k);
    }
   }
   
   module A = A(O)

   fun main() : bool = {
     var pk : pkey;
     var t : label;
     var k, k' : key;
     var c : ciphertext;
     KEM.init();
     (pk, sk) = KEM.keygen();
     t = A.choose(pk);
     (k, c) = KEM.enc(p', pk, t);
     k' = A.guess(c);
     return (k = k');
   }
  }.

 end OW_PCA.


 theory NR_PCA.

  const P : parameter set.

  const p' : parameter.

  axiom p'_in_P : mem p' P.

  module type Oracles = {
   fun check(p:parameter, k:key, t:label, c:ciphertext) : bool
  }.

  module type Adversary(O:Oracles) = {
   fun choose(pk:pkey) : label
   fun guess(c:ciphertext) : label * ciphertext
  }.

  module NR_PCA(KEM:KEM, A:Adversary) = {
   var sk : skey

   module O = {
    fun check(p:parameter, k:key, t:label, c:ciphertext) : bool = {
      var k' : key;
      k' = KEM.dec(p, sk, t, c);
      return (k' = k);
    }
   }
   
   module A = A(O)

   fun main() : bool = {
     var pk : pkey;
     var t, t' : label;
     var k, k' : key;
     var c, c' : ciphertext;
     KEM.init();
     (pk, sk) = KEM.keygen();
     t = A.choose(pk);
     (k, c) = KEM.enc(p', pk, t);
     (t', c') = A.guess(c);
     k' = KEM.dec(p', sk, t', c');
     return (c <> c' /\ k' = k);
   }
  }.

 end NR_PCA.

end Agile_Labeled_KEM.


type hash.
type version.
type label.
type pms.
type ms.

(* Shall we treat pv as a label or as a parameter? As a label for now *)
clone import Agile_Labeled_KEM as Inner_KEM with 
 type parameter <- unit,
 type key <- pms,
 type label <- version.

clone Inner_KEM.OW_PCA as OW_PCA with op P = FSet.single ().

clone Inner_KEM.NR_PCA as NR_PCA with op P = FSet.single ().

clone Agile_Labeled_KEM as Outer_KEM with 
 type pkey <- Inner_KEM.pkey,
 type skey <- Inner_KEM.skey,
 type key <- ms,
 type label <- label,
 type ciphertext <- Inner_KEM.ciphertext,
 type parameter <- version * hash.

clone Outer_KEM.RCCA as RCCA.

clone import Agile_KEF as KEF with
 type key <- ms,
 type parameter <- hash,
 type secret <- pms * label.

(* Master Secret KEM *)
module KEM(KEF:KEF, PMS_KEM:Inner_KEM.KEM) : Outer_KEM.KEM = {
 fun init() : unit = {
   PMS_KEM.init();
   KEF.init();
 }

 fun keygen() : pkey * skey = {
   var pk : pkey;
   var sk : skey;
   (pk, sk) = PMS_KEM.keygen();
   return (pk, sk);
 }

 fun enc(p:version * hash, pk:pkey, t:label) : ms * ciphertext = {
   var pms : pms;
   var ms : ms;
   var c : ciphertext;
   var pv : version;
   var h : hash;
   (pv, h) = p;
   (pms, c) = PMS_KEM.enc((), pk, pv);
   ms = KEF.extract(h, (pms, t));
   return (ms, c);
 }

 fun dec(p:version * hash, sk:skey, t:label, c:ciphertext) : ms = {
   var pms : pms;
   var ms : ms;
   var pv : version;
   var h : hash;
   (pv, h) = p;
   pms = PMS_KEM.dec((), sk, pv, c);
   ms = KEF.extract(h, (pms, t));
   return ms;
 }
}.


(* Agile KEF in the ROM *)
module RO_KEF : KEF = {
 var m : (hash * (pms * label), ms) map
 
 fun init() : unit = {
   m = FMap.Core.empty;
 }
 
 fun extract(p:hash, s:pms * label) : ms = {
   if (!in_dom (p, s) m) {
     m.[(p, s)] = $Outer_KEM.key;
   }
   return (proj m.[(p, s)]);
 }
}.

lemma lossless_init : islossless RO_KEF.init.
proof.
 by fun; wp.
qed.

lemma lossless_extract : islossless RO_KEF.extract.
proof.
 by fun; if => //; rnd; skip; progress; smt.
qed. 

(* RCCA Adversary in the ROM *)
module type Adversary(KO:KEF.Oracles, O:RCCA.Oracles) = {
 fun choose(pk:pkey) : label {* O.dec KO.extract}
 fun guess(c:ciphertext, k:ms) : bool
}.


section.

 declare module PMS_KEM : Inner_KEM.KEM 
   {RO_KEF, RCCA.RCCA, NR_PCA.NR_PCA, OW_PCA.OW_PCA}.

 axiom lossless_pmsinit : islossless PMS_KEM.init.

 axiom lossless_keygen : islossless PMS_KEM.keygen.

 axiom lossless_enc : islossless PMS_KEM.enc.

 axiom lossless_dec : islossless PMS_KEM.dec.

 (* PMS_KEM is stateless *)
 axiom stateless_pms_kem : forall (x y:glob PMS_KEM), x = y.

 (* Decryption si functional *)
 op decrypt : skey -> version -> ciphertext -> pms.

 (* Crucial *)
 axiom dec_injective_pv : forall sk pv1 pv2 c,
   decrypt sk pv1 c = decrypt sk pv2 c => pv1 = pv2.

 (* TODO: add relation between pk and sk *)
 axiom enc_spec_rel : forall (sk:skey) (_pk:pkey) (_pv:version),
   equiv [ PMS_KEM.enc ~ PMS_KEM.enc :
    pk{1} = _pk /\ t{1} = _pv /\ ={pk, t} ==>
    ={res} /\ let (pms, c) = res{1} in decrypt sk _pv c = pms].

 axiom dec_spec_rel : forall (_sk:skey) (_pv:version) (_c:ciphertext),
   equiv [ PMS_KEM.dec ~ PMS_KEM.dec :
    sk{1} = _sk /\ t{1} = _pv /\ c{1} = _c /\ ={sk, t, c} ==>
    ={res} /\ res{1} = decrypt _sk _pv _c ].

 (* TODO: is it needed? *)
 axiom dec_spec : forall (_sk:skey) (_pv:version) (_c:ciphertext),
   bd_hoare [ PMS_KEM.dec : 
    sk = _sk /\ t = _pv /\ c = _c ==> res = decrypt _sk _pv _c ] = 1%r.

 local module MS_KEM = KEM(RO_KEF, PMS_KEM).

 declare module A : Adversary
   {RO_KEF, PMS_KEM, RCCA.RCCA, NR_PCA.NR_PCA, OW_PCA.OW_PCA}.

 axiom lossless_choose : 
   forall (KO <: KEF.Oracles{A}) (O <: RCCA.Oracles{A}),
    islossless O.dec => islossless KO.extract => islossless A(KO, O).choose.

 axiom lossless_guess : 
   forall (KO <: KEF.Oracles{A}) (O <: RCCA.Oracles{A}),
    islossless O.dec => islossless KO.extract => islossless A(KO, O).guess.

 import RCCA.

 (* Global variables in RCCA1 and RCCA2 *)
 local module V = {
  var pk : pkey
  var sk : skey
  var keys : ms set
  var labels : label set
  var t : label
  var c : ciphertext 
  var pms : pms
  var guess : bool

  fun init() : unit = {
    V.keys = FSet.empty;
    V.labels = FSet.empty;
    V.guess = false;
  }
 }.

 local module RCCA1 = {
  var m : (hash * (pms * label), ms) map
  var abort : bool

  module O = {
   fun extract(p:hash, s:pms * label) : ms = {
     var pms : pms;
     var t : label;
     (pms, t) = s;
     abort = abort \/ (p = snd p' /\ pms = V.pms);
     if (!in_dom (p, (pms, t)) m) m.[(p, (pms, t))] = $Outer_KEM.key;
     return proj m.[(p, (pms, t))];
   }

   fun dec(p:version * hash, t:label, c:ciphertext) : ms option = {
     var pv : version;
     var h : hash;
     var pms : pms;
     var k : ms;
     var maybe_k : ms option = None;
     if (!mem t V.labels /\ mem p P) { 
       V.labels = add t V.labels;
       (pv, h) = p;
       pms = PMS_KEM.dec((), V.sk, pv, c);
       abort = abort \/ (V.guess /\ pms = V.pms /\ t = V.t /\ c <> V.c);
       if (!(V.guess /\ (pv, h) = p' /\ t = V.t /\ c = V.c)) {
         if (!in_dom (h, (pms, t)) m) m.[(h, (pms, t))] = $Outer_KEM.key;
         k = proj m.[(h, (pms, t))];
         maybe_k = if (!mem k V.keys) then Some k else None;
       }
     }
     return maybe_k;
   }
  }
  
  module A = A(O, O)

  fun main() : bool = {
    var b, b', valid : bool;
    var k0, k1 : ms;
    PMS_KEM.init();
    (V.pk, V.sk) = PMS_KEM.keygen();
    V.init();
    m = FMap.Core.empty;
    abort = false;
    (V.pms, V.c) = PMS_KEM.enc((), V.pk, fst p');
    V.t = A.choose(V.pk);
    valid = !mem V.t V.labels;
    k0 = $Outer_KEM.key;
    k1 = $Outer_KEM.key;
    V.keys = add k0 (add k1 V.keys);
    V.guess = true;
    b' = A.guess(V.c, k0);
    b = ${0,1};
    return (b = b' /\ valid);
  }
 }.

 (** RCCA -> RCCA 1 **)

 local equiv RCCA_RCCA1_extract_upto :
   RO_KEF.extract ~ RCCA1.O.extract :
   !RCCA1.abort{2} /\
   ={p, s} /\
   V.guess{2} /\
   RCCA.pk{1} = V.pk{2} /\
   RCCA.sk{1} = V.sk{2} /\
   RCCA.keys{1} = V.keys{2} /\
   RCCA.labels{1} = V.labels{2} /\
   eq_except RO_KEF.m{1} RCCA1.m{2} (snd p', (V.pms, V.t)){2} /\
   in_dom (snd p', (V.pms, V.t)){2} RO_KEF.m{1} /\
   mem (proj RO_KEF.m{1}.[(snd p', (V.pms, V.t))]){2} V.keys{2} /\
   decrypt V.sk{2} (fst p') V.c{2} = V.pms{2}
   ==>
   !RCCA1.abort{2} =>
    ={res} /\
    V.guess{2} /\
    RCCA.pk{1} = V.pk{2} /\
    RCCA.sk{1} = V.sk{2} /\
    RCCA.keys{1} = V.keys{2} /\
    RCCA.labels{1} = V.labels{2} /\
    eq_except RO_KEF.m{1} RCCA1.m{2} (snd p', (V.pms, V.t)){2} /\
    in_dom (snd p', (V.pms, V.t)){2} RO_KEF.m{1} /\
    mem (proj RO_KEF.m{1}.[(snd p', (V.pms, V.t))]){2} V.keys{2} /\
    decrypt V.sk{2} (fst p') V.c{2} = V.pms{2}.
 proof.
  fun.
   sp; case RCCA1.abort{2}.
    (* aborts *)
    if{1}; if{2}.
     by rnd; skip; progress; smt.
     by rnd{1}; skip; progress; smt.
     by rnd{2}; skip; progress; smt.
     by skip; progress; smt.
   
    (* doesn't abort *)
    if.
     by progress; smt.
     by wp; rnd; skip; progress; smt.

    wp; skip; progress.
    cut W : 
      (p, (pms, t)){2} <>
      (snd p', (decrypt V.sk (fst p') V.c, V.t)){2}
    by apply triple_neq; smt.
 qed.

 local equiv RCCA_RCCA1_dec_upto :
   RCCA(MS_KEM, A(RO_KEF)).O.dec ~ RCCA1.O.dec :
   !RCCA1.abort{2} /\
   ={p, t, c} /\
   V.guess{2} /\
   RCCA.pk{1} = V.pk{2} /\
   RCCA.sk{1} = V.sk{2} /\
   RCCA.keys{1} = V.keys{2} /\
   RCCA.labels{1} = V.labels{2} /\
   eq_except RO_KEF.m{1} RCCA1.m{2} (snd p', (V.pms, V.t)){2} /\
   in_dom (snd p', (V.pms, V.t)){2} RO_KEF.m{1} /\
   mem (proj RO_KEF.m{1}.[(snd p', (V.pms, V.t))]){2} V.keys{2} /\
   decrypt V.sk{2} (fst p') V.c{2} = V.pms{2}
   ==>
   !RCCA1.abort{2} =>
    ={res} /\
    V.guess{2} /\
    RCCA.pk{1} = V.pk{2} /\
    RCCA.sk{1} = V.sk{2} /\
    RCCA.keys{1} = V.keys{2} /\
    RCCA.labels{1} = V.labels{2} /\
    eq_except RO_KEF.m{1} RCCA1.m{2} (snd p', (V.pms, V.t)){2} /\
    in_dom (snd p', (V.pms, V.t)){2} RO_KEF.m{1} /\
    mem (proj RO_KEF.m{1}.[(snd p', (V.pms, V.t))]){2} V.keys{2} /\
    decrypt V.sk{2} (fst p') V.c{2} = V.pms{2}.
proof.
  fun.
  sp; if => //.  
  wp; inline KEM(RO_KEF, PMS_KEM).dec.
  seq 7 3 : 
   ((decrypt RCCA.sk pv c0 = pms){1} /\
    maybe_k{1} = None /\
    sk{1} = RCCA.sk{1} /\ c0{1} = c{2} /\ t0{1} = t{2} /\
    ={maybe_k, pms, pv, h, p, t, c} /\
    !RCCA1.abort{2} /\ 
    V.guess{2} /\
    RCCA.pk{1} = V.pk{2} /\
    RCCA.sk{1} = V.sk{2} /\
    RCCA.keys{1} = V.keys{2} /\
    RCCA.labels{1} = V.labels{2} /\
    eq_except RO_KEF.m{1} RCCA1.m{2} (snd p', (V.pms, V.t)){2} /\
    in_dom (snd p', (V.pms, V.t)){2} RO_KEF.m{1} /\
    mem (proj RO_KEF.m{1}.[(snd p', (V.pms, V.t))]){2} V.keys{2} /\
    decrypt V.sk{2} (fst p') V.c{2} = V.pms{2}).
   sp.
   exists * sk{1}, pv{1}, c0{1}; elim *; intros sk pv c.
   by call (dec_spec_rel sk pv c); wp.

   wp; sp; case RCCA1.abort{2}.
    (* aborts *)
    call{1} (_:true ==> true); first by apply lossless_extract.
    if{2}.
     if{2}.
      by wp; rnd{2}; skip; smt.
      by wp; skip; progress; smt.
     by skip; progress; smt.
 
   (* doesn't abort *)
   inline{1} RO_KEF.extract.
   if{2}.
    wp; sp; if.
     progress; try smt.
     by cut W :
      (snd p', (decrypt V.sk (fst p') V.c, V.t)){2} <>
      (h, (decrypt V.sk pv c, t)){2}; smt.
     by rnd; skip; progress; smt.
    
    skip; progress.
    cut W :
     (snd p', (decrypt V.sk (fst p') V.c, V.t)){2} <>
     (h, (decrypt V.sk pv c, t)){2} by smt.
    by generalize H1; rewrite eq_except_def; smt.

   wp; sp; if{1}.
    by rnd{1}; skip; progress; smt.
    by skip; progress; smt.
 qed.

 local lemma RCCA_lossless_dec : islossless RCCA(MS_KEM, A(RO_KEF)).O.dec.
 proof.
  fun.
  sp; if => //.
  inline KEM(RO_KEF, PMS_KEM).dec; wp; sp.
  seq 1 : true => //.
   by call (_:true) => //; apply lossless_dec.
   by call (_:true ==> true) => //; apply lossless_extract.
 qed.

 local lemma RCCA1_dec_preserves_abort : 
   bd_hoare [ RCCA1.O.dec : RCCA1.abort ==> RCCA1.abort ] = 1%r.
 proof.
  fun.
  sp; if => //; wp.
  seq 3 : RCCA1.abort => //.
   by call (_:RCCA1.abort); [apply lossless_dec | wp]. 
   sp; if => //; wp; if. 
    by rnd; skip; smt.
    by wp; skip; smt.
   by bd_hoare; call (_:RCCA1.abort); wp.
 qed.

 local equiv RCCA_RCCA1_extract :
   RO_KEF.extract ~ RCCA1.O.extract :
   !RCCA1.abort{2} /\
   ={p, s} /\ 
   !V.guess{2} /\
   RO_KEF.m{1} = RCCA1.m{2} /\
   RCCA.pk{1} = V.pk{2} /\
   RCCA.sk{1} = V.sk{2} /\
   RCCA.keys{1} = V.keys{2} /\
   RCCA.labels{1} = V.labels{2} /\
   decrypt V.sk{2} (fst p') V.c{2} = V.pms{2} /\
   (forall t,
    in_dom (snd p', (V.pms, t)) RCCA1.m => 
    RCCA1.abort \/ mem t V.labels){2}
   ==>
   !RCCA1.abort{2} =>
    ={res} /\ 
    !V.guess{2} /\
    RO_KEF.m{1} = RCCA1.m{2} /\
    RCCA.pk{1} = V.pk{2} /\
    RCCA.sk{1} = V.sk{2} /\
    RCCA.keys{1} = V.keys{2} /\
    RCCA.labels{1} = V.labels{2} /\
    decrypt V.sk{2} (fst p') V.c{2} = V.pms{2} /\
    (forall t,
     in_dom (snd p', (V.pms, t)) RCCA1.m => 
     RCCA1.abort \/ mem t V.labels){2}.
 proof.
  fun.
  sp; case RCCA1.abort{2}.
   by if{1}; if{2}; try rnd{1}; try rnd{2}; skip; progress; smt.
   if => //.
    by rnd; skip; progress; try smt.
    by skip; progress; try smt.
 qed.

 local equiv RCCA_RCCA1_dec :
   RCCA(MS_KEM, A(RO_KEF)).O.dec ~ RCCA1.O.dec :
   !RCCA1.abort{2} /\
   ={p, t, c} /\ 
   !V.guess{2} /\
   RO_KEF.m{1} = RCCA1.m{2} /\
   RCCA.pk{1} = V.pk{2} /\
   RCCA.sk{1} = V.sk{2} /\
   RCCA.keys{1} = V.keys{2} /\
   RCCA.labels{1} = V.labels{2} /\
   (decrypt V.sk (fst p') V.c = V.pms){2} /\
   (forall t,
    in_dom (snd p', (V.pms, t)) RCCA1.m => 
    RCCA1.abort \/ mem t V.labels){2}
   ==>
   !RCCA1.abort{2} =>
    ={res} /\ 
    !V.guess{2} /\
    RO_KEF.m{1} = RCCA1.m{2} /\
    RCCA.pk{1} = V.pk{2} /\
    RCCA.sk{1} = V.sk{2} /\
    RCCA.keys{1} = V.keys{2} /\
    RCCA.labels{1} = V.labels{2} /\
    (decrypt V.sk (fst p') V.c = V.pms){2} /\
    (forall t,
     in_dom (snd p', (V.pms, t)) RCCA1.m => 
     RCCA1.abort \/ mem t V.labels){2}.
 proof.
  fun.
  sp; if => //.
  inline KEM(RO_KEF, PMS_KEM).dec.
  seq 7 3 :
    (!RCCA1.abort{2} /\
     !V.guess{2} /\
     ={maybe_k, pms, p, t, c} /\
     (pms = decrypt V.sk pv c){2} /\
     (pv{2}, h{2}) = p{2} /\
     t0{1} = t{1} /\
     p0{1} = p{1} /\
     sk{1} = RCCA.sk{1} /\
     c0{1} = c{1} /\
     (pv, h){1} = p0{1} /\
     mem t{2} V.labels{2} /\
     mem p{2} P /\
     RO_KEF.m{1} = RCCA1.m{2} /\
     RCCA.pk{1} = V.pk{2} /\
     RCCA.sk{1} = V.sk{2} /\
     RCCA.keys{1} = V.keys{2} /\
     RCCA.labels{1} = V.labels{2} /\
     (decrypt V.sk (fst p') V.c = V.pms){2} /\
     (forall t,
     in_dom (snd p', (V.pms, t)) RCCA1.m => 
     RCCA1.abort \/ mem t V.labels){2}).
   sp; exists * sk{1}, pv{1}, c0{1}; elim *; intros sk pv c.
   by call (dec_spec_rel sk pv c); skip; progress; smt.

   inline{1} RO_KEF.extract; wp; sp.
   if{2}.
    if => //.
     by wp; rnd; skip; progress; smt.
     by wp; skip; progress; smt.

    if{1}.
     by rnd{1}; skip; progress; smt.
     by skip; progress; smt.
 qed.

 (* TODO: workaround *) 
 local module M = RCCA(MS_KEM, A(RO_KEF)).

 local equiv RCCA_RCCA1 :
   RCCA(MS_KEM, A(RO_KEF)).main ~ RCCA1.main : 
   true ==> !RCCA1.abort{2} => ={res}.
 proof.
  fun.
  swap{1} 9 -3.
  swap{2} 14 -6.
  inline KEM(RO_KEF, PMS_KEM).enc.

  (* Workaround to swap PMS_KEM.enc *)
  transitivity {1} {
   MS_KEM.init();
   (RCCA.pk, RCCA.sk) = MS_KEM.keygen();
   RCCA.keys = FSet.empty;
   RCCA.labels = FSet.empty;
   (pms, c) = PMS_KEM.enc((), RCCA.pk, fst p');
   t = M.A.choose(RCCA.pk);
   b = ${0,1};
   valid = !mem t RCCA.labels;
   k0 = RO_KEF.extract(snd p', (pms, t));
   k1 = $Outer_KEM.key;
   RCCA.keys = add k0 (add k1 RCCA.keys);
   b'= M.A.guess(c, b ? k1 : k0);
  }
  (true ==> ={b, b', valid, RCCA1.abort})
  (true ==> !RCCA1.abort{2} => 
   (b = b' /\ valid){1} = (b = b' /\ valid){2}) => //.
  swap{1} 6 6; swap{1} 6 6.
  inline RO_KEF.extract MS_KEM.init KEM(RO_KEF, PMS_KEM).init;
  eqobs_in; wp; rnd.
  admit (* swap{2} 6 1.*).
  (*********************************)

  seq 7 8 : 
   (={b} /\
    pms{1} = V.pms{2} /\
    c{1} = V.c{2} /\
    (!RCCA1.abort{2} =>
     ={glob A} /\
     t{1} = V.t{2} /\
     RO_KEF.m{1} = RCCA1.m{2} /\
     RCCA.pk{1} = V.pk{2} /\
     RCCA.sk{1} = V.sk{2} /\
     RCCA.keys{1} = V.keys{2} /\
     RCCA.labels{1} = V.labels{2} /\
     (decrypt V.sk (fst p') V.c = V.pms){2} /\
     (forall t,
      in_dom (snd p', (V.pms, t)) RCCA1.m => mem t V.labels){2})).
   wp; rnd; simplify.
   call (_:RCCA1.abort,
    !V.guess{2} /\
    RO_KEF.m{1} = RCCA1.m{2} /\
    RCCA.pk{1} = V.pk{2} /\
    RCCA.sk{1} = V.sk{2} /\
    RCCA.keys{1} = V.keys{2} /\
    RCCA.labels{1} = V.labels{2} /\
    (decrypt V.sk (fst p') V.c = V.pms){2} /\
    (forall t,
     in_dom (snd p', (V.pms, t)) RCCA1.m => 
     RCCA1.abort \/ mem t V.labels){2}).
    by apply lossless_choose.
    by apply RCCA_RCCA1_dec.
    by progress; apply RCCA_lossless_dec.
    by apply RCCA1_dec_preserves_abort.
    by apply RCCA_RCCA1_extract.
    by intros _ _; apply lossless_extract.
    intros _; fun; sp; if.
     by rnd; skip; smt.
     by skip; smt.

  seq 2 2 : 
   (RCCA.pk{1} = V.pk{2} /\
    RCCA.sk{1} = V.sk{2} /\
    RO_KEF.m{1} = FMap.Core.empty).
  inline MS_KEM.init RO_KEF.init MS_KEM.keygen.
  wp; call (_:true); wp; call (_:true); skip; progress.
  exists * V.sk{2}, V.pk{2}; elim *; intros sk pk.
  call (enc_spec_rel sk pk (fst p')).
  inline V.init; wp; skip; progress; try smt.

  inline RO_KEF.extract; wp; sp.
  case RCCA1.abort{2}.
   call (_:RCCA1.abort, RCCA1.abort{2}).
    by apply lossless_guess.
    by exfalso; smt.
    by progress; apply RCCA_lossless_dec.
    by apply RCCA1_dec_preserves_abort.
    by exfalso; smt.
    by progress; apply lossless_extract.
    intros _; fun; sp; if.
     by rnd; skip; smt.
     by skip; smt.
   wp; rnd; wp; if{1}.
    rnd; skip; progress; smt.
    rnd{2}; skip; progress; smt.

  (* !RCCA1.abort *)
  case valid{1}.
  rcondt{1} 1; first by intros _; skip; smt.
  call (_:RCCA1.abort,
   V.guess{2} /\
   RCCA.pk{1} = V.pk{2} /\
   RCCA.sk{1} = V.sk{2} /\
   RCCA.keys{1} = V.keys{2} /\
   RCCA.labels{1} = V.labels{2} /\
   eq_except RO_KEF.m{1} RCCA1.m{2} (snd p', (V.pms, V.t)){2} /\
   in_dom (snd p', (V.pms, V.t)){2} RO_KEF.m{1} /\
   mem (proj RO_KEF.m{1}.[(snd p', (V.pms, V.t))]){2} V.keys{2} /\
   decrypt V.sk{2} (fst p') V.c{2} = V.pms{2}).
  by apply lossless_guess.
  by apply RCCA_RCCA1_dec_upto.
  by progress; apply RCCA_lossless_dec.
  by apply RCCA1_dec_preserves_abort.
  by apply RCCA_RCCA1_extract_upto.
  by intros _ _; apply lossless_extract.
  intros _; fun; sp; if.
   by rnd; skip; smt.
   by skip; smt.
  wp; case b{1}.
   swap{2} 1; rnd; wp; rnd; skip; progress; try smt.
   rnd; wp; rnd; skip; progress; try smt.

  (* !abort /\ !valid *)  
  call{1} (_:true ==> true).
  apply (lossless_guess RO_KEF (<:RCCA(MS_KEM, A(RO_KEF)).O)).
  fun.
    sp; if => //.
     sp; seq 1 : true => //.
      call (_:true) => //.
       call (_:true).
        if; try rnd; skip; smt.
        call (_:true); first by apply lossless_dec.
       by wp.
      by wp.
   (* lossless RCCA1.O.extract *)      
   by fun; sp; if => //; rnd; skip; smt.
  call{2} (_:true ==> true).
  apply (lossless_guess RCCA1.O RCCA1.O).
  fun.
    sp; if => //.
     sp; seq 1 : true => //.
      by call (_:true); first by apply lossless_dec.
      sp; if => //.
       if => //.
        by wp; rnd; skip; smt.
        by wp; skip; smt.
   (* lossless RCCA1.O.extract *)      
   by fun; sp; if => //; rnd; skip; smt.
  wp; rnd; wp; if{1}.
   rnd; skip; progress; smt.
   rnd{2}; skip; smt.
 qed.

 local lemma Pr_RCCA1_res : forall &m, 
   Pr[RCCA1.main() @ &m : res] <= 1%r / 2%r.
 proof.
  intros &m; bdhoare_deno (_:true) => //. 
  fun.
  rnd; simplify; call (_:true).
   (* lossless RCCA1.O.dec *)
   fun; sp; if => //.
   (* lossless RCCA1.O.extract *)      
   by fun; sp; if => //; rnd; skip; smt.

  wp; rnd; rnd; wp.
  call (_:true).
   (* lossless RCCA1.O.dec *)
   fun; sp; if => //.
   (* lossless RCCA1.O.extract *)      
   by fun; sp; if => //; rnd; skip; smt.

  inline V.init.
  call (_:true); wp; call (_:true); wp; call (_:true).
  by skip; progress; try rewrite Bool.Dbool.mu_def; smt.
 qed.

 local lemma Pr_RCCA_RCCA1 : forall &m,
   Pr[RCCA(KEM(RO_KEF, PMS_KEM), A(RO_KEF)).main() @ &m : res] <=
   1%r / 2%r + Pr[RCCA1.main() @ &m : RCCA1.abort].
 proof.
  intros &m.
  apply (Trans _ (Pr[RCCA1.main() @ &m : res \/ RCCA1.abort])).
  equiv_deno RCCA_RCCA1; smt.  
  rewrite Pr mu_or; smt.
 qed.


 (** RCCA1 -> RCCA2 **)

 op find_ext : skey ->
  (label, (ms * version * hash * ciphertext)) map -> hash -> pms -> label -> bool.

 op find_dec : skey ->
  (hash * (pms * label), ms) map -> version -> ciphertext -> hash -> label -> bool.

 axiom find_ext_spec : forall sk d h pms t,
   find_ext sk d h pms t <=>
   in_dom t d /\
   exists k pv c, d.[t] = Some (k, pv, h, c) /\ decrypt sk pv c = pms.

 axiom find_dec_spec : forall sk m pv c h t,
   find_dec sk m pv c h t <=> in_dom (h, (decrypt sk pv c, t)) m.

 local module RCCA2 = {
  var m : (hash * (pms * label), ms) map
  var d : (label, (ms * version * hash * ciphertext)) map

  module O = {
   fun extract(p:hash, s:pms * label) : ms = {
     var k : ms;
     var pms : pms;
     var t : label;
     (pms, t) = s;
     if (!in_dom (p, (pms, t)) m) {
       if (find_ext V.sk d p pms t) {
         k = let (ms, pv, h, c) = proj d.[t] in ms;
       }
       else k = $Outer_KEM.key;
       m.[(p, (pms, t))] = k;
     }
     else {
       k = proj m.[(p, (pms, t))];
     }
     return k;
   }

   fun dec(p:version * hash, t:label, c:ciphertext) : ms option = {
     var pv : version;
     var h : hash;
     var k : ms;
     var maybe_k : ms option = None;
     if (!mem t V.labels /\ mem p P) { 
       V.labels = add t V.labels;
       (pv, h) = p;
       if (!(V.guess /\ (pv, h) = p' /\ t = V.t /\ V.c = c)) {
         if (find_dec V.sk m pv c h t) {
           k = proj m.[(h, (decrypt V.sk pv c, t))];
         }
         else {
           k = $Outer_KEM.key;
         }
         d.[t] = (k, pv, h, c);
         maybe_k = if (!mem k V.keys) then Some k else None;
       }
     }
     return maybe_k;
   }
  }
  
  module A = A(O, O)

  fun main() : bool = {
    var b, b' : bool;
    var k0, k1 : ms;
    PMS_KEM.init();
    (V.pk, V.sk) = PMS_KEM.keygen();
    V.init();
    m = FMap.Core.empty;
    d = FMap.Core.empty;
    (V.pms, V.c) = PMS_KEM.enc((), V.pk, fst p');
    V.t = A.choose(V.pk);
    k0 = $Outer_KEM.key;
    k1 = $Outer_KEM.key;
    V.guess = true;
    V.keys = add k0 (add k1 V.keys);
    b' = A.guess(V.c, k0);
    return true;
  }
 }.

 local equiv RCCA1_RCCA2_extract : 
   RCCA1.O.extract ~ RCCA2.O.extract :
   ={p, s} /\ 
   ={V.pk, V.sk, V.keys, V.labels, V.pms, V.c, V.guess} /\
   (V.guess{1} => ={V.t}) /\
   (decrypt V.sk (fst p') V.c = V.pms){2} /\ 
   (RCCA1.abort{1} =>
    (exists t, in_dom (snd p', (V.pms, t)) RCCA2.m \/
    (V.guess /\ in_dom V.t RCCA2.d /\
     let (k, pv, h, c) = proj RCCA2.d.[V.t] in
      c <> V.c /\ decrypt V.sk pv c = V.pms)){2}) /\
   (forall t, in_dom t RCCA2.d => mem t V.labels){2} /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} <=>
    (in_dom (h, (pms, t)) RCCA2.m{2} \/
     (in_dom t RCCA2.d{2} /\ 
      let (k, pv, h', c) = proj RCCA2.d{2}.[t] in 
       h = h' /\ decrypt V.sk{2} pv c = pms)))) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     in_dom (h, (pms, t)) RCCA2.m{2} => 
     RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))])) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     !in_dom (h, (pms, t)) RCCA2.m{2} => 
       RCCA1.m{1}.[(h, (pms, t))] = 
       let (k, pv, h', c) = proj RCCA2.d{2}.[t] in Some k))
   ==>
   ={res} /\
   ={V.pk, V.sk, V.keys, V.labels, V.pms, V.c, V.guess} /\
   (V.guess{1} => ={V.t}) /\
   (decrypt V.sk (fst p') V.c = V.pms){2} /\ 
   (RCCA1.abort{1} =>
    (exists t, in_dom (snd p', (V.pms, t)) RCCA2.m \/
    (V.guess /\ in_dom V.t RCCA2.d /\
     let (k, pv, h, c) = proj RCCA2.d.[V.t] in
      c <> V.c /\ decrypt V.sk pv c = V.pms)){2}) /\
   (forall t, in_dom t RCCA2.d => mem t V.labels){2} /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} <=>
    (in_dom (h, (pms, t)) RCCA2.m{2} \/
     (in_dom t RCCA2.d{2} /\ 
      let (k, pv, h', c) = proj RCCA2.d{2}.[t] in 
       h = h' /\ decrypt V.sk{2} pv c = pms)))) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     in_dom (h, (pms, t)) RCCA2.m{2} => 
     RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))])) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     !in_dom (h, (pms, t)) RCCA2.m{2} => 
       RCCA1.m{1}.[(h, (pms, t))] = 
       let (k, pv, h', c) = proj RCCA2.d{2}.[t] in Some k)).
 proof.
  fun.
  sp; if{1}.
   rcondt{2} 1; first by intros &1; skip; intros &2; progress; smt.
   sp; rcondf{2} 1; first by intros &m; skip; progress; smt.
   wp; rnd; skip; progress.
    by smt.
 
    elim H9; clear H9; intros ?.
     cut W : abortL = true by smt; subst.
     by elim H0; intros ? ?; exists t0; smt.
     
     by elim H9; intros ? ?; subst; exists t{2}; smt.

    cut W := H2 h pms0 t0. 
    case (in_dom (h, (pms0, t0)) RCCA1.m{1}); first by smt.
    by intros ?; left; smt.

    elim H9; clear H9; intros ?.
     case (in_dom (h, (pms0, t0)) RCCA2.m{2}).
      by smt.
      intros ?; cut V : (h, (pms0, t0)) = (p, (pms, t)){2} by smt.
      by smt.

    cut W := H2 h pms0 t0; cut V : in_dom (h, (pms0, t0)) RCCA1.m{1}.
     by elim W; intros _ X; apply X; smt.
    by smt.
    
    by cut W := H3 h pms0 t0; smt.    
    by cut W := H2 h pms0 t0; cut X := H4 h pms0 t0; smt.    

   if{2}.
    sp; rcondt{2} 1.
     intros &1; skip; intros &2; progress.
     rewrite find_ext_spec.
     cut W := H2 p{2} pms{2} t{2}; elim W; intros X Y; clear W Y.
     cut V : 
      in_dom t{2} RCCA2.d{2} /\
      let (k, pv, h', c) = proj RCCA2.d{2}.[t{2}] in
       p{2} = h' /\ decrypt V.sk{2} pv c = pms{2} by smt.
     clear H; split; first by smt.

     exists (let (k, pv, h', c) = proj RCCA2.d{2}.[t{2}] in k),
            (let (k, pv, h', c) = proj RCCA2.d{2}.[t{2}] in pv),
            (let (k, pv, h', c) = proj RCCA2.d{2}.[t{2}] in c).
     split; last by smt.
     by cut W : RCCA2.d{2}.[t{2}] <> None by smt; smt.

    wp; skip; progress; try smt.
  
    elim H7; clear H7; intros ?.
     cut W : abortL = true by smt; subst.
     by elim H0; intros ? ?; exists t0; smt.
     
     by exists t{2}; smt.

    cut W := H2 h pms0 t0. 
    by case (in_dom (h, (pms0, t0)) RCCA1.m{1}); smt.

    elim H7; clear H7; intros ?.
     case (in_dom (h, (pms0, t0)) RCCA2.m{2}).
      by smt.
      intros ?; cut V : (h, (pms0, t0)) = (p, (pms, t)){2} by smt.
      by smt.

    cut W := H2 h pms0 t0. 
    by elim W; intros _ X; apply X; smt.

   by wp; skip; progress; smt.
 qed.

 local equiv RCCA1_RCCA2_dec :
   RCCA1.O.dec ~ RCCA2.O.dec : 
   ={p, t, c} /\ 
   ={V.pk, V.sk, V.keys, V.labels, V.pms, V.c, V.guess} /\
   (V.guess{1} => ={V.t}) /\
   (decrypt V.sk (fst p') V.c = V.pms){2} /\ 
   (RCCA1.abort{1} =>
    (exists t, in_dom (snd p', (V.pms, t)) RCCA2.m \/
    (V.guess /\ in_dom V.t RCCA2.d /\
     let (k, pv, h, c) = proj RCCA2.d.[V.t] in
      c <> V.c /\ decrypt V.sk pv c = V.pms)){2}) /\
   (forall t, in_dom t RCCA2.d => mem t V.labels){2} /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} <=>
    (in_dom (h, (pms, t)) RCCA2.m{2} \/
     (in_dom t RCCA2.d{2} /\ 
      let (k, pv, h', c) = proj RCCA2.d{2}.[t] in 
       h = h' /\ decrypt V.sk{2} pv c = pms)))) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     in_dom (h, (pms, t)) RCCA2.m{2} => 
     RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))])) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     !in_dom (h, (pms, t)) RCCA2.m{2} => 
       RCCA1.m{1}.[(h, (pms, t))] = 
       let (k, pv, h', c) = proj RCCA2.d{2}.[t] in Some k))
   ==>
   ={res} /\
   ={V.pk, V.sk, V.keys, V.labels, V.pms, V.c, V.guess} /\
   (V.guess{1} => ={V.t}) /\
   (decrypt V.sk (fst p') V.c = V.pms){2} /\ 
   (RCCA1.abort{1} =>
    (exists t, in_dom (snd p', (V.pms, t)) RCCA2.m \/
    (V.guess /\ in_dom V.t RCCA2.d /\
     let (k, pv, h, c) = proj RCCA2.d.[V.t] in
      c <> V.c /\ decrypt V.sk pv c = V.pms)){2}) /\
   (forall t, in_dom t RCCA2.d => mem t V.labels){2} /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} <=>
    (in_dom (h, (pms, t)) RCCA2.m{2} \/
     (in_dom t RCCA2.d{2} /\ 
      let (k, pv, h', c) = proj RCCA2.d{2}.[t] in 
       h = h' /\ decrypt V.sk{2} pv c = pms)))) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     in_dom (h, (pms, t)) RCCA2.m{2} => 
     RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))])) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     !in_dom (h, (pms, t)) RCCA2.m{2} => 
       RCCA1.m{1}.[(h, (pms, t))] = 
       let (k, pv, h', c) = proj RCCA2.d{2}.[t] in Some k)).
 proof.
  fun.
  wp; sp; if => //.
  inline{1} RCCA1.O.extract.
  seq 3 2 :
   ((pms = decrypt V.sk pv c){1} /\
    (pv{2}, h{2}) = p{2} /\
    mem t{1} V.labels{1} /\
    mem p{1} P /\
    !in_dom t{2} RCCA2.d{2} /\
    (pv{1}, h{1}) = p{1} /\
    maybe_k{1} = None /\
    ={maybe_k, p, t, c, V.pk, V.sk, V.keys, V.labels, V.pms, V.c, V.guess} /\
   (V.guess{1} => ={V.t}) /\
   (decrypt V.sk (fst p') V.c = V.pms){2} /\ 
   (RCCA1.abort{1} =>
    (exists t, in_dom (snd p', (V.pms, t)) RCCA2.m \/
    (V.guess /\ in_dom V.t RCCA2.d /\
     let (k, pv, h, c) = proj RCCA2.d.[V.t] in
      c <> V.c /\ decrypt V.sk pv c = V.pms)){2}) /\
   (forall t, in_dom t RCCA2.d => mem t V.labels){2} /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} <=>
    (in_dom (h, (pms, t)) RCCA2.m{2} \/
     (in_dom t RCCA2.d{2} /\ 
      let (k, pv, h', c) = proj RCCA2.d{2}.[t] in 
       h = h' /\ decrypt V.sk{2} pv c = pms)))) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     in_dom (h, (pms, t)) RCCA2.m{2} => 
     RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))])) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     !in_dom (h, (pms, t)) RCCA2.m{2} => 
       RCCA1.m{1}.[(h, (pms, t))] = 
       let (k, pv, h', c) = proj RCCA2.d{2}.[t] in Some k))).
   sp; wp.
   exists * V.sk{1}, pv{1}, c{1} ; elim *; intros sk pv c.
   call{1} (dec_spec sk pv c); skip; progress; try smt.
 
   sp; if => //; first by smt.
   if{1}.
    if{2}.
     by exfalso; progress; rewrite find_dec_spec; smt.
     wp; rnd; skip; progress.
      by smt.
 
      elim H14; clear H14; intros ?.
       cut X : abortL = true by smt; subst.
       by elim H3; smt.
     
       by exists t{2}; smt.
     
      by smt.

     case (in_dom (h0, (pms0, t0)) RCCA1.m{1}); first by smt.
     intros ?;
     cut Z : 
       (h0, (pms0, t0)) =
       (h{2}, (decrypt V.sk{2} pv{2} c{2}, t{2})) by smt.
     right; split; first by smt.
     elim Z; intros ? [? ?]; subst.
     by rewrite /_.[_] FMap.Core.get_setE; smt.

     elim H14; clear H14; intros ?; first by smt.
     case (t0 = t{2}).
      intros ?; subst; elim H14; clear H14; intros X Y.
      by generalize Y; rewrite /_.[_] FMap.Core.get_setE; smt.
      intros ?; cut L : (in_dom (h0, (pms0, t0)) RCCA1.m{1}); 
        last by smt.
      cut W := H5 h0 pms0 t0.
      cut L : (in_dom t0 RCCA2.d{2} /\
        let (k0, pv0, h', c0) = proj RCCA2.d{2}.[t0] in
        h0 = h' /\ decrypt V.sk{2} pv0 c0 = pms0).
      split; first by smt.
      by generalize H14; rewrite /_.[_] FMap.Core.get_setN; smt.
      rewrite H5; smt.
     
     by smt.
     by case ((h, (decrypt V.sk pv c, t)){2} = (h0, (pms0, t0))); smt.

   (* the same *)
   rcondt{2} 1; first by intros &1; skip; intros &2; progress; smt.
   wp; skip; progress.
    by smt.
  
    elim H10; clear H10; intros ?.
     cut X : abortL = true by smt; subst.
     by elim H3; smt.

     by exists t{2}; smt.
    
    by smt.
    by smt.

    elim H10; clear H10; first by smt.
    case (t0 = t{2}); first by smt.
    intros ? [? ?].
    case ((h, (decrypt V.sk pv c, t)){2} = (h0, (pms0, t0)));
     first by smt.
    intros ?; rewrite H5; right; split; first by smt.
    by generalize H12; rewrite /_.[_] FMap.Core.get_setN; smt.
        
   by smt.
 qed.

 local equiv RCCA1_RCCA2 :
   RCCA1.main ~ RCCA2.main : 
   true ==>
   RCCA1.abort{1} =>
    (exists t, in_dom (snd p', (V.pms, t)) RCCA2.m){2} \/
    (in_dom V.t RCCA2.d /\
     let (k, pv, h, c) = proj RCCA2.d.[V.t] in
      c <> V.c /\ decrypt V.sk pv c = V.pms){2}.
 proof.
  fun.
  rnd{1}.
  call (_:
   ={V.pk, V.sk, V.keys, V.labels, V.pms, V.c, V.guess} /\
   (V.guess{1} => ={V.t}) /\
   (decrypt V.sk (fst p') V.c = V.pms){2} /\ 
   (RCCA1.abort{1} =>
    (exists t, in_dom (snd p', (V.pms, t)) RCCA2.m \/
    (V.guess /\ in_dom V.t RCCA2.d /\
     let (k, pv, h, c) = proj RCCA2.d.[V.t] in
      c <> V.c /\ decrypt V.sk pv c = V.pms)){2}) /\
   (forall t, in_dom t RCCA2.d => mem t V.labels){2} /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} <=>
    (in_dom (h, (pms, t)) RCCA2.m{2} \/
     (in_dom t RCCA2.d{2} /\ 
      let (k, pv, h', c) = proj RCCA2.d{2}.[t] in 
       h = h' /\ decrypt V.sk{2} pv c = pms)))) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     in_dom (h, (pms, t)) RCCA2.m{2} => 
     RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))])) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     !in_dom (h, (pms, t)) RCCA2.m{2} => 
       RCCA1.m{1}.[(h, (pms, t))] = 
       let (k, pv, h', c) = proj RCCA2.d{2}.[t] in Some k))).
   by apply RCCA1_RCCA2_dec.
   by apply RCCA1_RCCA2_extract.
  wp; rnd; rnd; wp.
  call (_:
   ={V.pk, V.sk, V.keys, V.labels, V.pms, V.c, V.guess} /\
   (V.guess{1} => ={V.t}) /\
   (decrypt V.sk (fst p') V.c = V.pms){2} /\ 
   (RCCA1.abort{1} =>
    (exists t, in_dom (snd p', (V.pms, t)) RCCA2.m \/
    (V.guess /\ in_dom V.t RCCA2.d /\
     let (k, pv, h, c) = proj RCCA2.d.[V.t] in
      c <> V.c /\ decrypt V.sk pv c = V.pms)){2}) /\
   (forall t, in_dom t RCCA2.d => mem t V.labels){2} /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} <=>
    (in_dom (h, (pms, t)) RCCA2.m{2} \/
     (in_dom t RCCA2.d{2} /\ 
      let (k, pv, h', c) = proj RCCA2.d{2}.[t] in 
       h = h' /\ decrypt V.sk{2} pv c = pms)))) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     in_dom (h, (pms, t)) RCCA2.m{2} => 
     RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))])) /\
   (forall h pms t, 
    (in_dom (h, (pms, t)) RCCA1.m{1} => 
     !in_dom (h, (pms, t)) RCCA2.m{2} => 
       RCCA1.m{1}.[(h, (pms, t))] = 
       let (k, pv, h', c) = proj RCCA2.d{2}.[t] in Some k))).
  by apply RCCA1_RCCA2_dec.
  by apply RCCA1_RCCA2_extract.
 
  seq 2 2 : (={V.pk, V.sk}); first by eqobs_in.
  exists * V.pk{1}, V.sk{1}; elim *; intros pk sk.
  call (enc_spec_rel sk pk (fst p')).
  inline V.init; wp; skip; progress; try smt.
 qed.

 local lemma Pr_RCCA1_RCCA2 : forall &m,
   Pr[RCCA1.main() @ &m : RCCA1.abort] <=
   Pr[RCCA2.main() @ &m : exists t, in_dom (snd p', (V.pms, t)) RCCA2.m] +  
   Pr[RCCA2.main() @ &m : let (k, pv, h, c) = proj RCCA2.d.[V.t] in
      c <> V.c /\ decrypt V.sk pv c = V.pms].
 proof.
  intros &m.
  apply (Trans _ 
   Pr[RCCA2.main() @ &m : 
    (exists t, in_dom (snd p', (V.pms, t)) RCCA2.m) \/
    let (k, pv, h, c) = proj RCCA2.d.[V.t] in
     c <> V.c /\ decrypt V.sk pv c = V.pms]).
  equiv_deno RCCA1_RCCA2; smt.  
  rewrite Pr mu_or.
  cut X : forall (x y z:real), 0%r <= z => x <= y => x - z <= y by smt.
  apply X; [smt | apply Refl].
 qed.


 (** Conclusion **)
 lemma Conclusion : forall &m,
   exists (B <: OW_PCA.Adversary) (C <: NR_PCA.Adversary),
    Pr[RCCA(KEM(RO_KEF, PMS_KEM), A(RO_KEF)).main() @ &m : res] - 1%r / 2%r <= 
    Pr[NR_PCA.NR_PCA(PMS_KEM, C).main() @ &m : res] +
    Pr[OW_PCA.OW_PCA(PMS_KEM, B).main() @ &m : res].
 proof.
  intros &m.
  admit.
 qed.

end section.
