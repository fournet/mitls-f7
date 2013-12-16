(*
 * Proof of Theorem 2 in the Technical Report
 *
 * Theorem: if the pre-master secret KEM used in the TLS handshake is
 * both One-Way and Non-Randomizable under Plaintext-Checking Attacks,
 * then the master secret KEM, seen as an agile labeled KEM, is
 * Indistinguishable under Replayable Chosen-Ciphertext Attacks in the
 * ROM for the underlying agile KEF.
 *
 * The definition of the master secret KEM includes the countermeasure
 * against padding-oracle attacks (aka Bleichenbecher attacks) used for
 * RSA encryption with PKCS#1 padding: when decryption fails, a value for
 * the master secret is computed anyway using a random pre-master secret.
 *
 *)

require import Bool.
require import Int.
require import Real.
require import Pair.
require import FMap.
require import ISet.
require import RandomOracle.

import Finite.
import FSet.
import OptionGet.

(* Bare minimum *)
prover "Alt-Ergo" "Z3".

lemma eq_except_in_dom (m1 m2:('a, 'b) map) (x y:'a) :
  eq_except m1 m2 x => x <> y => (in_dom y m1 <=> in_dom y m2) 
by [].

lemma eq_except_set (m1 m2:('a, 'b) map) (x y:'a) (z:'b) :
  eq_except m1 m2 x => eq_except m1.[y <- z] m2.[y <- z] x 
by [].

(* TODO: Map this to a RO in the standard library *)
theory Agile_KEF.

  type parameter.
  type secret.
  type key.
  
  module type KEF = {
    fun init() : unit {*}
    fun extract(p:parameter, s:secret) : key
  }.
  
  module type Oracle = {
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
    
  module type KEM = {
    fun init() : unit {*}
    fun keygen() : pkey * skey
    fun enc(p:parameter, pk:pkey, t:label) : key * ciphertext
    fun dec(p:parameter, sk:skey, t:label, c:ciphertext) : key option
  }.

  theory RCCA.
  
    const P : parameter set.
   
    const pp : parameter.
   
    axiom pp_in_P : mem pp P.
  
    op key : key distr.
     
    module type Oracle = {
      fun dec(p:parameter, t:label, c:ciphertext) : key option
    }.
   
    module type Adversary(O:Oracle) = {
      fun choose(pk:pkey) : label
      fun guess(c:ciphertext, k:key) : bool
    }.
  
    module W = {
      var sk : skey
      var keys : key set
      var labels : label set
    }.
    
    module Wrap(KEM:KEM) : Oracle = {  
      fun dec(p:parameter, t:label, c:ciphertext) : key option = {
        var k : key;
        var maybe_k : key option = None;
        if (!mem t W.labels /\ mem p P) { 
          W.labels = add t W.labels;
          maybe_k = KEM.dec(p, W.sk, t, c);
          k = $key;
          maybe_k = if (maybe_k = None) then Some k else maybe_k;
          maybe_k = if (!mem (proj maybe_k) W.keys) then maybe_k else None;  
      }
        return maybe_k;
      }
    }.
    
    module RCCA(KEM:KEM, A:Adversary) = {
      module O = Wrap(KEM)
      module A = A(O)
     
      fun main() : bool = {
        var b, b', valid : bool;
        var k0, k1 : key;
        var c : ciphertext;
        var t : label;
        var pk : pkey;
        KEM.init();
        (pk, W.sk) = KEM.keygen();
        W.keys = FSet.empty;
        W.labels = FSet.empty;
        t = A.choose(pk);
        valid = !mem t W.labels; 
        (k0, c) = KEM.enc(pp, pk, t);
        k1 = $key;
        b = ${0,1};
        W.keys = add k0 (add k1 W.keys);
        b' = A.guess(c, if b then k1 else k0);
        return (b = b' /\ valid);
      }
    }.
  
  end RCCA.
  
  theory PCA.
  
    const P : parameter set.
   
    const pp : parameter.
   
    axiom pp_in_P : mem pp P.
   
    module type Oracle = {
      fun check(p:parameter, k:key, t:label, c:ciphertext) : bool
    }.

    module type OW_Adversary(O:Oracle) = {
      fun choose(pk:pkey) : label
      fun guess(c:ciphertext) : key 
    }.

    module V = { var sk : skey }.
    
    module Wrap(KEM:KEM) : Oracle = {
      fun check(p:parameter, k:key, t:label, c:ciphertext) : bool = {
        var maybe_k : key option;
        maybe_k = KEM.dec(p, V.sk, t, c);
        return (maybe_k = Some k);
      }
    }.
      
    module OW_PCA(KEM:KEM, A:OW_Adversary) = {
      module O = Wrap(KEM)
      module A = A(O)
    
      fun main() : bool = {
        var pk : pkey;
        var t : label;
        var k, k' : key;
        var c : ciphertext;
        KEM.init();
        (pk, V.sk) = KEM.keygen();
        t = A.choose(pk);
        (k, c) = KEM.enc(pp, pk, t);
        k' = A.guess(c);
        return (k = k');
      }
    }.

    module type NR_Adversary(O:Oracle) = {
      fun choose(pk:pkey) : label
      fun guess(c:ciphertext) : label * ciphertext
    }.
   
    module NR_PCA(KEM:KEM, A:NR_Adversary) = {
      module O = Wrap(KEM)
      module A = A(O)
    
      fun main() : bool = {
        var pk : pkey;
        var t, t' : label;
        var k : key;
        var maybe_k : key option;
        var c, c' : ciphertext;
        KEM.init();
        (pk, V.sk) = KEM.keygen();
        t = A.choose(pk);
        (k, c) = KEM.enc(pp, pk, t);
        (t', c') = A.guess(c);
        maybe_k = KEM.dec(pp, V.sk, t', c');
        return (c <> c' /\ maybe_k = Some k);
      }
    }.
  
  end PCA.

end Agile_Labeled_KEM.


type hash.
type version.
type label.
type pms.
type ms.

op key : ms distr.

axiom key_lossless : Distr.weight key = 1%r.

op dpms : pms distr.

axiom dpms_lossless : Distr.weight dpms = 1%r.

(* Shall we treat pv as a label or as a parameter? As a label for now *)
(* Theory for non-agile pre-master secret KEM with protocol version as label *)
clone import Agile_Labeled_KEM as Inner_KEM with 
  type parameter <- unit,
  type label     <- version,
  type key       <- pms.

(* Theory for agile and labeled master-secret KEM *)
clone Agile_Labeled_KEM as Outer_KEM with 
  type parameter  <- version * hash,
  type label      <- label,
  type key        <- ms,
  type pkey       <- Inner_KEM.pkey,
  type skey       <- Inner_KEM.skey,
  type ciphertext <- Inner_KEM.ciphertext,
  op RCCA.key     <- key.

(* Theory for agile KEF, indexed by a hash algorithm identifier *)
clone Agile_KEF as KEF with
  type parameter <- hash,
  type secret    <- pms * label,
  type key       <- ms.

(* Used for the transformation from RCCA0 to RCCA1 *)
clone LazyEager as LE with 
  type from  <- label,
  type to    <- pms,
  op dsample <- lambda (t:label), dpms.

(* TLS master secret KEM *)
module KEM(KEF:KEF.KEF, PMS_KEM:Inner_KEM.KEM) : Outer_KEM.KEM = {
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

  fun dec(p:version * hash, sk:skey, t:label, c:ciphertext) : ms option = {
    var maybe_pms : pms option;
    var pms : pms;
    var ms : ms;
    var pv : version;
    var h : hash;
    (pv, h) = p;
    maybe_pms = PMS_KEM.dec((), sk, pv, c);
    pms = $dpms;
    pms = if maybe_pms = None then pms else proj maybe_pms;
    ms = KEF.extract(h, (pms, t));
    return Some ms;
  }
}.


(* Agile KEF in the ROM *)
module RO_KEF : KEF.KEF = {
  var m : (hash * (pms * label), ms) map
 
  fun init() : unit = {
    m = Core.empty;
  }
 
  fun extract(p:hash, s:pms * label) : ms = {
    if (!in_dom (p, s) m) m.[(p, s)] = $key;
    return proj m.[(p, s)];
  }
}.

lemma lossless_init : islossless RO_KEF.init 
by (fun; wp).

lemma lossless_extract : islossless RO_KEF.extract
by (fun; if => //; rnd; skip; smt).

(* RCCA Adversary in the ROM *)
import Outer_KEM.RCCA.

module type Adversary(O1:KEF.Oracle, O2:Oracle) = {
  fun choose(pk:pkey) : label {* O2.dec O1.extract}
  fun guess(c:ciphertext, k:ms) : bool
}.

section.

  declare module PMS_KEM : Inner_KEM.KEM {RO_KEF, RCCA, PCA.NR_PCA, PCA.OW_PCA, LE.Lazy.RO, LE.Eager.RO}.

  (* Assumptions on the Pre-master secret KEM *)

  (* 
   * REMARK: This can be weakened. It is enough to require that 
   * PMS_KEM.enc and PMS_KEM.dec do not write shared global state
   * (read-only shared state initialized by PMS_KEM.init and 
   * PMS_KEM.keygen is fine).
   *)
  axiom stateless_pms_kem (x y:glob PMS_KEM) : x = y.

  axiom finite_labels : finite univ<:label>.

  axiom finite_pms : finite univ<:pms>.

  (* TODO: maybe move the first 2 operators to PMS_KEM? *)
  op keypair : pkey * skey -> bool.

  op decrypt : skey -> version -> ciphertext -> pms option.

  op same_key : pkey -> version -> version -> ciphertext -> bool.

  (* 
   * REMARK: The axiom previously used only holds for RSA:
   *
   * axiom nosmt dec_injective_pv sk pv1 pv2 c :
   *   decrypt sk pv1 c = decrypt sk pv2 c => pv1 = pv2.
   *
   * For RSA, same_key pk pv1 pv2 c := pv1 = pv2
   * For DH, same_key pk pv1 pv2 c := true
   *)  
  axiom same_key_spec pk sk pv1 pv2 c :
    keypair(pk, sk) =>
    (same_key pk pv1 pv2 c <=> decrypt sk pv1 c = decrypt sk pv2 c).

  (* REMARK: this axiom is not needed
  axiom dec_fail sk pv1 c :
    decrypt sk pv1 c = None => forall pv2, decrypt sk pv2 c = None.
  *)

  axiom keygen_spec_rel :
    equiv [ PMS_KEM.keygen ~ PMS_KEM.keygen : true ==> ={res} /\ keypair res{1} ].

  axiom enc_spec_rel sk pk pv :
    equiv [ PMS_KEM.enc ~ PMS_KEM.enc :
      pk{1} = pk /\ t{1} = pv /\ ={pk, t} /\ keypair(pk, sk) ==>
      ={res} /\ let (k, c) = res{1} in decrypt sk pv c = Some k ].

  axiom dec_spec _sk _pv _c :
    bd_hoare [ PMS_KEM.dec :
      sk = _sk /\ t = _pv /\ c = _c ==> res = decrypt _sk _pv _c ] = 1%r.
  
  (* TLS master secret KEM in the ROM for KEF *)
  local module MS_KEM = KEM(RO_KEF, PMS_KEM).

  (* RCCA adversary *)
  declare module A : Adversary {RO_KEF, PMS_KEM, RCCA, PCA.NR_PCA, PCA.OW_PCA, LE.Lazy.RO, LE.Eager.RO}.

  axiom lossless_choose (O1 <: KEF.Oracle {A}) (O2 <: Oracle {A}) :
   islossless O2.dec => islossless O1.extract => islossless A(O1, O2).choose.

  axiom lossless_guess (O1 <: KEF.Oracle {A}) (O2 <: Oracle {A}) :
    islossless O2.dec => islossless O1.extract => islossless A(O1, O2).guess.

  (*
   * Swap call to PMS_KEM.enc with A.choose in main, so as to be able
   * to abort when the challenge pms is queried to extract
   *)
  local module RCCA0 = {
    module O = {
      fun dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var maybe_pms : pms option;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t W.labels /\ mem p P) { 
          W.labels = add t W.labels;
          (pv, h) = p;
          maybe_pms = decrypt W.sk pv c;
          pms = $dpms;
          pms = if maybe_pms = None then pms else proj maybe_pms;
          k = RO_KEF.extract(h, (pms, t));
          maybe_k = if (!mem k W.keys) then Some k else None;
        }
        return maybe_k;
      }
    }

    module A = A(RO_KEF, O)

    fun main() : bool = {
      var b, b', valid : bool;
      var k0, k1 : ms;
      var c : ciphertext;
      var t : label;
      var pk : pkey;
      var pv : version;
      var pms : pms;
      var h : hash;
      MS_KEM.init();
      (pk, W.sk) = MS_KEM.keygen();
      W.keys = FSet.empty;
      W.labels = FSet.empty;
      (pv, h) = pp;
      (pms, c) = PMS_KEM.enc((), pk, pv);
      t = A.choose(pk);
      valid = !mem t W.labels;
      k0 = RO_KEF.extract(h, (pms, t));
      k1 = $key;
      b = ${0,1};
      W.keys = add k0 (add k1 W.keys);
      b' = A.guess(c, if b then k1 else k0);
      return (b = b' /\ valid);
    }
  }.

  local equiv RCCA_RCCA0_dec :
    RCCA(MS_KEM, A(RO_KEF)).O.dec ~ RCCA0.O.dec : 
    ={p, t, c} /\ ={glob W, glob RO_KEF} ==>
    ={res} /\ ={glob W, glob RO_KEF}.
  proof.
    fun; sp; if => //.
    inline KEM(RO_KEF, PMS_KEM).dec; sp.
    seq 1 0 : (={maybe_k, maybe_pms, pv, h, p, t, c, glob W, glob RO_KEF} /\ 
      maybe_k{1} = None /\
      (maybe_pms = decrypt W.sk pv c){2} /\ (t0 = t){1}).
      exists * sk{1}, pv{1}, c0{1}; elim *; intros sk pv c.
      by call{1} (dec_spec sk pv c).
    wp; rnd{1}; wp.
    call (_: ={glob W, glob RO_KEF}); first by eqobs_in.
    by wp; rnd; skip; progress; smt.
  qed.    

  local equiv RCCA_RCCA0 : 
    RCCA(MS_KEM, A(RO_KEF)).main ~ RCCA0.main : true ==> ={res}.
  proof.
    fun.
    swap{2} [5..6] 1.
    call (_: ={glob W, glob RO_KEF}).
      by apply RCCA_RCCA0_dec.
      by fun; eqobs_in.
    inline KEM(RO_KEF, PMS_KEM).enc.
    wp; rnd; rnd; wp.
    call (_: ={glob W, glob RO_KEF}); first by eqobs_in.
    seq 5 5 : (={t, pk, glob A, glob W, glob RO_KEF} /\ keypair(pk, W.sk){1}).
    call (_: ={glob W, glob RO_KEF}).
      by apply RCCA_RCCA0_dec.
      by fun; eqobs_in.
    inline KEM(RO_KEF, PMS_KEM).init KEM(RO_KEF, PMS_KEM).keygen
           MS_KEM.init RO_KEF.init MS_KEM.keygen.
    by wp; call keygen_spec_rel; wp; call (_:true).
    sp; exists * W.sk{1}, pk0{1}, pv{1}; elim *; intros sk pk pv.
    by wp; call (enc_spec_rel sk pk pv); skip; progress; smt.
  qed.


  (* Distinguisher for transformation from lazy to eagerly sampled fake pms's *)
  local module D(Fake:LE.Types.ARO) : LE.Types.Dist(Fake) = {
    var m : (hash * (pms * label), ms) map

    module O1 = {
      fun extract(p:hash, s:pms * label) : ms = {
        var pms : pms;
        var t : label;
        (pms, t) = s;
        if (!in_dom (p, (pms, t)) m) m.[(p, (pms, t))] = $key;
        return proj m.[(p, (pms, t))];
      }
    }

    module O2 = {
      fun dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var maybe_pms : pms option;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t W.labels /\ mem p P) { 
          W.labels = add t W.labels;
          (pv, h) = p;
          maybe_pms = decrypt W.sk pv c;
          if (maybe_pms = None) {
            pms = Fake.o(t);
            k = O1.extract(h, (pms, t));
          }
          else k = O1.extract(h, (proj maybe_pms, t));
          maybe_k = if (!mem k W.keys) then Some k else None;
        }
        return maybe_k;
      }
    }

    module A = A(O1, O2)

    fun distinguish() : bool = {
      var b, b', valid : bool;
      var k0, k1 : ms;
      var c : ciphertext;
      var t : label;
      var pk : pkey;
      var pv : version;
      var pms : pms;
      var h : hash;
      PMS_KEM.init();
      (pk, W.sk) = MS_KEM.keygen();
      W.keys = FSet.empty;
      W.labels = FSet.empty;
      m = Core.empty;
      (pv, h) = pp;
      (pms, c) = PMS_KEM.enc((), pk, pv);
      t = A.choose(pk);
      valid = !mem t W.labels;
      k0 = O1.extract(h, (pms, t));
      k1 = $key;
      b = ${0,1};
      W.keys = add k0 (add k1 W.keys);
      b' = A.guess(c, if b then k1 else k0);
      return (b = b' /\ valid);
    }
  }.

  (* Here is where the condition !mem t labels in dec is used *)
  local equiv RCCA0_Lazy : 
   RCCA0.main ~ LE.Types.IND(LE.Lazy.RO, D).main : true ==> ={res}.
  proof.
    fun.
    inline LE.Types.IND(LE.Lazy.RO, D).D.distinguish
           MS_KEM.init MS_KEM.keygen RO_KEF.init; wp.
    call (_: 
      ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
      (forall t, in_dom t LE.Lazy.RO.m => mem t W.labels){2}).
    fun.
      sp; if => //; sp; if{2}; wp.
      call (_: 
        ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
        (forall t, in_dom t LE.Lazy.RO.m => mem t W.labels){2}).
      by sp; if => //; try rnd.
      by inline LE.Lazy.RO.o; wp; sp; rnd; skip; progress; smt.
      call (_: 
        ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
        (forall t, in_dom t LE.Lazy.RO.m => mem t W.labels){2}).
      by sp; if => //; try rnd.
      by wp; rnd{1}; skip; progress; smt.
    by fun; sp; if => //; try rnd.
    wp; rnd; rnd.
    call (_: 
      ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
      (forall t, in_dom t LE.Lazy.RO.m => mem t W.labels){2}).
    by sp; if => //; try rnd.
    wp.
    call (_: 
      ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
      (forall t, in_dom t LE.Lazy.RO.m => mem t W.labels){2}).
    fun.
      sp; if => //; sp; if{2}; wp.
      call (_: 
        ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
        (forall t, in_dom t LE.Lazy.RO.m => mem t W.labels){2}).
      by sp; if => //; try rnd.
      by inline LE.Lazy.RO.o; wp; sp; rnd; skip; progress; smt.
      call (_: 
        ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
        (forall t, in_dom t LE.Lazy.RO.m => mem t W.labels){2}).
      by sp; if => //; try rnd.
      by wp; rnd{1}; skip; progress; smt.
    by fun; sp; if => //; try rnd.
    call (_: true); wp; call (_: true); wp; call (_: true); wp.
    by inline LE.Lazy.RO.init; wp; skip; progress; smt.
  qed.


  (* Eager version of RCCA0 *)
  local module RCCA1 = {
    var m : (hash * (pms * label), ms) map
    var fake : (label, pms) map

    module O1 = {
      fun extract(p:hash, s:pms * label) : ms = {
        var pms : pms;
        var t : label;
        (pms, t) = s;
        if (!in_dom (p, (pms, t)) m) m.[(p, (pms, t))] = $key;
        return proj m.[(p, (pms, t))];
      }
    }

    module O2 = {
      fun dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var maybe_pms : pms option;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t W.labels /\ mem p P) { 
          W.labels = add t W.labels;
          (pv, h) = p;
          maybe_pms = decrypt W.sk pv c;
          if (maybe_pms = None) {
            pms = proj fake.[t];
            k = O1.extract(h, (pms, t));
          }
          else k = O1.extract(h, (proj maybe_pms, t));
          maybe_k = if (!mem k W.keys) then Some k else None;
        }
        return maybe_k;
      }
    }

    module A = A(O1, O2)

    fun sample() : unit = {
      var t : label;
      var labels = toFSet univ;
      fake = Core.empty;
      while (labels <> FSet.empty) {
        t = pick labels;
        fake.[t] = $dpms;
        labels = rm t labels;
      }
    }

    fun main() : bool = {
      var b, b', valid : bool;
      var k0, k1 : ms;
      var c : ciphertext;
      var t : label;
      var pk : pkey;
      var pv : version;
      var pms : pms;
      var h : hash;
      sample();
      PMS_KEM.init();
      (pk, W.sk) = MS_KEM.keygen();
      W.keys = FSet.empty;
      W.labels = FSet.empty;
      m = Core.empty;
      (pv, h) = pp;
      (pms, c) = PMS_KEM.enc((), pk, pv);
      t = A.choose(pk);
      valid = !mem t W.labels;
      k0 = O1.extract(h, (pms, t));
      k1 = $key;
      b = ${0,1};
      W.keys = add k0 (add k1 W.keys);
      b' = A.guess(c, if b then k1 else k0);
      return (b = b' /\ valid);
    }
  }.

 local equiv Eager_RCCA1 : 
   LE.Types.IND(LE.Eager.RO, D).main ~ RCCA1.main : true ==> ={res}.
  proof.
    fun.
    inline LE.Types.IND(LE.Eager.RO, D).D.distinguish
           MS_KEM.init MS_KEM.keygen RO_KEF.init; wp.
    call (_: 
      ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}).
    fun.
      sp; if => //; sp; if => //; wp.
      call (_: 
        ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}).
      by sp; if => //; try rnd.
      by inline LE.Eager.RO.o; wp.
      call (_: 
        ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}) => //.
      by sp; if => //; try rnd.
    by fun; sp; if => //; try rnd.
    wp; rnd; rnd.
    call (_: 
      ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}).
    by sp; if => //; try rnd.
    wp.
    call (_: 
      ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}).
    fun.
      sp; if => //; sp; if => //; wp.
      call (_: 
        ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}).
      by sp; if => //; try rnd.
      by inline LE.Eager.RO.o; wp.
      call (_: 
        ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}) => //.
      by sp; if => //; try rnd.
    by fun; sp; if => //; try rnd.
    call (_: true); wp; call (_: true); wp; call (_: true); wp.
    inline LE.Eager.RO.init RCCA1.sample; sp.
    while (work{1} = labels{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}) => //.
    by wp; sp; rnd.
  qed.

  local equiv RCCA0_RCCA1 : RCCA0.main ~ RCCA1.main : true ==> ={res}.
  proof.
    bypr (res{1}) (res{2}) => //.
    intros &1 &2 b.
    apply (eq_trans _ Pr[LE.Types.IND(LE.Lazy.RO, D).main() @ &1: b = res]).
    by equiv_deno RCCA0_Lazy.
    apply (eq_trans _ Pr[LE.Types.IND(LE.Eager.RO, D).main() @ &1: b = res]).
    equiv_deno (LE.eagerRO D _) => //; first by smt.
    by equiv_deno Eager_RCCA1.
  qed.

  local lemma Pr_RCCA0_RCCA1 &m :
    Pr[RCCA0.main() @ &m : res] = Pr[RCCA1.main() @ &m : res].
  proof.
    by equiv_deno RCCA0_RCCA1.
  qed.


  (* 
   * Similar to RCCA1, but the decryption oracle does not query extract when
   * given an invalid ciphertext (i.e. with a randomly generated fake pms)
   *
   * This only makes a difference if the adversary queries extract directly
   * with one of the fake pms's generated internally during decryption in RCCA1.
   *
   *)
  local module RCCA2 = {
    var m : (hash * (pms * label), ms) map
    var fake : (label, pms) map

    module O1 = {
      fun extract(p:hash, s:pms * label) : ms = {
        var pms : pms;
        var t : label;
        (pms, t) = s;
        if (!in_dom (p, (pms, t)) m) m.[(p, (pms, t))] = $key;
        return proj m.[(p, (pms, t))];
      }
    }

    module O2 = {
      fun dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var maybe_pms : pms option;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t W.labels /\ mem p P) { 
          W.labels = add t W.labels;
          (pv, h) = p;
          maybe_pms = decrypt W.sk pv c;
          if (maybe_pms = None) k = $key;
          else k = O1.extract(h, (proj maybe_pms, t));
          maybe_k = if (!mem k W.keys) then Some k else None;
        }
        return maybe_k;
      }
    }

    module A = A(O1, O2)

    fun sample() : unit = {
      var t : label;
      var labels = toFSet univ;
      fake = Core.empty;
      while (labels <> FSet.empty) {
        t = pick labels;
        fake.[t] = $dpms;
        labels = rm t labels;
      }
    }

    fun main() : bool = {
      var b, b', valid : bool;
      var k0, k1 : ms;
      var c : ciphertext;
      var t : label;
      var pk : pkey;
      var pv : version;
      var pms : pms;
      var h : hash;
      sample();
      PMS_KEM.init();
      (pk, W.sk) = MS_KEM.keygen();
      W.keys = FSet.empty;
      W.labels = FSet.empty;
      m = Core.empty;
      (pv, h) = pp;
      (pms, c) = PMS_KEM.enc((), pk, pv);
      t = A.choose(pk);
      valid = !mem t W.labels;
      k0 = O1.extract(h, (pms, t));
      k1 = $key;
      b = ${0,1};
      W.keys = add k0 (add k1 W.keys);
      b' = A.guess(c, if b then k1 else k0);
      return (b = b' /\ valid);
    }
  }.

  local equiv RCCA1_RCCA2_extract :
    RCCA1.O1.extract ~ RCCA2.O1.extract : 
    !(exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m){2} /\
    ={p, s} /\ ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
    (forall t, in_dom t RCCA1.fake){1} /\
    (forall h t, 
     in_dom (h, (proj RCCA1.fake.[t], t)) RCCA1.m => mem t W.labels){1} /\
    forall h pms t, pms <> proj RCCA1.fake{1}.[t] => 
      RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))]
    ==>
    !(exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m){2} =>
      ={res} /\ ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
      (forall t, in_dom t RCCA1.fake){1} /\
      (forall h t, 
       in_dom (h, (proj RCCA1.fake.[t], t)) RCCA1.m => mem t W.labels){1} /\
      forall h pms t, pms <> proj RCCA1.fake{1}.[t] => 
        RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))].
  proof.  
    fun; sp.
    case (pms = proj RCCA2.fake.[t]){2}.
      (* pms = proj RCCA2.fake[t] *)
      if{1}; if{2}.
        rnd; skip; progress.
          by smt.
          cut : (exists h t, 
           in_dom (h, (proj RCCA2.fake{2}.[t], t))
            RCCA2.m{2}.[(p{2}, (proj RCCA2.fake{2}.[t{2}], t{2})) <- mL]).
          exists p{2}, t{2}; smt.
          by smt.
          by rewrite /_.[_] Core.get_setN; smt.
        by rnd{1}; skip; smt.
        by rnd{2}; skip; intros ? ? ?; split; smt.
        by exfalso; smt.
      (* pms <> proj RCCA2.fake[t] *)
      if => //.
        by progress; smt.
        rnd; skip; progress.
          by smt.
          by smt.
          by case ((p, (pms, t)){2} = (h, (pms0, t0))); smt.
        by skip; progress; smt.
  qed.

  local equiv RCCA1_RCCA2_dec :
    RCCA1.O2.dec ~  RCCA2.O2.dec :
    !(exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m){2} /\
    ={p, t, c} /\ ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
    (forall t, in_dom t RCCA1.fake){1} /\
    (forall h t, 
     in_dom (h, (proj RCCA1.fake.[t], t)) RCCA1.m => mem t W.labels){1} /\
    forall h pms t, pms <> proj RCCA1.fake{1}.[t] => 
      RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))]
    ==>
    !(exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m){2} =>
      ={res} /\ ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
      (forall t, in_dom t RCCA1.fake){1} /\
      (forall h t, 
       in_dom (h, (proj RCCA1.fake.[t], t)) RCCA1.m => mem t W.labels){1} /\
      forall h pms t, pms <> proj RCCA1.fake{1}.[t] => 
        RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))].
  proof.  
    fun; sp; if => //.
      sp; if => //.
        inline RCCA1.O1.extract; wp; sp.
        if{1}.
          by rnd; skip; progress; smt.
          by rnd{2}; skip; progress; smt.
      wp; call RCCA1_RCCA2_extract.
      by skip; progress; smt.
  qed.

  local equiv RCCA1_RCCA2 :
    RCCA1.main ~ RCCA2.main : 
    true ==>  
    !(exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m){2} => ={res}.
  proof.
    fun.
    seq 10 10 :
      (!(exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m){2} =>
      ={glob W, glob A, pk, pv, h, pms, c, t, valid} /\ 
      RCCA1.fake{1} = RCCA2.fake{2} /\
      (forall t, in_dom t RCCA1.fake){1} /\
      (forall h t, 
        in_dom (h, (proj RCCA1.fake.[t], t)) RCCA1.m => mem t W.labels){1} /\
      forall h pms t, pms <> proj RCCA1.fake{1}.[t] => 
        RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))]).
    wp; call (_:
     (exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m),
     ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
     (forall t, in_dom t RCCA1.fake){1} /\
     (forall h t, 
       in_dom (h, (proj RCCA1.fake.[t], t)) RCCA1.m =>  mem t W.labels){1} /\
     forall h pms t, pms <> proj RCCA1.fake{1}.[t] => 
       RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))]).
     by apply lossless_choose.
     by apply RCCA1_RCCA2_dec.
     intros &2 ?; fun; sp; if => //.
     wp; sp; inline RCCA1.O1.extract; if.
       by wp; sp; if => //; rnd; skip; smt.
       by wp; sp; if => //; rnd; skip; smt.
     intros &1; fun.
     sp; if; wp; sp => //.
     if.  
       by rnd (lambda x, true); skip; progress; smt.
       inline RCCA2.O1.extract; wp; sp; if => //.
       by rnd (lambda x, true); skip; progress; smt.
     by apply RCCA1_RCCA2_extract.
     by progress; fun; wp; sp; if; try rnd; skip; smt.
     by intros _; fun; sp; if => //; rnd (lambda x, true); skip; progress; smt.

     call (_: ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2}); wp.
     call (_:RCCA1.fake{1} = RCCA2.fake{2}).
     eqobs_in; progress; apply stateless_pms_kem.
     call (_:true); wp.
     call (_:true ==> RCCA1.fake{1} = RCCA2.fake{2} /\
                      forall t, (in_dom t RCCA1.fake){1}).
     fun; sp.
     while (={labels} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
            forall t, (!mem t labels => in_dom t RCCA1.fake){1}).
     by wp; rnd; wp; skip; progress; smt.
     by wp; skip; progress; smt.
     by wp; skip; progress; smt.

     case ((proj RCCA2.fake.[t] = pms){2} \/
           exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m){2}.
     seq 1 1 : (exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m){2}.
     inline RCCA1.O1.extract RCCA2.O1.extract; wp; sp.      
     if{1}; if{2}.
       rnd; skip; progress; elim H0 => ?.
         by exists h{2}, t{2}; smt.
         by smt.
       by rnd{1}; skip; progress; smt.
       rnd{2}; skip; progress; [smt | elim H0 => ?].
         by exists h{2}, t{2}; smt.
         by smt.
       by skip; progress; smt.
     call (_:true, true,
      (exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m){2}).
        by apply lossless_guess.
        by exfalso; smt.
        (* by apply RCCA1_dec_preserves_bad. *)
        progress; fun; sp; if => //.
        wp; sp; inline RCCA1.O1.extract; if.
          by wp; sp; if => //; rnd; skip; smt.
          by wp; sp; if => //; rnd; skip; smt.
        (* by apply RCCA2_dec_preserves_bad. *)
        progress; fun; sp; if => //.
        wp; sp; inline RCCA1.O1.extract; if.
          by rnd (lambda x, true); skip; progress; smt.
          inline RCCA2.O1.extract; wp; sp; if => //.
          by rnd (lambda x, true); skip; progress; smt.
        by exfalso; smt.
        (* by apply RCCA1_extract_preserves_bad. *)
        by progress; fun; wp; sp; if; try rnd; skip; smt.
        (* by apply RCCA2_extract_preserves_bad. *)
        by progress; fun; sp; if => //; rnd (lambda x, true); skip; progress; smt.
     wp; rnd; rnd; inline RCCA1.O1.extract RCCA2.O1.extract; wp; sp.      
     by skip; progress; smt. 

    call (_:
     (exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m),
     ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
     (forall t, in_dom t RCCA1.fake){1} /\
     (forall h t, 
       in_dom (h, (proj RCCA1.fake.[t], t)) RCCA1.m =>  mem t W.labels){1} /\
     forall h pms t, pms <> proj RCCA1.fake{1}.[t] => 
       RCCA1.m{1}.[(h, (pms, t))] = RCCA2.m{2}.[(h, (pms, t))]).
     by apply lossless_guess.
     by apply RCCA1_RCCA2_dec.
     progress; fun; sp; if => //.
     wp; sp; inline RCCA1.O1.extract; if.
       by wp; sp; if => //; rnd; skip; smt.
       by wp; sp; if => //; rnd; skip; smt.
     intros &1; fun.
     sp; if; wp; sp => //.
     if.  
       by rnd (lambda x, true); skip; progress; smt.
       inline RCCA2.O1.extract; wp; sp; if => //.
       by rnd (lambda x, true); skip; progress; smt.
     by apply RCCA1_RCCA2_extract.
     by progress; fun; wp; sp; if; try rnd; skip; smt.
     by progress; fun; sp; if => //; rnd (lambda x, true); skip; progress; smt.
    
     wp; rnd; rnd.
     inline RCCA1.O1.extract RCCA2.O1.extract; wp; sp.      
     if => //; first by progress; smt.
       rnd; skip; progress; [smt | smt | smt | smt | smt | smt | smt | smt | | | ].   
         cut X : !(exists h t, in_dom 
           (h, (proj RCCA2.fake{2}.[t], t)) RCCA2.m{2}) by smt.
         generalize H; rewrite X => /=; progress.
         by smt.
         cut X : !(exists h t, in_dom 
           (h, (proj RCCA2.fake{2}.[t], t)) RCCA2.m{2}) by smt.
         generalize H; rewrite X => /=; progress.
         case ((h0, (pms1, t1)) = (h, (pms, t)){2}) => ?; first by smt.
         by cut V := H14 h0 pms1 t1; smt.
         cut X : !(exists h t, in_dom 
           (h, (proj RCCA2.fake{2}.[t], t)) RCCA2.m{2}) by smt.
         generalize H; rewrite X => /=; progress.
         by smt.
      skip; progress; [smt | smt | smt | smt | smt | smt | smt | smt | smt | smt | ].          cut X : !(exists h t, in_dom 
           (h, (proj RCCA2.fake{2}.[t], t)) RCCA2.m{2}) by smt.
         generalize H; rewrite X => /=; progress.
         generalize H9; rewrite H10 => /=; progress.
  qed. 

  local lemma Pr_RCCA1_RCCA2 &m :
    Pr[RCCA1.main() @ &m : res] <=
    Pr[RCCA2.main() @ &m : res] +
    Pr[RCCA2.main() @ &m : exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m].
  proof.
    apply (Trans _ 
     Pr[RCCA2.main() @ &m : res \/ 
      exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m]).
    by equiv_deno RCCA1_RCCA2; smt.  
    by rewrite Pr mu_or; smt.    
  qed.


  (* Maximum number of queries to KEF extract oracle *)
  (* TODO: enforce this in RCCA *)
  const qKEF : int.

  axiom qKEF_pos : 0 < qKEF.

  (* Assuming that fake pms's are uniformly random to have a readable bound *)
  axiom dpms_uniform pms : Distr.mu_x dpms pms = 1%r / (card (toFSet univ<:pms>))%r.

  local lemma Pr_RCCA2 &m :
    Pr[RCCA2.main() @ &m : exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m] <=
    qKEF%r / (card (toFSet univ<:pms>))%r.
  proof.
    bdhoare_deno 
      (_:true ==> exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m) => //;
    last by smt.
    fun; swap 14; inline RCCA2.sample.
    (* Too complicated to prove, but evident at this point:
     *
     * dom(m) = { (h_1, pms_1, t_1), (h_2, pms_2, t_2) ... (h_q, pms_q, t_q) }
     * q <= q_KEF
     * 
     * Pr[exists h t, (h, fake[t], t) in dom(m)] <= 
     * sum_{t \in labels} sum_{i=1..q} Pr[fake[t] = pms_i /\ t = t_i] <=
     * sum_{i=1..q} Pr[fake[t_i] = pms_i] = q / |pms| <= q_KEF / |pms|
     *)
    admit.
  qed.

  (* Global variables in RCCA3 and RCCA4 *)
  local module V = {
    var pk : pkey
    var sk : skey
    var keys : ms set
    var labels : label set
    var guess : bool
    var t : label
    var c : ciphertext 
    var pms : pms
  
    fun init() : unit = {
      keys = FSet.empty;
      labels = FSet.empty;
      guess = false;
      t = pick FSet.empty;
      c = pick FSet.empty;
      pms = pick FSet.empty;
    }
  }.

  (*
   * This game "aborts" when the simulation fails, but still uses the PMS KEM
   * secret key to detect when to abort and implement the simulation.
   * However, all uses of the secret key for simulation could be implemented
   * using a plaintext-checking oracle instead.
   *)
  local module RCCA3 = {
    var m : (hash * (pms * label), ms) map
    var abort : bool
  
    module O1 = {
      fun extract(p:hash, s:pms * label) : ms = {
        var pms : pms;
        var t : label;
        (pms, t) = s;
        abort = abort \/ (p = snd pp /\ pms = V.pms);
        if (!in_dom (p, (pms, t)) m) m.[(p, (pms, t))] = $key;
        return proj m.[(p, (pms, t))];
      }
    }
  
    module O2 = {
      fun dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var maybe_pms : pms option;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t V.labels /\ mem p P) { 
          V.labels = add t V.labels;
          (pv, h) = p;
          maybe_pms = decrypt V.sk pv c;
          abort = abort \/ 
           (V.guess /\ maybe_pms <> None /\ proj maybe_pms = V.pms /\ t = V.t /\ c <> V.c);
          if (!(V.guess /\ same_key V.pk (fst pp) pv c /\ h = snd pp /\ t = V.t /\ c = V.c)) {
            if (maybe_pms = None) k = $key;
            else {
              pms = proj maybe_pms;
              if (!in_dom (h, (pms, t)) m) m.[(h, (pms, t))] = $key;
              k = proj m.[(h, (pms, t))];
            }
            maybe_k = if (!mem k V.keys) then Some k else None;
          }
        }
        return maybe_k;
      }
    }
   
   module A = A(O1, O2)
  
    fun main() : bool = {
     var b, b', valid : bool;
     var k0, k1 : ms;
     PMS_KEM.init();
     (V.pk, V.sk) = PMS_KEM.keygen();
     V.init();
     m = Core.empty;
     abort = false;
     (V.pms, V.c) = PMS_KEM.enc((), V.pk, fst pp);
     V.t = A.choose(V.pk);
     valid = !mem V.t V.labels;
     k0 = $key;
     k1 = $key;
     V.keys = add k0 (add k1 V.keys);
     V.guess = true;
     b' = A.guess(V.c, k0);
     b = ${0,1};
     return (b = b' /\ valid);
   }
  }.
  
  (** RCCA2 -> RCCA3 **)
  local lemma RCCA2_lossless_extract : islossless RCCA2.O1.extract.
  proof.
    by fun; sp; if => //; rnd; skip; progress; smt.
  qed.

  local lemma RCCA2_lossless_dec : islossless RCCA2.O2.dec.
  proof.
    fun.
    sp; if => //.
    inline KEM(RO_KEF, PMS_KEM).dec; wp; sp.
    if => //.
      by rnd; skip; smt.    
      by call (_:true ==> true) => //; apply RCCA2_lossless_extract.
  qed.

  local lemma RCCA3_lossless_extract : islossless RCCA3.O1.extract.
  proof.
    by fun; sp; if => //; rnd; skip; progress; smt.
  qed.

  local lemma RCCA3_lossless_dec : islossless RCCA3.O2.dec.
  proof.
    fun.
    sp; if => //.
    sp; if => //.
    if => //; wp.
      by rnd; skip; smt.
      by sp; if; try rnd; skip; smt.
  qed.

  local lemma RCCA3_dec_preserves_abort : 
    bd_hoare [ RCCA3.O2.dec : RCCA3.abort ==> RCCA3.abort ] = 1%r.
  proof.
    fun.
    sp; if => //.
    sp; if => //.
    if => //.
      by wp; rnd; skip; smt.  
    sp; if => //; wp; try rnd; skip; smt.
  qed.

  local equiv RCCA2_RCCA3_extract_guess :
    RCCA2.O1.extract ~ RCCA3.O1.extract :
    !RCCA3.abort{2} /\
    ={p, s} /\
    keypair(V.pk, V.sk){2} /\
    V.guess{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    eq_except RCCA2.m{1} RCCA3.m{2} (snd pp, (V.pms, V.t)){2} /\
    in_dom (snd pp, (V.pms, V.t)){2} RCCA2.m{1} /\
    mem (proj RCCA2.m{1}.[(snd pp, (V.pms, V.t))]){2} V.keys{2} /\
    decrypt V.sk{2} (fst pp) V.c{2} = Some V.pms{2}
    ==>
    !RCCA3.abort{2} =>
      ={res} /\
      keypair(V.pk, V.sk){2} /\
      V.guess{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      eq_except RCCA2.m{1} RCCA3.m{2} (snd pp, (V.pms, V.t)){2} /\
      in_dom (snd pp, (V.pms, V.t)){2} RCCA2.m{1} /\
      mem (proj RCCA2.m{1}.[(snd pp, (V.pms, V.t))]){2} V.keys{2} /\
      decrypt V.sk{2} (fst pp) V.c{2} = Some V.pms{2}.
  proof.
    fun.
    sp; case RCCA3.abort{2}.
      (* aborts *)
      if{1}; if{2}.
        by rnd; skip; smt.
        by rnd{1}; skip; smt.
        by rnd{2}; skip; smt.
        by skip; smt.     
      (* doesn't abort *)
      if; first by smt.
        by wp; rnd; skip; progress; smt.    
        by skip; progress; smt.
  qed.
  
  local equiv RCCA2_RCCA3_dec_guess :
    RCCA2.O2.dec ~ RCCA3.O2.dec :
    !RCCA3.abort{2} /\
    ={p, t, c} /\
    keypair(V.pk, V.sk){2} /\
    V.guess{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    eq_except RCCA2.m{1} RCCA3.m{2} (snd pp, (V.pms, V.t)){2} /\
    in_dom (snd pp, (V.pms, V.t)){2} RCCA2.m{1} /\
    mem (proj RCCA2.m{1}.[(snd pp, (V.pms, V.t))]){2} V.keys{2} /\
    decrypt V.sk{2} (fst pp) V.c{2} = Some V.pms{2}
    ==>
    !RCCA3.abort{2} =>
      ={res} /\
      keypair(V.pk, V.sk){2} /\
      V.guess{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      eq_except RCCA2.m{1} RCCA3.m{2} (snd pp, (V.pms, V.t)){2} /\
      in_dom (snd pp, (V.pms, V.t)){2} RCCA2.m{1} /\
      mem (proj RCCA2.m{1}.[(snd pp, (V.pms, V.t))]){2} V.keys{2} /\
      decrypt V.sk{2} (fst pp) V.c{2} = Some V.pms{2}.
  proof.
    fun.
    sp; if => //.
    wp; sp; case RCCA3.abort{2}.
      (* aborts *)
      if{2}.
       if{1}; if{2}.
         by wp; rnd.
         sp; if{2}; wp; try rnd; try rnd{1}; skip; progress; smt.
   
         call{1} (_:true ==> true); first by apply RCCA2_lossless_extract.
         by wp; rnd{2}; skip; smt.

         call{1} (_:true ==> true); first by apply RCCA2_lossless_extract.
         sp; if{2}; wp; try rnd{2}; skip; progress; smt.
         
         if{1}.
           by rnd{1}; skip; smt.
           call{1} (_:true ==> true); first by apply RCCA2_lossless_extract.
           by skip; smt.    
      (* doesn't abort *)
      inline{1} RCCA2.O1.extract.
      if{2}.
        if => //; first by wp; rnd; skip.
        wp; sp; if.
          progress.
          by smt.
          cut W : (exists pms, decrypt V.sk pv c = Some pms){2} by smt.
          by cut V := same_key_spec V.pk{2} V.sk{2} (fst pp) pv{2} c{2}; smt.
          by rnd; skip; progress; smt.    
        skip; progress.
        cut W := same_key_spec V.pk{2} V.sk{2} (fst pp) pv{2} c{2}.
        cut X : (exists pms, decrypt V.sk pv c = Some pms){2} by smt.
        by generalize H2; rewrite eq_except_def; smt.

    if{1}; wp; sp.
      by exfalso; smt.
      if{1}.
        by rnd{1}; skip; progress;
        cut W := same_key_spec V.pk{2} V.sk{2} (fst pp) pv{2} V.c{2}; smt.
        by skip; progress;
        cut W := same_key_spec V.pk{2} V.sk{2} (fst pp) pv{2} V.c{2}; smt.
  qed.
  
  local equiv RCCA2_RCCA3_extract_choose :
    RCCA2.O1.extract ~ RCCA3.O1.extract :
    !RCCA3.abort{2} /\
    ={p, s} /\
    keypair(V.pk, V.sk){2} /\ 
    !V.guess{2} /\
    RCCA2.m{1} = RCCA3.m{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    decrypt V.sk{2} (fst pp) V.c{2} = Some V.pms{2} /\
    (forall t,
     in_dom (snd pp, (V.pms, t)) RCCA3.m => 
     RCCA3.abort \/ mem t V.labels){2}
    ==>
    !RCCA3.abort{2} =>
      ={res} /\ 
      keypair(V.pk, V.sk){2} /\
      !V.guess{2} /\
      RCCA2.m{1} = RCCA3.m{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      decrypt V.sk{2} (fst pp) V.c{2} = Some V.pms{2} /\
      (forall t,
       in_dom (snd pp, (V.pms, t)) RCCA3.m => 
       RCCA3.abort \/ mem t V.labels){2}.
  proof.
    fun.
    sp; case RCCA3.abort{2}.
      by if{1}; if{2}; try rnd{1}; try rnd{2}; skip; smt.
      if => //.
        by rnd; skip; smt. 
        by skip; smt.
  qed.
  
  local equiv RCCA2_RCCA3_dec_choose :
    RCCA2.O2.dec ~ RCCA3.O2.dec :
    !RCCA3.abort{2} /\
    ={p, t, c} /\ 
    keypair(V.pk, V.sk){2} /\
    !V.guess{2} /\
    RCCA2.m{1} = RCCA3.m{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){2} /\
    (forall t,
     in_dom (snd pp, (V.pms, t)) RCCA3.m => 
     RCCA3.abort \/ mem t V.labels){2}
    ==>
    !RCCA3.abort{2} =>
      ={res} /\ 
      keypair(V.pk, V.sk){2} /\
      !V.guess{2} /\
      RCCA2.m{1} = RCCA3.m{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      (decrypt V.sk (fst pp) V.c = Some V.pms){2} /\
      (forall t,
       in_dom (snd pp, (V.pms, t)) RCCA3.m => 
       RCCA3.abort \/ mem t V.labels){2}.
  proof.
    fun.
    sp; if => //.
    inline{1} RCCA2.O1.extract; wp; sp.
    if{2}; last by exfalso; smt.
    if => //.
      by wp; rnd; skip; progress; smt.
      sp; if => //.
        by wp; rnd; skip; progress; smt.
        by wp; skip; progress; smt.
  qed.

  local equiv RCCA2_RCCA3 :
    RCCA2.main ~ RCCA3.main : true ==> !RCCA3.abort{2} => ={res}.
  proof.
    fun.
    swap{1} 13 -3; swap{2} 14 -6.
    seq 10 8 : 
     (={b} /\ pms{1} = V.pms{2} /\ c{1} = V.c{2} /\ (pv, h){1} = pp /\
      (!RCCA3.abort{2} =>
       ={glob A} /\ t{1} = V.t{2} /\ RCCA2.m{1} = RCCA3.m{2} /\
       keypair(V.pk, V.sk){2} /\
       W.sk{1} = V.sk{2} /\ W.keys{1} = V.keys{2} /\ W.labels{1} = V.labels{2} /\
       (decrypt V.sk (fst pp) V.c = Some V.pms){2} /\
       (forall t, in_dom (snd pp, (V.pms, t)) RCCA3.m => mem t V.labels){2})).
      rnd; simplify.
      call (_:RCCA3.abort,
        keypair(V.pk, V.sk){2} /\
        !V.guess{2} /\ RCCA2.m{1} = RCCA3.m{2} /\
        W.sk{1} = V.sk{2} /\ W.keys{1} = V.keys{2} /\ W.labels{1} = V.labels{2} /\
        (decrypt V.sk (fst pp) V.c = Some V.pms){2} /\
        (forall t, in_dom (snd pp, (V.pms, t)) RCCA3.m => 
           RCCA3.abort \/ mem t V.labels){2}).
      by apply lossless_choose.
      by apply RCCA2_RCCA3_dec_choose.
      by progress; apply RCCA2_lossless_dec.
      by apply RCCA3_dec_preserves_abort.
      by apply RCCA2_RCCA3_extract_choose.
      by progress; apply RCCA2_lossless_extract.
      by progress; fun; sp; if; try rnd; skip; smt. 
      seq 3 2 : (pk{1} = V.pk{2} /\ W.sk{1} = V.sk{2} /\ keypair(V.pk, V.sk){2}).
        inline MS_KEM.init MS_KEM.keygen; wp.
        call keygen_spec_rel; wp; call (_:true).
        (* RCCA2.sample lossless *)
        call{1} (_:true ==> true) => //.
          fun; sp; while true (card labels).
          intros _; wp; rnd; wp; skip; smt.
          skip; progress; smt.
        inline V.init; sp; exists * V.sk{2}, V.pk{2}; elim *; intros sk pk.
        by call (enc_spec_rel sk pk (fst pp)); skip; progress; smt.

      inline RCCA2.O1.extract; wp; sp.
      case RCCA3.abort{2}.
        (* abort *)
        call (_:RCCA3.abort, RCCA3.abort{2}).
          by apply lossless_guess.
          by exfalso; smt.
          by progress; apply RCCA2_lossless_dec.
          by apply RCCA3_dec_preserves_abort.
          by exfalso; smt.
          by progress; apply RCCA2_lossless_extract.
          by progress; fun; sp; if; try rnd; skip; smt.
        wp; rnd; wp; if{1}.
          by rnd; skip; smt.
          by rnd{2}; skip; smt.
        (* !abort *)
        case valid{1}.
          (* valid *)
          (* REMARK: here is where the validity condition is used *)
          rcondt{1} 1; first by intros _; skip; smt.
          call (_:RCCA3.abort,
           keypair(V.pk, V.sk){2} /\
           V.guess{2} /\ 
           W.sk{1} = V.sk{2} /\ W.keys{1} = V.keys{2} /\ W.labels{1} = V.labels{2} /\
           eq_except RCCA2.m{1} RCCA3.m{2} (snd pp, (V.pms, V.t)){2} /\
           in_dom (snd pp, (V.pms, V.t)){2} RCCA2.m{1} /\
           mem (proj RCCA2.m{1}.[(snd pp, (V.pms, V.t))]){2} V.keys{2} /\
           decrypt V.sk{2} (fst pp) V.c{2} = Some V.pms{2}).
          by apply lossless_guess.
          by apply RCCA2_RCCA3_dec_guess.
          by progress; apply RCCA2_lossless_dec.
          by apply RCCA3_dec_preserves_abort.
          by apply RCCA2_RCCA3_extract_guess.
          by progress; apply RCCA2_lossless_extract.
          by intros _; fun; sp; if; try rnd; skip; smt.
          wp; case b{1}.
            by swap{2} 1; rnd; wp; rnd; skip; progress; smt.
            by rnd; wp; rnd; skip; progress; smt.
   
          (* !abort /\ !valid *)  
          call{1} (_:true ==> true).
            apply (lossless_guess RCCA2.O1 RCCA2.O2).
              by apply RCCA2_lossless_dec.
              by apply RCCA2_lossless_extract.
          call{2} (_:true ==> true).
            apply (lossless_guess RCCA3.O1 RCCA3.O2).
              by apply RCCA3_lossless_dec.
              by apply RCCA3_lossless_extract.
      wp; rnd; wp; if{1}.
        by rnd; skip; progress; smt.
        by rnd{2}; skip; smt.
  qed.
  
  local lemma Pr_RCCA3_res &m : Pr[RCCA3.main() @ &m : res] <= 1%r / 2%r.
  proof.
    bdhoare_deno (_:true) => //. 
    fun; rnd; simplify; call (_:true) => //.  
    wp; rnd; rnd; wp; call (_:true) => //.
    inline V.init; call (_:true); wp; call (_:true); wp; call (_:true).
    by skip; progress; try rewrite Bool.Dbool.mu_def; smt.
  qed.
  
  local lemma Pr_RCCA_RCCA2 &m :
    Pr[RCCA(KEM(RO_KEF, PMS_KEM), A(RO_KEF)).main() @ &m : res] <=
    Pr[RCCA2.main() @ &m : res] +
    Pr[RCCA2.main() @ &m : exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m].
  proof.
   apply (Trans _ Pr[RCCA0.main() @ &m : res]).
   equiv_deno RCCA_RCCA0 => //.
   rewrite (Pr_RCCA0_RCCA1 &m).
   apply (Trans _   
    (Pr[RCCA2.main() @ &m : res] +
     Pr[RCCA2.main() @ &m : exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m])).
   apply (Pr_RCCA1_RCCA2 &m).
   smt.    
  qed.

  local lemma Pr_RCCA2_RCCA3 &m :
    Pr[RCCA2.main() @ &m : res] <= 1%r / 2%r + Pr[RCCA3.main() @ &m : RCCA3.abort].
  proof.
   apply (Trans _ Pr[RCCA3.main() @ &m : res \/ RCCA3.abort]).
     by equiv_deno RCCA2_RCCA3; smt.  
     by rewrite Pr mu_or; smt.
  qed.

  local lemma Pr_RCCA_RCCA3 &m :
    Pr[RCCA(KEM(RO_KEF, PMS_KEM), A(RO_KEF)).main() @ &m : res] <=
    1%r / 2%r +
    Pr[RCCA2.main() @ &m : exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m] +
    Pr[RCCA3.main() @ &m : RCCA3.abort].
  proof.
    apply (Trans _ 
     (Pr[RCCA2.main() @ &m : res] +
      Pr[RCCA2.main() @ &m : exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m])).
    apply (Pr_RCCA_RCCA2 &m).
    apply (Trans _
      (1%r / 2%r + Pr[RCCA3.main() @ &m : RCCA3.abort] +
      Pr[RCCA2.main() @ &m : exists h t, in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m])).
    by apply addleM => //; [apply (Pr_RCCA2_RCCA3 &m) | smt].
    by smt.
  qed.
  
  (** RCCA3 -> RCCA4 **)

  (*
   * This game used two maps m and d to implement the simulation for
   * the RCCA adversary A. If the simulation fails and the previous
   * game aborts, then either the pms used to compute the challenge ciphertext
   * can be obtained from map m using the plaintext-checking oracle, or else
   * a randomization of the challenge ciphertext can be obtained by a direct
   * lookup in d.
   *)  
  local module RCCA4 = {
    var m : (hash * (pms * label), ms) map
    var d : (label, (ms * version * hash * ciphertext)) map
   
    module O1 = {
      fun extract(p:hash, s:pms * label) : ms = {
        var k : ms;
        var pms : pms;
        var t : label;
        (pms, t) = s;
        if (!in_dom (p, (pms, t)) m) {
          if (in_dom t d /\ 
              let (ms, pv, h, c) = proj d.[t] in 
                p = h /\ decrypt V.sk pv c = Some pms) {
            k = let (ms, pv, h, c) = proj d.[t] in ms;
          }
          else k = $key;
          m.[(p, (pms, t))] = k;
        }
        else k = proj m.[(p, (pms, t))];
        return k;
      }
    }
   
    module O2 = {
      fun dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t V.labels /\ mem p P) { 
          V.labels = add t V.labels;
          (pv, h) = p;
          if (!(V.guess /\ same_key V.pk (fst pp) pv c /\ h = snd pp /\ t = V.t /\ V.c = c)) {
            if (decrypt V.sk pv c <> None /\ 
                in_dom (h, (proj (decrypt V.sk pv c), t)) m) {
              k = proj m.[(h, (proj (decrypt V.sk pv c), t))];
            }
            else k = $key;
            d.[t] = (k, pv, h, c);
            maybe_k = if (!mem k V.keys) then Some k else None;
          }
        }
        return maybe_k;
      }
    }
    
    module A = A(O1, O2)
   
    fun main() : bool = {
      var b, b' : bool;
      var k0, k1 : ms;
      PMS_KEM.init();
      (V.pk, V.sk) = PMS_KEM.keygen();
      V.init();
      m = Core.empty;
      d = Core.empty;
      (V.pms, V.c) = PMS_KEM.enc((), V.pk, fst pp);
      V.t = A.choose(V.pk);
      k0 = $key;
      k1 = $key;
      V.guess = true;
      V.keys = add k0 (add k1 V.keys);
      b' = A.guess(V.c, k0);
      return true;
    }
  }.
  
  local equiv RCCA3_RCCA4_extract : 
    RCCA3.O1.extract ~ RCCA4.O1.extract :
    ={p, s} /\ 
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){2} /\ 
    (RCCA3.abort{1} =>
     (exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m) \/
     (V.guess /\ in_dom V.t RCCA4.d /\
      let (k, pv, h, c) = proj RCCA4.d.[V.t] in
       c <> V.c /\ decrypt V.sk pv c = Some V.pms)){2} /\
    (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} <=>
     (in_dom (h, (pms, t)) RCCA4.m{2} \/
      (in_dom t RCCA4.d{2} /\ 
       let (k, pv, h', c) = proj RCCA4.d{2}.[t] in 
        h = h' /\ decrypt V.sk{2} pv c = Some pms)))) /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} => 
      in_dom (h, (pms, t)) RCCA4.m{2} => 
      RCCA3.m{1}.[(h, (pms, t))] = RCCA4.m{2}.[(h, (pms, t))])) /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} => 
      !in_dom (h, (pms, t)) RCCA4.m{2} => 
        RCCA3.m{1}.[(h, (pms, t))] = 
        let (k, pv, h', c) = proj RCCA4.d{2}.[t] in Some k))
    ==>
    ={res} /\
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){2} /\ 
    (RCCA3.abort{1} =>
     (exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m) \/
     (V.guess /\ in_dom V.t RCCA4.d /\
      let (k, pv, h, c) = proj RCCA4.d.[V.t] in
       c <> V.c /\ decrypt V.sk pv c = Some V.pms)){2} /\
    (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} <=>
     (in_dom (h, (pms, t)) RCCA4.m{2} \/
      (in_dom t RCCA4.d{2} /\ 
       let (k, pv, h', c) = proj RCCA4.d{2}.[t] in 
        h = h' /\ decrypt V.sk{2} pv c = Some pms)))) /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} => 
      in_dom (h, (pms, t)) RCCA4.m{2} => 
      RCCA3.m{1}.[(h, (pms, t))] = RCCA4.m{2}.[(h, (pms, t))])) /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} => 
      !in_dom (h, (pms, t)) RCCA4.m{2} => 
        RCCA3.m{1}.[(h, (pms, t))] = 
        let (k, pv, h', c) = proj RCCA4.d{2}.[t] in Some k)).
  proof.
    fun.
    sp; if{1}.
      rcondt{2} 1; first by intros &1; skip; intros &2; progress; smt.
      sp; rcondf{2} 1.
        intros &1; skip; intros &2; progress.
        by cut W := H2 p{2} pms{2} t{2}; smt.   
      wp; rnd; skip; progress.
        by smt.   
        elim H9; clear H9; intros ?.
          cut W : abortL = true by smt; subst.
          elim H0; last by smt.
          by intros [t0 ?]; left; exists t0; smt.
          by left; exists t{2}; smt.
        cut W := H2 h pms0 t0. 
        case (in_dom (h, (pms0, t0)) RCCA3.m{1}) => ?; first by smt.
        by cut : (h, (pms0, t0)) = (p, (pms, t)){2}; smt.
        elim H9; clear H9; intros ?.
          by case (in_dom (h, (pms0, t0)) RCCA4.m{2}); smt.
          cut W := H2 h pms0 t0.
          cut V : in_dom (h, (pms0, t0)) RCCA3.m{1}.
          by elim W; intros _ X; apply X; smt.
        by smt.
        by cut W := H3 h pms0 t0; smt.    
        by cut W := H2 h pms0 t0; cut X := H4 h pms0 t0; smt.
       
     if{2}.
       sp; rcondt{2} 1; first by intros &1; skip; intros &2; progress; smt.
       wp; skip; progress.
         by smt.
         elim H7; clear H7; intros ?.
           cut W : abortL = true by smt; subst.
           elim H0; last by smt.
           by intros [t0 ?]; left; exists t0; smt.
           by left; exists t{2}; smt.
         by cut W := H2 h pms0 t0; smt. 
         elim H7; clear H7; intros ?.
         case (in_dom (h, (pms0, t0)) RCCA4.m{2}); first by smt.
         by intros ?; cut V : (h, (pms0, t0)) = (p, (pms, t)){2}; smt.
         cut W := H2 h pms0 t0.
         by elim W; intros _ X; apply X; smt.
         by smt.
         by smt.
      by wp; skip; progress; smt.
  qed.
  
  local equiv RCCA3_RCCA4_dec :
    RCCA3.O2.dec ~ RCCA4.O2.dec : 
    ={p, t, c} /\ 
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){2} /\ 
    (RCCA3.abort{1} =>
     (exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m) \/
     (V.guess /\ in_dom V.t RCCA4.d /\
      let (k, pv, h, c) = proj RCCA4.d.[V.t] in
       c <> V.c /\ decrypt V.sk pv c = Some V.pms)){2} /\
    (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} <=>
     (in_dom (h, (pms, t)) RCCA4.m{2} \/
      (in_dom t RCCA4.d{2} /\ 
       let (k, pv, h', c) = proj RCCA4.d{2}.[t] in 
        h = h' /\ decrypt V.sk{2} pv c = Some pms)))) /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} => 
      in_dom (h, (pms, t)) RCCA4.m{2} => 
      RCCA3.m{1}.[(h, (pms, t))] = RCCA4.m{2}.[(h, (pms, t))])) /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} => 
      !in_dom (h, (pms, t)) RCCA4.m{2} => 
        RCCA3.m{1}.[(h, (pms, t))] = 
        let (k, pv, h', c) = proj RCCA4.d{2}.[t] in Some k))
    ==>
    ={res} /\
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){2} /\ 
    (RCCA3.abort{1} =>
     (exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m) \/
     (V.guess /\ in_dom V.t RCCA4.d /\
      let (k, pv, h, c) = proj RCCA4.d.[V.t] in
       c <> V.c /\ decrypt V.sk pv c = Some V.pms)){2} /\
    (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} <=>
     (in_dom (h, (pms, t)) RCCA4.m{2} \/
      (in_dom t RCCA4.d{2} /\ 
       let (k, pv, h', c) = proj RCCA4.d{2}.[t] in 
        h = h' /\ decrypt V.sk{2} pv c = Some pms)))) /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} => 
      in_dom (h, (pms, t)) RCCA4.m{2} => 
      RCCA3.m{1}.[(h, (pms, t))] = RCCA4.m{2}.[(h, (pms, t))])) /\
    (forall h pms t, 
     (in_dom (h, (pms, t)) RCCA3.m{1} => 
      !in_dom (h, (pms, t)) RCCA4.m{2} => 
        RCCA3.m{1}.[(h, (pms, t))] = 
        let (k, pv, h', c) = proj RCCA4.d{2}.[t] in Some k)).
  proof.
    fun.
    wp; sp; if => //.
    inline{1} RCCA3.O1.extract.
    sp; if => //; first by smt.
      if{1}.
        if{2}.
          by exfalso; smt.
          wp; rnd; skip; progress.
            by smt.
            by smt.
            by smt.
            elim H13; clear H13; intros ?.
            by smt.
            case (t0 = t{2}) => ?.
              subst; elim H13; clear H13; intros X Y.
              by generalize Y; rewrite /_.[_] Core.get_setE; smt.
              cut L : (in_dom (h0, (pms0, t0)) RCCA3.m{1}); last by smt.
              rewrite H2.
              cut L : (in_dom t0 RCCA4.d{2} /\
                let (k0, pv0, h', c0) = proj RCCA4.d{2}.[t0] in
                  h0 = h' /\ decrypt V.sk{2} pv0 c0 = Some pms0).
              split; first by smt.
              by generalize H13; rewrite /_.[_] Core.get_setN; smt.
            by right; smt.   
            by smt.

          if{2}.
          sp; if{1}; first by exfalso; smt.
          wp; skip; progress.
            by smt.
            elim H12; clear H12; intros ?; first by smt.
            right; split; first by smt.
            split; first by smt.
            cut -> : t{2} = V.t{2} by smt.
            rewrite /_.[_] Core.get_setE; smt.

            by smt.

            case (in_dom (h0, (pms0, t0)) RCCA4.m{2}) => //= ?.
            case (t0 = t{2}) => ?.
              subst; split; smt.
              split; first by smt.
              rewrite /_.[_] /_.[_] Core.get_setN; smt.

            elim H12 => ?; clear H12; first by smt.
              cut L : (in_dom (h0, (pms0, t0)) RCCA3.m{1}); last by smt.
              rewrite H2.
              case (t0 = t{2}) => ?.
                subst; elim H13; clear H13 => X Y.
                by generalize Y; rewrite /_.[_] Core.get_setE; smt.

                right.
                elim H13; clear H13 => X Y.
                by generalize X Y; rewrite /_.[_] /_.[_] !Core.get_setN; smt.

            by smt.
    
         sp; if{1}; last by exfalso; smt.
         wp; rnd; skip; progress.
           by smt.
           elim H14 => ?; clear H14; first by smt.
           right; split; first by smt.
           split; first by smt.
           cut -> : t{2} = V.t{2} by smt.
           rewrite /_.[_] Core.get_setE; smt.

           by smt.

           case (in_dom (h0, (pms0, t0)) RCCA4.m{2}) => //= ?.
           case ((h0, (pms0, t0)) = (h{2}, (proj (decrypt V.sk{2} pv{2} c{2}), t{2}))) => ?.
              split; first by smt.
              cut -> : (t0 = t){2} by smt.
              rewrite /_.[_] Core.get_setE; smt.
              cut L : (in_dom (h0, (pms0, t0)) RCCA3.m{1}) by smt.
              split; first by smt.
              by generalize H14; rewrite /_.[_] Core.get_setN; smt.

            elim H14 => ?; clear H14; first by smt.

            elim H15; clear H15 => X Y.
            case ((h0, (pms0, t0)) = (h{2}, (proj (decrypt V.sk{2} pv{2} c{2}), t{2}))) => ?.
              by smt.

              cut L : (in_dom (h0, (pms0, t0)) RCCA3.m{1}); last by smt.
              rewrite H2.
              case (in_dom (h0, (pms0, t0)) RCCA4.m{2}) => //= ?.
              case (t0 = t{2}) => ?.
                subst; generalize Y; rewrite /_.[_] Core.get_setE proj_some; smt.                   generalize Y; rewrite /_.[_] Core.get_setN; smt.

             by smt.
             cut : decrypt V.sk{2} pv{2} c{2} <> None by smt.
             case (t0 = t{2}) => ?; smt.

      by skip; progress; smt.
  qed.
  
  local equiv RCCA3_RCCA4 :
    RCCA3.main ~ RCCA4.main : 
    true ==>
    RCCA3.abort{1} =>
      (exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m){2} \/
      (in_dom V.t RCCA4.d /\
       let (k, pv, h, c) = proj RCCA4.d.[V.t] in
         c <> V.c /\ decrypt V.sk pv c = Some V.pms){2}.
  proof.
    fun.
    rnd{1}.
    call (_:
     ={glob V} /\
     (V.guess{1} => ={V.t}) /\
     (decrypt V.sk (fst pp) V.c = Some V.pms){2} /\ 
     (RCCA3.abort{1} =>
      (exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m) \/
      (V.guess /\ in_dom V.t RCCA4.d /\
       let (k, pv, h, c) = proj RCCA4.d.[V.t] in
        c <> V.c /\ decrypt V.sk pv c = Some V.pms)){2} /\
     (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
     (forall h pms t, 
      (in_dom (h, (pms, t)) RCCA3.m{1} <=>
      (in_dom (h, (pms, t)) RCCA4.m{2} \/
       (in_dom t RCCA4.d{2} /\ 
        let (k, pv, h', c) = proj RCCA4.d{2}.[t] in 
         h = h' /\ decrypt V.sk{2} pv c = Some pms)))) /\
     (forall h pms t, 
      (in_dom (h, (pms, t)) RCCA3.m{1} => 
       in_dom (h, (pms, t)) RCCA4.m{2} => 
       RCCA3.m{1}.[(h, (pms, t))] = RCCA4.m{2}.[(h, (pms, t))])) /\
     (forall h pms t, 
      (in_dom (h, (pms, t)) RCCA3.m{1} => 
       !in_dom (h, (pms, t)) RCCA4.m{2} => 
         RCCA3.m{1}.[(h, (pms, t))] = 
         let (k, pv, h', c) = proj RCCA4.d{2}.[t] in Some k))).
      by apply RCCA3_RCCA4_dec.
      by apply RCCA3_RCCA4_extract.
    wp; rnd; rnd; wp.
    call (_:
     ={glob V} /\
     (V.guess{1} => ={V.t}) /\
     (decrypt V.sk (fst pp) V.c = Some V.pms){2} /\ 
     (RCCA3.abort{1} =>
      (exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m) \/
      (V.guess /\ in_dom V.t RCCA4.d /\
       let (k, pv, h, c) = proj RCCA4.d.[V.t] in
        c <> V.c /\ decrypt V.sk pv c = Some V.pms)){2} /\
     (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
     (forall h pms t, 
      (in_dom (h, (pms, t)) RCCA3.m{1} <=>
      (in_dom (h, (pms, t)) RCCA4.m{2} \/
       (in_dom t RCCA4.d{2} /\ 
        let (k, pv, h', c) = proj RCCA4.d{2}.[t] in 
         h = h' /\ decrypt V.sk{2} pv c = Some pms)))) /\
     (forall h pms t, 
      (in_dom (h, (pms, t)) RCCA3.m{1} => 
       in_dom (h, (pms, t)) RCCA4.m{2} => 
       RCCA3.m{1}.[(h, (pms, t))] = RCCA4.m{2}.[(h, (pms, t))])) /\
     (forall h pms t, 
      (in_dom (h, (pms, t)) RCCA3.m{1} => 
       !in_dom (h, (pms, t)) RCCA4.m{2} => 
         RCCA3.m{1}.[(h, (pms, t))] = 
         let (k, pv, h', c) = proj RCCA4.d{2}.[t] in Some k))).
      by apply RCCA3_RCCA4_dec.
      by apply RCCA3_RCCA4_extract. 
    seq 2 2 : (={V.pk, V.sk} /\ keypair(V.pk, V.sk){1}).
      by call keygen_spec_rel; call (_:true); skip.
      exists * V.pk{1}, V.sk{1}; elim *; intros pk sk.
      call (enc_spec_rel sk pk (fst pp)).
      inline V.init; wp; skip; progress; smt.
  qed.
  
  local lemma Pr_RCCA3_RCCA4 &m :
    Pr[RCCA3.main() @ &m : RCCA3.abort] <=
    Pr[RCCA4.main() @ &m : exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m] +  
    Pr[RCCA4.main() @ &m : let (k, pv, h, c) = proj RCCA4.d.[V.t] in
       c <> V.c /\ decrypt V.sk pv c = Some V.pms].
  proof.
    apply (Trans _ 
      Pr[RCCA4.main() @ &m : 
       (exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m) \/
       let (k, pv, h, c) = proj RCCA4.d.[V.t] in
         c <> V.c /\ decrypt V.sk pv c = Some V.pms]).
      by equiv_deno RCCA3_RCCA4; smt.  
      rewrite Pr mu_or.
      cut X : forall (x y z), 0%r <= z => x <= y => x - z <= y by smt.
    by apply X; [smt | apply Refl].
  qed.
  
  
  (** RCCA4 -> OW_PCA **)

  (* 
   * This module implements auxiliary procedures used in the reduction
   * to OW_PCA and NR_PCA, and the extract and decryption oracles (the
   * same are used in both reductions).
   *)
  local module Find(PCO:PCA.Oracle) = {
    var m : (hash * (pms * label), ms) map
    var d : (label, (ms * version * hash * ciphertext)) map
    var pk : pkey
  
    (* Private procedures *)
    fun find(pv:version, c:ciphertext, h:hash, t:label) : pms option = {
      var h' : hash;
      var s : pms * label;
      var pms : pms;
      var t' : label;
      var found : bool;
      var q : (hash * (pms * label)) set;
      var maybe_pms : pms option = None;
      q = dom(m);
      while (q <> FSet.empty /\ maybe_pms = None) {
        (h',  s) = pick q;
        q = rm (h', s) q;
        (pms, t') = s;
        found = PCO.check((), pms, pv, c);
        if (found /\ h = h' /\ t = t') maybe_pms = Some pms; 
      }
      return maybe_pms;
    }
  
    fun find_any(pv:version, c:ciphertext) : pms option = {
      var h' : hash;
      var s : pms * label;
      var pms : pms;
      var t' : label;
      var found : bool;
      var q : (hash * (pms * label)) set;
      var maybe_pms : pms option = None;
      q = dom(m);
      while (q <> FSet.empty /\ maybe_pms = None) {
        (h',  s) = pick q;
        q = rm (h', s) q;
        (pms, t') = s;
        found = PCO.check((), pms, pv, c);
        if (found) maybe_pms = Some pms;
      }
      return maybe_pms;
    }

    module O1 = {
      fun extract(p:hash, s:pms * label) : ms = {
        var k : ms;
        var pms : pms;
        var t : label;
        var pv : version;
        var h : hash;
        var c : ciphertext;
        var found : bool;
        (pms, t) = s;
        if (!in_dom (p, (pms, t)) m) {
          (k, pv, h, c) = proj d.[t];
          found = PCO.check((), pms, pv, c);
          if (in_dom t d /\ p = h /\ found) {
            k = let (ms, pv, h, c) = proj d.[t] in ms;
          }
          else k = $key;
          m.[(p, (pms, t))] = k;
        }
        else k = proj m.[(p, (pms, t))];
        return k;
      }
    }
    
    module O2 = {
      fun dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var k : ms;
        var maybe_pms : pms option;
        var maybe_k : ms option = None;
        if (!mem t V.labels /\ mem p P) { 
          V.labels = add t V.labels;
          (pv, h) = p;
          if (!(V.guess /\ same_key pk (fst pp) pv c /\ h = snd pp /\ t = V.t /\ V.c = c)) {
            maybe_pms = find(pv, c, h, t);
            if (maybe_pms <> None) k = proj m.[(h, (proj maybe_pms, t))];
            else k = $key;
            d.[t] = (k, pv, h, c);
            maybe_k = if (!mem k V.keys) then Some k else None;
          }
        }
        return maybe_k;
      }
    }
  }.

  (* Adversary used in the reduction to OW_PCA *)
  local module B(PCO:PCA.Oracle) = {  
    module F = Find(PCO)
    module A = A(Find(PCO).O1, Find(PCO).O2)
   
    fun choose(pk:pkey) : version = {
      var t : label;
      V.init();
      Find.m = Core.empty;
      Find.d = Core.empty;
      Find.pk = pk;
      V.t = A.choose(pk);
      return (fst pp);
    }
  
    fun guess(c:ciphertext) : pms = {
      var maybe_pms : pms option;
      var k0, k1 : ms;
      var b' : bool;
      V.c = c;
      k0 = $key;
      k1 = $key;
      V.keys = add k0 (add k1 V.keys);
      V.guess = true;
      b' = A.guess(c, k0);
      maybe_pms = F.find_any(fst pp, c);
      return proj maybe_pms;
    }
  }.

  local module O = {
    fun check(p:unit, k:pms, t:version, c:ciphertext) : bool = {
      var maybe_k : pms option;
      maybe_k = decrypt PCA.V.sk t c;
      return (maybe_k = Some k);
    }
  }.
 
  local module OW_PCA0 = {
    module B = B(O)
    
    fun main() : bool = {
      var pk : pkey;
      var t : version;
      var k, k' : pms;
      var c : ciphertext;
      PMS_KEM.init();
      (pk, PCA.V.sk) = PMS_KEM.keygen();
      (k, c) = PMS_KEM.enc((), pk, fst pp);
      t = B.choose(pk);
      k' = B.guess(c);
      return (k = k');
    }
  }.

  local equiv OW_PCA0_OW_PCA_check :
    O.check ~ PCA.OW_PCA(PMS_KEM, B).O.check : 
    ={p, k, t, c} /\ ={glob PCA.V} ==> 
    ={res} /\ ={glob PCA.V}.
  proof.
    fun.
    wp; exists * PCA.V.sk{2}, t{2}, c{2}; elim *; intros sk pv c.
    by call{2} (dec_spec sk pv c).
  qed.

  local equiv OW_PCA0_OW_PCA :
    OW_PCA0.main ~ PCA.OW_PCA(PMS_KEM, B).main : true ==> ={res}.
  proof.
    fun.
    swap{1} 3 1.
    inline PCA.OW_PCA(PMS_KEM, B).A.guess OW_PCA0.B.guess.
    eqobs_in (={glob PCA.V}) true : (={k,k',glob Find, glob PCA.V}).
    apply OW_PCA0_OW_PCA_check.
    seq 3 3 : 
     (={pk, glob PCA.V, glob A, glob Find, t} /\ 
      t{1} = fst pp /\ keypair(pk, PCA.V.sk){2}).
    inline PCA.OW_PCA(PMS_KEM, B).A.choose OW_PCA0.B.choose; wp.
    call (_: ={glob PCA.V, glob Find}) => //.
      fun.
      eqobs_in true (={glob PCA.V}) : (={maybe_k, glob Find, glob PCA.V}).
      apply OW_PCA0_OW_PCA_check.
      fun.
      eqobs_in (={glob PCA.V}) true : (={k, glob Find, glob PCA.V}).
      apply OW_PCA0_OW_PCA_check.
    by inline V.init; wp; call keygen_spec_rel; call (_:true).
    exists * PCA.V.sk{1}, pk{1}, t{1}; elim *; intros sk pk t.
    by call (enc_spec_rel sk pk t).
  qed.

  local lemma check_spec _k _t _c :
    bd_hoare 
    [ O.check : 
      k = _k /\ t = _t /\ c = _c ==>
      res <=> decrypt PCA.V.sk _t _c = Some _k ] = 1%r.
  proof.
    by fun; wp; skip; smt.
  qed.
  
  local lemma find_any_spec _pv _c :
    bd_hoare 
    [ Find(O).find_any : 
      pv = _pv /\ c = _c ==> 
      let maybe = decrypt PCA.V.sk _pv _c in
       res = 
       if (exists h t, in_dom (h, (proj maybe, t)) Find.m) then maybe
       else None ] = 1%r.
  proof.
    fun; sp.
    while  
     (let maybe = decrypt PCA.V.sk pv c in
      (forall x, mem x q => in_dom x Find.m) /\
      (forall x, 
       in_dom x Find.m => !mem x q => maybe_pms = None => 
       maybe <> Some (fst (snd x))) /\
      (maybe_pms <> None =>
       (exists h t, in_dom (h, (proj maybe, t)) Find.m) /\ maybe_pms = maybe))
     (card q).
       intros z; sp; wp. 
       exists * pms, pv, c; elim *; intros pms pv c.
       call (check_spec pms pv c); skip; progress; smt. 

    wp; skip; progress.
      by smt.
      by smt.
      by smt.
      case (maybe_pms0 = None) => ?; last by smt.
      subst.
      cut : (q0 = FSet.empty) by smt => ?.
      subst.
      cut : forall h pms t,
       in_dom (h, (pms, t)) Find.m{hr} =>
       decrypt PCA.V.sk{hr} pv{hr} c{hr} <> Some pms by smt => ?.
      cut : !exists (h : hash) (t : label),
        in_dom (h, (proj (decrypt PCA.V.sk{hr} pv{hr} c{hr}), t)) Find.m{hr} /\
        decrypt PCA.V.sk{hr} pv{hr} c{hr} <> None by smt.
      by smt.
  qed.

  local lemma find_spec _pv _c _h _t :
    bd_hoare 
    [ Find(O).find : 
      pv = _pv /\ c = _c /\ h = _h /\ t = _t ==> 
      let maybe = decrypt PCA.V.sk _pv _c in
       res = 
       if (in_dom (_h, (proj maybe, _t)) Find.m) then maybe
       else None ] = 1%r.
  proof.
    fun; sp.
    case (decrypt PCA.V.sk pv c = Some (proj (decrypt PCA.V.sk pv c))). (* argh! *)
    while  
     ((forall x, mem x q => in_dom x Find.m) /\
      let maybe = decrypt PCA.V.sk pv c in maybe <> None /\
      (forall h_ pms_ t_, 
       in_dom (h_, (pms_, t_)) Find.m => !mem (h_, (pms_, t_)) q =>
       maybe_pms = None => h_ <> h \/ maybe <> Some pms_ \/ t_ <> t) /\
      (maybe_pms <> None <=> maybe_pms = maybe) /\
      (maybe_pms <> None =>
       in_dom (h, (proj maybe, t)) Find.m /\ 
       maybe_pms = Some pms /\ h = h' /\  t = t'))
     (card q).
      intros z; sp; wp. 
      exists * pms, pv, c; elim *; intros pms pv c.
      call (check_spec pms pv c); skip; progress; smt.
    wp; skip; progress => //; smt.

    while  
     (decrypt PCA.V.sk pv c = None /\ maybe_pms = None)
     (card q).
      intros z; sp; wp. 
      exists * pms, pv, c; elim *; intros pms pv c.
      by call (check_spec pms pv c); skip; progress; smt.
      by skip; progress; smt.
  qed.

  local equiv RCCA4_Find_extract_guess : 
    RCCA4.O1.extract ~ Find(O).O1.extract :
    ={p, s} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1}
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1}. 
  proof.
    fun.
    sp; if => //.
      seq 0 2 : 
       (={pms, t, p, s, V.keys, V.labels, V.guess, V.t, V.c} /\
        V.pk{1} = Find.pk{2} /\
        V.sk{1} = PCA.V.sk{2} /\ 
        RCCA4.m{1} = Find.m{2} /\ 
        RCCA4.d{1} = Find.d{2} /\
        decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1} /\ 
        ((in_dom t RCCA4.d /\ 
          let (ms, pv, h, c) = proj RCCA4.d.[t] in 
            p = h /\ decrypt V.sk pv c = Some pms){1} <=> 
         (in_dom t Find.d /\ p = h /\ found){2})).
        sp; exists * pms{2}, pv{2}, c{2}; elim *; intros pms pv c.
        by call{2} (check_spec pms pv c); skip; progress; smt.
        by if => //; wp; try rnd; skip; progress.
      by wp.
  qed.
  
  local equiv RCCA4_Find_dec_guess : 
    RCCA4.O2.dec ~ Find(O).O2.dec :
    ={p, t, c} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1} 
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1}. 
  proof.
    fun.
    sp; if => //.
    sp; if => //.
    seq 0 1 :    
     (maybe_k{1} = None /\
      ={maybe_k, pv, h, p, t, c, V.labels, V.keys, V.guess, V.t, V.c} /\
      V.pk{1} = Find.pk{2} /\
      V.sk{1} = PCA.V.sk{2} /\
      RCCA4.m{1} = Find.m{2} /\ 
      RCCA4.d{1} = Find.d{2} /\
      decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1} /\
      !(V.guess /\ same_key V.pk (fst pp) pv c /\ h = snd pp /\ t = V.t /\ V.c = c){1} /\
      ((decrypt V.sk pv c <> None /\ 
       in_dom (h, (proj (decrypt V.sk pv c), t)) RCCA4.m){1} <=> 
       maybe_pms{2} <> None) /\
      (maybe_pms <> None => 
       maybe_pms = Some (proj (decrypt PCA.V.sk pv c))){2}).
      sp; exists * pv{2}, c{2}, h{2}, t{2}; elim *; intros pv c h t.
      call{2} (find_spec pv c h t); skip; progress => //;
        try rewrite some_proj; smt.

      if => //.
        by wp; skip; smt.
        by wp; rnd.
  qed.

  local equiv RCCA4_Find_extract_choose : 
    RCCA4.O1.extract ~ Find(O).O1.extract :
    ={p, s} /\ ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1}
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1}. 
  proof.
    fun.
    sp; if => //.
      seq 0 2 : 
       (={pms, t, p, s, V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
        V.sk{1} = PCA.V.sk{2} /\ 
        V.pk{1} = Find.pk{2} /\
        RCCA4.m{1} = Find.m{2} /\ 
        RCCA4.d{1} = Find.d{2} /\
        decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1} /\ 
        ((in_dom t RCCA4.d /\ 
          let (ms, pv, h, c) = proj RCCA4.d.[t] in 
            p = h /\ decrypt V.sk pv c = Some pms){1} <=> 
         (in_dom t Find.d /\ p = h /\ found){2})).
        sp; exists * pms{2}, pv{2}, c{2}; elim *; intros pms pv c.
        by call{2} (check_spec pms pv c); skip; progress; smt.
        by if => //; wp; try rnd; skip; progress.
      by wp.
  qed.

  local equiv RCCA4_Find_dec_choose : 
    RCCA4.O2.dec ~ Find(O).O2.dec :
    ={p, t, c} /\ ={V.keys, V.labels, V.guess, V.t} /\
    !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1} 
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t} /\
    !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1}. 
  proof.
    fun.
    sp; if => //.
    sp; if => //; first by smt.
    seq 0 1 :    
     (maybe_k{1} = None /\
      ={maybe_k, pv, h, p, t, c, V.labels, V.keys, V.guess, V.t} /\
      !V.guess{1} /\
      V.pk{1} = Find.pk{2} /\
      V.sk{1} = PCA.V.sk{2} /\
      RCCA4.m{1} = Find.m{2} /\ 
      RCCA4.d{1} = Find.d{2} /\
      decrypt V.sk{1} (fst pp) V.c{1} = Some V.pms{1} /\
      !(V.guess /\ same_key V.pk (fst pp) pv c /\ h = snd pp /\ t = V.t /\ V.c = c){1} /\
      ((decrypt V.sk pv c <> None /\
        in_dom (h, (proj (decrypt V.sk pv c), t)) RCCA4.m){1} <=> 
       maybe_pms{2} <> None) /\
      (maybe_pms <> None => 
       maybe_pms = Some (proj (decrypt PCA.V.sk pv c))){2}).
      sp; exists * pv{2}, c{2}, h{2}, t{2}; elim *; intros pv c h t.
      by call{2} (find_spec pv c h t); skip; progress; 
        try rewrite some_proj; smt.  
      if => //.
        by wp; skip; smt.
        by wp; rnd.
  qed.

  local equiv RCCA4_OW_PCA0 :
    RCCA4.main ~ OW_PCA0.main :
    true ==> (exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m){1} => res{2}.
  proof.
   fun.
   inline OW_PCA0.B.choose OW_PCA0.B.guess.
   swap{2} [4..8] -1; wp.
   seq 6 8 :
     (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
      RCCA4.m{1} = Find.m{2} /\ RCCA4.d{1} = Find.d{2} /\
      V.pk{1} = Find.pk{2} /\ V.sk{1} = PCA.V.sk{2} /\ 
      pk0{2} = pk{2} /\ pk{2} = Find.pk{2} /\
      V.pms{1} = k{2} /\ V.c{1} = c{2} /\ 
      (decrypt V.sk (fst pp) V.c = Some V.pms){1}).
   seq 5 6 : (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
      RCCA4.m{1} = Find.m{2} /\ RCCA4.d{1} = Find.d{2} /\
      V.sk{1} = PCA.V.sk{2} /\ pk0{2} = pk{2} /\ V.pk{1} = pk{2} /\
      keypair(V.pk, V.sk){1}).
   by inline V.init; wp; call keygen_spec_rel; call (_:true).
   exists * V.sk{1}, V.pk{1}; elim *; intros sk pk.
   call (enc_spec_rel sk pk (fst pp)); wp; skip; progress; smt.

   seq 6 9 : (={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\ V.sk{1} = PCA.V.sk{2} /\ 
    pk0{2} = pk{2} /\ pk{2} = Find.pk{2} /\
    V.pms{1} = k{2} /\ V.c{2} = c0{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){1}).
   call (_: ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){1}).
     by apply RCCA4_Find_dec_guess.
     by apply RCCA4_Find_extract_guess.
    wp; rnd; rnd; wp.
   call (_: ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){1}).
     by apply RCCA4_Find_dec_choose.
     by apply RCCA4_Find_extract_choose.
   skip; progress.

    wp; exists * c0{2}; elim *; intros c.
    call{2} (find_any_spec (fst pp) c).
    by wp; skip; progress; smt.
  qed.
  
  local lemma Pr_RCCA4_OW_PCA &m :
    Pr[RCCA4.main() @ &m : exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m] <=
    Pr[PCA.OW_PCA(PMS_KEM, B).main() @ &m : res].
  proof.
    apply (Trans _ Pr[OW_PCA0.main() @ &m : res]).
    by equiv_deno RCCA4_OW_PCA0.
    by equiv_deno OW_PCA0_OW_PCA.
  qed.
  
  
  (** RCCA4 -> NR *)

  (* 
   * REMARK: the remark below may not hold when using Bleichenbacher 
   * countermeasure because the condition !mem t labels is used earlier.
   *
   * REMARK: the condition !mem t labels in the decryption oracle in
   * the RCCA game could be dropped. A similar reduction to NR-PCA
   * would work, but the map d would no longer be functional on t, and so
   * the NR adversary would have to choose one decryption query for the
   * challenge label at random, incurring a q_dec loss factor.
   *)

  (* Adversary used in the reduction to NR_PCA *)
  local module C(PCO:PCA.Oracle) = {
    module F = Find(PCO)
    module A = A(Find(PCO).O1, Find(PCO).O2)
      
    fun choose(pk:pkey) : version = {
      var t : label;
      V.init();
      Find.m = Core.empty;
      Find.d = Core.empty;
      Find.pk = pk;
      V.t = A.choose(pk);
      return (fst pp);
    }
  
    fun guess(c:ciphertext) : version * ciphertext = {
      var pms : pms;
      var k0, k1 : ms;
      var b' : bool;
      V.c = c;
      k0 = $key;
      k1 = $key;
      V.keys = add k0 (add k1 V.keys);
      V.guess = true;
      b' = A.guess(c, k0);
      return let (k, pv, h, c) = proj Find.d.[V.t] in (pv, c);
    }
  }.

  local module NR_PCA0 = {
    module C = C(O)
    
    fun main() : bool = {
      var pk : pkey;
      var t, t' : version;
      var k : pms;
      var maybe_k : pms option;
      var c, c' : ciphertext;
      PMS_KEM.init();
      (pk, PCA.V.sk) = PMS_KEM.keygen();
      (k, c) = PMS_KEM.enc((), pk, fst pp);
      t = C.choose(pk);
      (t', c') = C.guess(c);
      maybe_k = PMS_KEM.dec((), PCA.V.sk, t', c');
      return (c <> c' /\ maybe_k = Some k);
    }
  }.

  local equiv NR_PCA0_NR_PCA :
    NR_PCA0.main ~ PCA.NR_PCA(PMS_KEM, C).main : true ==> ={res}.
  proof.
    fun.
    swap{1} 3 1.
    inline PCA.NR_PCA(PMS_KEM, C).A.guess NR_PCA0.C.guess.
    call (_: ={glob Find, glob PCA.V}); wp.
    call (_: ={glob Find, glob PCA.V}).
      fun.
      eqobs_in true (={glob PCA.V}) : (={maybe_k, glob Find, glob PCA.V}).
      apply OW_PCA0_OW_PCA_check.
      fun.
      eqobs_in (={glob PCA.V}) true : (={k, glob Find, glob PCA.V}).
      apply OW_PCA0_OW_PCA_check.
    seq 3 3 : 
     (={pk, glob PCA.V, glob A, glob Find, t} /\ 
      t{1} = fst pp /\ keypair(pk, PCA.V.sk){2}).
    inline PCA.NR_PCA(PMS_KEM, C).A.choose NR_PCA0.C.choose; wp.
    call (_: ={glob PCA.V, glob Find}) => //.
      fun.
      eqobs_in true (={glob PCA.V}) : (={maybe_k, glob Find, glob PCA.V}).
      apply OW_PCA0_OW_PCA_check.
      fun.
      eqobs_in (={glob PCA.V}) true : (={k, glob Find, glob PCA.V}).
      apply OW_PCA0_OW_PCA_check.
    by inline V.init; wp; call keygen_spec_rel; call (_:true).
    wp; rnd; rnd; wp.
    exists * PCA.V.sk{1}, pk{1}, t{1}; elim *; intros sk pk t.
    by call (enc_spec_rel sk pk t); skip; progress; smt.
  qed.
  
  local equiv RCCA4_NR :
    RCCA4.main ~ NR_PCA0.main :
    true ==> 
    (let (k, pv, h, c) = proj RCCA4.d.[V.t] in
       c <> V.c /\ decrypt V.sk pv c = Some V.pms){1} => res{2}.
  proof.
   fun.
   inline NR_PCA0.C.choose NR_PCA0.C.guess.
   swap{2} [4..8] -1; wp.
   seq 6 8 :
     (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
      RCCA4.m{1} = Find.m{2} /\ RCCA4.d{1} = Find.d{2} /\
      V.sk{1} = PCA.V.sk{2} /\ 
      V.pk{1} = pk{2} /\ pk0{2} = pk{2} /\ pk{2} = Find.pk{2} /\
      V.pms{1} = k{2} /\ V.c{1} = c{2} /\ 
      (decrypt V.sk (fst pp) V.c = Some V.pms){1}).
   seq 5 7 : (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
      RCCA4.m{1} = Find.m{2} /\ RCCA4.d{1} = Find.d{2} /\
      V.sk{1} = PCA.V.sk{2} /\ 
      V.pk{1} = pk{2} /\ pk0{2} = pk{2} /\ pk{2} = Find.pk{2} /\
      keypair(V.pk, V.sk){1}).
   by inline V.init; wp; call keygen_spec_rel; call (_:true).
   exists * V.sk{1}, V.pk{1}; elim *; intros sk pk.
   call (enc_spec_rel sk pk (fst pp)); wp; skip; progress; smt.

   seq 6 9 : (={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ V.c{2} = c0{2} /\ c{2} = c0{2} /\ pk0{2} = pk{2} /\
    V.pms{1} = k{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){1}).
   call (_: ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){1}).
     by apply RCCA4_Find_dec_guess.
     by apply RCCA4_Find_extract_guess.
    wp; rnd; rnd; wp.
   call (_: ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA4.m{1} = Find.m{2} /\ 
    RCCA4.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = Some V.pms){1}).
     by apply RCCA4_Find_dec_choose.
     by apply RCCA4_Find_extract_choose.
   skip; progress.

    sp; wp; exists * PCA.V.sk{2}, t'{2}, c'{2}; elim *; intros sk pv c.
    call{2} (dec_spec sk pv c).
    by skip; progress; smt.
  qed.
  
  local lemma Pr_RCCA4_NR_PCA &m :
    Pr[RCCA4.main() @ &m : let (k, pv, h, c) = proj RCCA4.d.[V.t] in
       c <> V.c /\ decrypt V.sk pv c = Some V.pms] <=
    Pr[PCA.NR_PCA(PMS_KEM, C).main() @ &m : res].
  proof.
    apply (Trans _ Pr[NR_PCA0.main() @ &m : res]).
    by equiv_deno RCCA4_NR.
    by equiv_deno NR_PCA0_NR_PCA.
  qed.

  (** Conclusion **)
  lemma Conclusion &m :
    exists (B <: PCA.OW_Adversary {PCA.V}) (C <: PCA.NR_Adversary {PCA.V}),
      Pr[RCCA(KEM(RO_KEF, PMS_KEM), A(RO_KEF)).main() @ &m : res] - 1%r / 2%r <=
      qKEF%r / (card (toFSet univ<:pms>))%r +
      Pr[PCA.OW_PCA(PMS_KEM, B).main() @ &m : res] +
      Pr[PCA.NR_PCA(PMS_KEM, C).main() @ &m : res].
  proof.
    exists B, C.
    cut X : forall (x y z:real), x <= y + z => x - y <= z by smt.
    apply X.
    apply (Trans _ (1%r / 2%r + 
      (Pr[RCCA2.main() @ &m : exists h t,  in_dom (h, (proj RCCA2.fake.[t], t)) RCCA2.m] +
      Pr[RCCA3.main() @ &m : RCCA3.abort]))).
    cut W := Pr_RCCA_RCCA3 &m; smt.
    apply addleM => //.
    cut -> : forall (x y z:real), x + y + z = x + (y + z) by smt.
    apply addleM => //.
    apply (Pr_RCCA2 &m).
    apply (Trans _
      (Pr[RCCA4.main() @ &m : exists t, in_dom (snd pp, (V.pms, t)) RCCA4.m] +  
       Pr[RCCA4.main() @ &m : let (k, pv, h, c) = proj RCCA4.d.[V.t] in
          c <> V.c /\ decrypt V.sk pv c = Some V.pms])).
    by apply (Pr_RCCA3_RCCA4 &m).
    apply addleM.
      by apply (Pr_RCCA4_OW_PCA &m).
      by apply (Pr_RCCA4_NR_PCA &m).
  qed.

end section.

print axiom Conclusion.
