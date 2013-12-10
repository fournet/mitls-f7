(*
 * Proof of Theorem 2 in the Technical Report
 *
 * Theorem: if the pre-master secret KEM used in the TLS handshake is
 * both One-Way and Non-Randomizable under Plaintext-Checking Attacks,
 * then the master secret KEM, seen as an agile labeled KEM, is
 * Indistinguishable under Replayable Chosen-Ciphertext Attacks in the
 * ROM for the underlying agile KEF.
 *)

require import Bool.
require import Int.
require import Real.
require import Pair.
require import FMap.

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
    fun dec(p:parameter, sk:skey, t:label, c:ciphertext) : key
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
          k = KEM.dec(p, W.sk, t, c);
          maybe_k = if (!mem k W.keys) then Some k else None;
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
        var k' : key;
        k' = KEM.dec(p, V.sk, t, c);
        return (k' = k);
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
        var k, k' : key;
        var c, c' : ciphertext;
        KEM.init();
        (pk, V.sk) = KEM.keygen();
        t = A.choose(pk);
        (k, c) = KEM.enc(pp, pk, t);
        (t', c') = A.guess(c);
        k' = KEM.dec(pp, V.sk, t', c');
        return (c <> c' /\ k' = k);
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

  declare module PMS_KEM : Inner_KEM.KEM 
    {RO_KEF, RCCA, PCA.NR_PCA, PCA.OW_PCA}.

  (* Assumptions on the Pre-master secret KEM *)

  (* 
   * REMARK: This can be weakened. It is enough to require that 
   * PMS_KEM.enc and PMS_KEM.dec do not write shared global state
   * (read-only shared state initialized by PMS_KEM.init and 
   * PMS_KEM.keygen is fine).
   *)
  axiom stateless_pms_kem : forall (x y:glob PMS_KEM), x = y.

  (* TODO: move these 3 operators to PMS_KEM *)
  op keypair : pkey * skey -> bool.

  op decrypt : skey -> version -> ciphertext -> pms.

  op same_key : pkey -> version -> version -> ciphertext -> bool.

  (* 
   * REMARK: The axiom previously used only holds for RSA:
   *
   * axiom nosmt dec_injective_pv : forall sk pv1 pv2 c,
   * decrypt sk pv1 c = decrypt sk pv2 c => pv1 = pv2.
   *
   * For RSA, same_key pk pv1 pv2 c := pv1 = pv2
   * For DH, same_key pk pv1 pv2 c := true
   *)  
  axiom nosmt same_key_spec : forall pk sk pv1 pv2 c,
    keypair(pk, sk) =>
    (same_key pk pv1 pv2 c <=> decrypt sk pv1 c = decrypt sk pv2 c).

  axiom keygen_spec_rel :
    equiv [ PMS_KEM.keygen ~ PMS_KEM.keygen : true ==> ={res} /\ keypair res{1} ].

  axiom enc_spec_rel : forall sk pk pv,
    equiv [ PMS_KEM.enc ~ PMS_KEM.enc :
      pk{1} = pk /\ t{1} = pv /\ ={pk, t} /\ keypair(pk, sk) ==>
      ={res} /\ let (k, c) = res{1} in decrypt sk pv c = k ].

  axiom dec_spec : forall _sk _pv _c,
    bd_hoare [ PMS_KEM.dec :
      sk = _sk /\ t = _pv /\ c = _c ==> res = decrypt _sk _pv _c ] = 1%r.
  
  (* TLS master secret KEM in the ROM for KEF *)
  local module MS_KEM = KEM(RO_KEF, PMS_KEM).

  (* RCCA adversary *)
  declare module A : Adversary
    {RO_KEF, PMS_KEM, RCCA, PCA.NR_PCA, PCA.OW_PCA}.

  axiom lossless_choose : 
    forall (O1 <: KEF.Oracle {A}) (O2 <: Oracle {A}),
      islossless O2.dec => islossless O1.extract => islossless A(O1, O2).choose.

  axiom lossless_guess : 
    forall (O1 <: KEF.Oracle {A}) (O2 <: Oracle {A}),
      islossless O2.dec => islossless O1.extract => islossless A(O1, O2).guess.
   
  local module RCCA0 = {
    module O = {
      fun dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t W.labels /\ mem p P) { 
          W.labels = add t W.labels;
          (pv, h) = p;
          pms = decrypt W.sk pv c;
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
    inline KEM(RO_KEF, PMS_KEM).dec; wp; sp.
    call (_: ={glob W, glob RO_KEF}); first by eqobs_in.
    exists * sk{1}, pv{1}, c0{1}; elim *; intros sk pv c.
    by call{1} (dec_spec sk pv c). 
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

  (* Global variables in RCCA1 and RCCA2 *)
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
  
  local module RCCA1 = {
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
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t V.labels /\ mem p P) { 
          V.labels = add t V.labels;
          (pv, h) = p;
          pms = decrypt V.sk pv c;
          abort = abort \/ (V.guess /\ pms = V.pms /\ t = V.t /\ c <> V.c);
          if (!(V.guess /\ same_key V.pk (fst pp) pv c /\ h = snd pp /\ t = V.t /\ c = V.c)) {
            if (!in_dom (h, (pms, t)) m) m.[(h, (pms, t))] = $key;
            k = proj m.[(h, (pms, t))];
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
  
  (** RCCA0 -> RCCA1 **)
  local equiv RCCA0_RCCA1_extract_upto :
    RO_KEF.extract ~ RCCA1.O1.extract :
    !RCCA1.abort{2} /\
    ={p, s} /\
    keypair(V.pk, V.sk){2} /\
    V.guess{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    eq_except RO_KEF.m{1} RCCA1.m{2} (snd pp, (V.pms, V.t)){2} /\
    in_dom (snd pp, (V.pms, V.t)){2} RO_KEF.m{1} /\
    mem (proj RO_KEF.m{1}.[(snd pp, (V.pms, V.t))]){2} V.keys{2} /\
    decrypt V.sk{2} (fst pp) V.c{2} = V.pms{2}
    ==>
    !RCCA1.abort{2} =>
      ={res} /\
      keypair(V.pk, V.sk){2} /\
      V.guess{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      eq_except RO_KEF.m{1} RCCA1.m{2} (snd pp, (V.pms, V.t)){2} /\
      in_dom (snd pp, (V.pms, V.t)){2} RO_KEF.m{1} /\
      mem (proj RO_KEF.m{1}.[(snd pp, (V.pms, V.t))]){2} V.keys{2} /\
      decrypt V.sk{2} (fst pp) V.c{2} = V.pms{2}.
  proof.
    fun.
    sp; case RCCA1.abort{2}.
      (* aborts *)
      if{1}; if{2}.
        by rnd; skip; smt.
        by rnd{1}; skip; smt.
        by rnd{2}; skip; smt.
        by skip; smt.     
      (* doesn't abort *)
      if; first by smt.
        by wp; rnd; skip; progress; smt.    
        wp; skip; progress.
        cut W : 
         (p, (pms, t)){2} <>
         (snd pp, (decrypt V.sk (fst pp) V.c, V.t)){2} by smt.
        by generalize H2; rewrite eq_except_def; smt.
  qed.
  
  local equiv RCCA0_RCCA1_dec_upto :
    RCCA0.O.dec ~ RCCA1.O2.dec :
    !RCCA1.abort{2} /\
    ={p, t, c} /\
    keypair(V.pk, V.sk){2} /\
    V.guess{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    eq_except RO_KEF.m{1} RCCA1.m{2} (snd pp, (V.pms, V.t)){2} /\
    in_dom (snd pp, (V.pms, V.t)){2} RO_KEF.m{1} /\
    mem (proj RO_KEF.m{1}.[(snd pp, (V.pms, V.t))]){2} V.keys{2} /\
    decrypt V.sk{2} (fst pp) V.c{2} = V.pms{2}
    ==>
    !RCCA1.abort{2} =>
      ={res} /\
      keypair(V.pk, V.sk){2} /\
      V.guess{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      eq_except RO_KEF.m{1} RCCA1.m{2} (snd pp, (V.pms, V.t)){2} /\
      in_dom (snd pp, (V.pms, V.t)){2} RO_KEF.m{1} /\
      mem (proj RO_KEF.m{1}.[(snd pp, (V.pms, V.t))]){2} V.keys{2} /\
      decrypt V.sk{2} (fst pp) V.c{2} = V.pms{2}.
  proof.
    fun.
    sp; if => //.
    wp; sp; case RCCA1.abort{2}.
      (* aborts *)
      call{1} (_:true ==> true); first by apply lossless_extract.
      if{2}.
        if{2}.
          by wp; rnd{2}; skip; smt.
          by wp; skip; smt.
        by skip; smt.    
      (* doesn't abort *)
      inline{1} RO_KEF.extract.
      if{2}.
        wp; sp; if.
          progress.
          by smt.
          by cut W := same_key_spec V.pk{2} V.sk{2} (fst pp) pv{2} c{2}; smt.
          by rnd; skip; progress; smt.    
        skip; progress.
        cut W := same_key_spec V.pk{2} V.sk{2} (fst pp) pv{2} c{2}.
        by generalize H2; rewrite eq_except_def; smt.
    wp; sp; if{1}.
      by rnd{1}; skip; progress;
        cut W := same_key_spec V.pk{2} V.sk{2} (fst pp) pv{2} V.c{2}; smt.
      by skip; progress;
        cut W := same_key_spec V.pk{2} V.sk{2} (fst pp) pv{2} V.c{2}; smt.
  qed.
  
  local lemma RCCA0_lossless_dec : islossless RCCA0.O.dec.
  proof.
    fun.
    sp; if => //.
    inline KEM(RO_KEF, PMS_KEM).dec; wp; sp.
    seq 1 : true => //.
      by call (_:true ==> true) => //; apply lossless_extract.
  qed.

  local lemma RCCA1_lossless_dec : islossless RCCA1.O2.dec.
  proof.
    fun.
    sp; if => //.
    sp; if => //.
    by if => //; wp; try rnd; skip; smt.  
  qed.

  local lemma RCCA1_dec_preserves_abort : 
    bd_hoare [ RCCA1.O2.dec : RCCA1.abort ==> RCCA1.abort ] = 1%r.
  proof.
    fun.
    sp; if => //.
    sp; if => //.
    by if => //; wp; try rnd; skip; smt.  
  qed.
  
  local equiv RCCA0_RCCA1_extract :
    RO_KEF.extract ~ RCCA1.O1.extract :
    !RCCA1.abort{2} /\
    ={p, s} /\
    keypair(V.pk, V.sk){2} /\ 
    !V.guess{2} /\
    RO_KEF.m{1} = RCCA1.m{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    decrypt V.sk{2} (fst pp) V.c{2} = V.pms{2} /\
    (forall t,
     in_dom (snd pp, (V.pms, t)) RCCA1.m => 
     RCCA1.abort \/ mem t V.labels){2}
    ==>
    !RCCA1.abort{2} =>
      ={res} /\ 
      keypair(V.pk, V.sk){2} /\
      !V.guess{2} /\
      RO_KEF.m{1} = RCCA1.m{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      decrypt V.sk{2} (fst pp) V.c{2} = V.pms{2} /\
      (forall t,
       in_dom (snd pp, (V.pms, t)) RCCA1.m => 
       RCCA1.abort \/ mem t V.labels){2}.
  proof.
    fun.
    sp; case RCCA1.abort{2}.
      by if{1}; if{2}; try rnd{1}; try rnd{2}; skip; smt.
      if => //.
        by rnd; skip; smt. 
        by skip; smt.
  qed.
  
  local equiv RCCA0_RCCA1_dec :
    RCCA0.O.dec ~ RCCA1.O2.dec :
    !RCCA1.abort{2} /\
    ={p, t, c} /\ 
    keypair(V.pk, V.sk){2} /\
    !V.guess{2} /\
    RO_KEF.m{1} = RCCA1.m{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    (decrypt V.sk (fst pp) V.c = V.pms){2} /\
    (forall t,
     in_dom (snd pp, (V.pms, t)) RCCA1.m => 
     RCCA1.abort \/ mem t V.labels){2}
    ==>
    !RCCA1.abort{2} =>
      ={res} /\ 
      keypair(V.pk, V.sk){2} /\
      !V.guess{2} /\
      RO_KEF.m{1} = RCCA1.m{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      (decrypt V.sk (fst pp) V.c = V.pms){2} /\
      (forall t,
       in_dom (snd pp, (V.pms, t)) RCCA1.m => 
       RCCA1.abort \/ mem t V.labels){2}.
  proof.
    fun.
    sp; if => //.
    inline{1} RO_KEF.extract; wp; sp.
    if{2}.
      if => //.
        by wp; rnd; skip; progress; smt.
        by wp; skip; progress; smt.
      if{1}.
        by rnd{1}; skip; progress; smt.
        by skip; progress; smt.
  qed.

  local equiv RCCA0_RCCA1 :
    RCCA0.main ~ RCCA1.main : true ==> !RCCA1.abort{2} => ={res}.
  proof.
    fun.
    swap{1} 11 -3; swap{2} 14 -6.
    seq 8 8 : 
     (={b} /\ pms{1} = V.pms{2} /\ c{1} = V.c{2} /\ (pv, h){1} = pp /\
      (!RCCA1.abort{2} =>
       ={glob A} /\ t{1} = V.t{2} /\ RO_KEF.m{1} = RCCA1.m{2} /\
       keypair(V.pk, V.sk){2} /\
       W.sk{1} = V.sk{2} /\ W.keys{1} = V.keys{2} /\ W.labels{1} = V.labels{2} /\
       (decrypt V.sk (fst pp) V.c = V.pms){2} /\
       (forall t, in_dom (snd pp, (V.pms, t)) RCCA1.m => mem t V.labels){2})).
      rnd; simplify.
      call (_:RCCA1.abort,
        keypair(V.pk, V.sk){2} /\
        !V.guess{2} /\ RO_KEF.m{1} = RCCA1.m{2} /\
        W.sk{1} = V.sk{2} /\ W.keys{1} = V.keys{2} /\ W.labels{1} = V.labels{2} /\
        (decrypt V.sk (fst pp) V.c = V.pms){2} /\
        (forall t, in_dom (snd pp, (V.pms, t)) RCCA1.m => 
           RCCA1.abort \/ mem t V.labels){2}).
      by apply lossless_choose.
      by apply RCCA0_RCCA1_dec.
      by progress; apply RCCA0_lossless_dec.
      by apply RCCA1_dec_preserves_abort.
      by apply RCCA0_RCCA1_extract.
      by progress; apply lossless_extract.
      by progress; fun; sp; if; try rnd; skip; smt. 
      seq 2 2 : 
       (pk{1} = V.pk{2} /\ W.sk{1} = V.sk{2} /\ keypair(V.pk, V.sk){2} /\
        RO_KEF.m{1} = Core.empty).
        inline MS_KEM.init RO_KEF.init MS_KEM.keygen; wp.
        by call keygen_spec_rel; wp; call (_:true).
        inline V.init; sp; exists * V.sk{2}, V.pk{2}; elim *; intros sk pk.
        by call (enc_spec_rel sk pk (fst pp)); skip; progress; smt.

      inline RO_KEF.extract; wp; sp.
      case RCCA1.abort{2}.
        (* abort *)
        call (_:RCCA1.abort, RCCA1.abort{2}).
          by apply lossless_guess.
          by exfalso; smt.
          by progress; apply RCCA0_lossless_dec.
          by apply RCCA1_dec_preserves_abort.
          by exfalso; smt.
          by progress; apply lossless_extract.
          by progress; fun; sp; if; try rnd; skip; smt.
        wp; rnd; wp; if{1}.
          by rnd; skip; smt.
          by rnd{2}; skip; smt.
        (* !abort *)
        case valid{1}.
          (* valid *)
          (* REMARK: here is where the validity condition is used *)
          rcondt{1} 1; first by intros _; skip; smt.
          call (_:RCCA1.abort,
           keypair(V.pk, V.sk){2} /\
           V.guess{2} /\ 
           W.sk{1} = V.sk{2} /\ W.keys{1} = V.keys{2} /\ W.labels{1} = V.labels{2} /\
           eq_except RO_KEF.m{1} RCCA1.m{2} (snd pp, (V.pms, V.t)){2} /\
           in_dom (snd pp, (V.pms, V.t)){2} RO_KEF.m{1} /\
           mem (proj RO_KEF.m{1}.[(snd pp, (V.pms, V.t))]){2} V.keys{2} /\
           decrypt V.sk{2} (fst pp) V.c{2} = V.pms{2}).
          by apply lossless_guess.
          by apply RCCA0_RCCA1_dec_upto.
          by progress; apply RCCA0_lossless_dec.
          by apply RCCA1_dec_preserves_abort.
          by apply RCCA0_RCCA1_extract_upto.
          by progress; apply lossless_extract.
          by intros _; fun; sp; if; try rnd; skip; smt.
          wp; case b{1}.
            by swap{2} 1; rnd; wp; rnd; skip; progress; smt.
            by rnd; wp; rnd; skip; progress; smt.
   
          (* !abort /\ !valid *)  
          call{1} (_:true ==> true).
            apply (lossless_guess RO_KEF RCCA0.O).
              by apply RCCA0_lossless_dec.
              by apply lossless_extract.
          call{2} (_:true ==> true).
            apply (lossless_guess RCCA1.O1 RCCA1.O2).
              by apply RCCA1_lossless_dec.
              by fun; sp; if => //; rnd; skip; smt.

      wp; rnd; wp; if{1}.
        by rnd; skip; progress; smt.
        by rnd{2}; skip; smt.
  qed.
  
  local lemma Pr_RCCA1_res : forall &m, 
    Pr[RCCA1.main() @ &m : res] <= 1%r / 2%r.
  proof.
    intros &m; bdhoare_deno (_:true) => //. 
    fun; rnd; simplify; call (_:true) => //.  
    wp; rnd; rnd; wp; call (_:true) => //.
    inline V.init; call (_:true); wp; call (_:true); wp; call (_:true).
    by skip; progress; try rewrite Bool.Dbool.mu_def; smt.
  qed.
  
  local lemma Pr_RCCA_RCCA1 : forall &m,
    Pr[RCCA(KEM(RO_KEF, PMS_KEM), A(RO_KEF)).main() @ &m : res] <=
    1%r / 2%r + Pr[RCCA1.main() @ &m : RCCA1.abort].
  proof.
   intros &m.
   apply (Trans _ Pr[RCCA0.main() @ &m : res]).
   equiv_deno RCCA_RCCA0 => //.
   apply (Trans _ Pr[RCCA1.main() @ &m : res \/ RCCA1.abort]).
     by equiv_deno RCCA0_RCCA1; smt.  
     by rewrite Pr mu_or; smt.
  qed.
  
  
  (** RCCA1 -> RCCA2 **)
  
  local module RCCA2 = {
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
              let (ms, pv, h, c) = proj d.[t] in p = h /\ decrypt V.sk pv c = pms) {
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
            if (in_dom (h, (decrypt V.sk pv c, t)) m) {
              k = proj m.[(h, (decrypt V.sk pv c, t))];
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
  
  local equiv RCCA1_RCCA2_extract : 
    RCCA1.O1.extract ~ RCCA2.O1.extract :
    ={p, s} /\ 
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt V.sk (fst pp) V.c = V.pms){2} /\ 
    (RCCA1.abort{1} =>
     (exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m \/
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
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt V.sk (fst pp) V.c = V.pms){2} /\ 
    (RCCA1.abort{1} =>
     (exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m \/
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
      sp; rcondf{2} 1.
        intros &1; skip; intros &2; progress.
        by cut W := H1 p{2} pms{2} t{2}; smt.   
      wp; rnd; skip; progress.
        by smt.   
        elim H8; clear H8; intros ?.
          cut W : abortL = true by smt; subst.
          by elim H; intros ? ?; exists t0; smt.       
        by exists t{2}; smt.   
        cut W := H1 h pms0 t0. 
        case (in_dom (h, (pms0, t0)) RCCA1.m{1}); first by smt.
        by intros ?; left; smt.
        elim H8; clear H8; intros ?.
          by case (in_dom (h, (pms0, t0)) RCCA2.m{2}); smt.
          cut W := H1 h pms0 t0.
          cut V : in_dom (h, (pms0, t0)) RCCA1.m{1}.
          by elim W; intros _ X; apply X; smt.
        by smt.
        by cut W := H2 h pms0 t0; smt.    
        by cut W := H1 h pms0 t0; cut X := H3 h pms0 t0; smt.
       
     if{2}.
       sp; rcondt{2} 1.
         by intros &1; skip; intros &2; progress; smt.
       wp; skip; progress.
         by smt.
         elim H6; clear H6; intros ?.
           cut W : abortL = true by smt; subst.
           by elim H; intros ? ?; exists t0; smt.       
         by exists t{2}; smt.
         by cut W := H1 h pms0 t0; smt. 
         elim H6; clear H6; intros ?.
         case (in_dom (h, (pms0, t0)) RCCA2.m{2}); first by smt.
         by intros ?; cut V : (h, (pms0, t0)) = (p, (pms, t)){2}; smt.
         cut W := H1 h pms0 t0.
         by elim W; intros _ X; apply X; smt.
         by smt.
         by smt.
      by wp; skip; smt.
  qed.
  
  local equiv RCCA1_RCCA2_dec :
    RCCA1.O2.dec ~ RCCA2.O2.dec : 
    ={p, t, c} /\ 
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt V.sk (fst pp) V.c = V.pms){2} /\ 
    (RCCA1.abort{1} =>
     (exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m \/
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
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt V.sk (fst pp) V.c = V.pms){2} /\ 
    (RCCA1.abort{1} =>
     (exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m \/
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
    inline{1} RCCA1.O1.extract.
    sp; if => //; first by smt.
      if{1}.
        if{2}.
          by exfalso; smt.
          wp; rnd; skip; progress.
            by smt.
            elim H12; clear H12; intros ?.
            cut X : abortL = true by smt; subst.
            by elim H; smt.
            by exists t{2}; right; smt.
            by smt.
            case (in_dom (h0, (pms0, t0)) RCCA1.m{1}); first by smt.
            by intros ?; cut Z : 
              (h0, (pms0, t0)) =
              (h{2}, (decrypt V.sk{2} pv{2} c{2}, t{2})); smt.
            elim H12; clear H12; intros ?; first by smt.
            case (t0 = t{2}).
              intros ?; subst; elim H12; clear H12; intros X Y.
              by generalize Y; rewrite /_.[_] Core.get_setE; smt.
              intros ?.
              cut L : (in_dom (h0, (pms0, t0)) RCCA1.m{1}); last by smt.
              rewrite H1.
              cut L : (in_dom t0 RCCA2.d{2} /\
                let (k0, pv0, h', c0) = proj RCCA2.d{2}.[t0] in
                  h0 = h' /\ decrypt V.sk{2} pv0 c0 = pms0).
              split; first by smt.
              by generalize H12; rewrite /_.[_] Core.get_setN; smt.
            by smt.
            by smt.
            by case ((h, (decrypt V.sk pv c, t)){2} = (h0, (pms0, t0))); smt.
    
      (* similarly *)
      rcondt{2} 1; first by intros &1; skip; intros &2; progress; smt.
      wp; skip; progress.
        by smt.
        elim H8; clear H8; intros ?.
        cut X : abortL = true by smt; subst.
        by elim H; smt.
        by exists t{2}; right; smt.         
        by smt.
        by smt.
        elim H8; clear H8; first by smt.
        case (t0 = t{2}); first by smt.
          intros ? [? ?].
          case ((h, (decrypt V.sk pv c, t)){2} = (h0, (pms0, t0))).
            by smt.
            intros ?; rewrite H1; right; split; first by smt.
            by generalize H10; rewrite /_.[_] Core.get_setN; smt.
        by smt.

      by skip; progress; smt.
  qed.
  
  local equiv RCCA1_RCCA2 :
    RCCA1.main ~ RCCA2.main : 
    true ==>
    RCCA1.abort{1} =>
      (exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m){2} \/
      (in_dom V.t RCCA2.d /\
       let (k, pv, h, c) = proj RCCA2.d.[V.t] in
         c <> V.c /\ decrypt V.sk pv c = V.pms){2}.
  proof.
    fun.
    rnd{1}.
    call (_:
     ={glob V} /\
     (V.guess{1} => ={V.t}) /\
     (decrypt V.sk (fst pp) V.c = V.pms){2} /\ 
     (RCCA1.abort{1} =>
      (exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m \/
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
     ={glob V} /\
     (V.guess{1} => ={V.t}) /\
     (decrypt V.sk (fst pp) V.c = V.pms){2} /\ 
     (RCCA1.abort{1} =>
      (exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m \/
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
    seq 2 2 : (={V.pk, V.sk} /\ keypair(V.pk, V.sk){1}).
      by call keygen_spec_rel; call (_:true); skip.
      exists * V.pk{1}, V.sk{1}; elim *; intros pk sk.
      call (enc_spec_rel sk pk (fst pp)).
      inline V.init; wp; skip; progress; smt.
  qed.
  
  local lemma Pr_RCCA1_RCCA2 : forall &m,
    Pr[RCCA1.main() @ &m : RCCA1.abort] <=
    Pr[RCCA2.main() @ &m : exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m] +  
    Pr[RCCA2.main() @ &m : let (k, pv, h, c) = proj RCCA2.d.[V.t] in
       c <> V.c /\ decrypt V.sk pv c = V.pms].
  proof.
    intros &m.
    apply (Trans _ 
      Pr[RCCA2.main() @ &m : 
       (exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m) \/
       let (k, pv, h, c) = proj RCCA2.d.[V.t] in
         c <> V.c /\ decrypt V.sk pv c = V.pms]).
      by equiv_deno RCCA1_RCCA2; smt.  
      rewrite Pr mu_or.
      cut X : forall (x y z), 0%r <= z => x <= y => x - z <= y by smt.
    by apply X; [smt | apply Refl].
  qed.
  
  
  (** RCCA2 -> OW_PCA **)
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
        maybe_pms = if found /\ h = h' /\ t = t' then Some pms else None; 
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
        maybe_pms = if found then Some pms else None; 
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
      var k' : pms;
      k' = decrypt PCA.V.sk t c;
      return (k' = k);
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

  local lemma check_spec : forall _k _t _c,
    bd_hoare 
    [ O.check : 
      k = _k /\ t = _t /\ c = _c ==>
      res <=> _k = decrypt PCA.V.sk _t _c ] = 1%r.
  proof.
    by progress; fun; wp.
  qed.
  
  local lemma find_any_spec : forall _pv _c,
    bd_hoare 
    [ Find(O).find_any : 
      pv = _pv /\ c = _c ==> 
      let pms = decrypt PCA.V.sk _pv _c in
       ((exists h t, in_dom (h, (pms, t)) Find.m) <=> res = Some pms) /\
       (res <> None => res = Some pms)] = 1%r.
  proof.
    progress; fun; sp.
    while  
     (let pms = decrypt PCA.V.sk pv c in
      (forall x, mem x q => in_dom x Find.m) /\
      (forall x, 
       in_dom x Find.m => !mem x q => maybe_pms = None => pms <> fst (snd x)) /\
      (maybe_pms <> None =>
       (exists h t, in_dom (h, (pms, t)) Find.m) /\ maybe_pms = Some pms))
     (card q).
       intros z; sp; wp. 
       exists * pms, pv, c; elim *; intros pms pv c.
       by call (check_spec pms pv c); skip; progress; smt. 
     by wp; skip; progress; smt.
  qed.
  
  local lemma find_spec : forall _pv _c _h _t,
    bd_hoare 
    [ Find(O).find : 
      pv = _pv /\ c = _c /\ h = _h /\ t = _t ==> 
      let pms = decrypt PCA.V.sk _pv _c in
       (in_dom (_h, (pms, _t)) Find.m <=> res = Some pms) /\
       (res <> None => res = Some pms) ] = 1%r.
  proof.
    progress; fun; sp.
    while  
     (let pms = decrypt PCA.V.sk pv c in
      (forall x, mem x q => in_dom x Find.m) /\
      (forall x, 
       in_dom x Find.m => !mem x q => maybe_pms = None => 
       x <> (h, (pms, t))) /\
      (maybe_pms <> None => 
       in_dom (h, (pms, t)) Find.m /\ 
       maybe_pms = Some pms /\ h = h' /\  t = t'))
     (card q).
      intros z; sp; wp. 
      exists * pms, pv, c; elim *; intros pms pv c.
      by call (check_spec pms pv c); skip; progress; smt. 
    by wp; skip; progress; smt.
  qed.
  
  local equiv RCCA2_OW_extract : 
    RCCA2.O1.extract ~ Find(O).O1.extract :
    ={p, s} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1}
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1}. 
  proof.
    fun.
    sp; if => //.
      seq 0 2 : 
       (={pms, t, p, s, V.keys, V.labels, V.guess, V.t, V.c} /\
        V.pk{1} = Find.pk{2} /\
        V.sk{1} = PCA.V.sk{2} /\ 
        RCCA2.m{1} = Find.m{2} /\ 
        RCCA2.d{1} = Find.d{2} /\
        decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1} /\ 
        ((in_dom t RCCA2.d /\ 
          let (ms, pv, h, c) = proj RCCA2.d.[t] in 
            p = h /\ decrypt V.sk pv c = pms){1} <=> 
         (in_dom t Find.d /\ p = h /\ found){2})).
        sp; exists * pms{2}, pv{2}, c{2}; elim *; intros pms pv c.
        by call{2} (check_spec pms pv c); skip; progress; smt.
        by if => //; wp; try rnd; skip; progress.
      by wp.
  qed.
  
  local equiv RCCA2_OW_dec : 
    RCCA2.O2.dec ~ Find(O).O2.dec :
    ={p, t, c} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1} 
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1}. 
  proof.
    fun.
    sp; if => //.
    sp; if => //.
    seq 0 1 :    
     (maybe_k{1} = None /\
      ={maybe_k, pv, h, p, t, c, V.labels, V.keys, V.guess, V.t, V.c} /\
      V.pk{1} = Find.pk{2} /\
      V.sk{1} = PCA.V.sk{2} /\
      RCCA2.m{1} = Find.m{2} /\ 
      RCCA2.d{1} = Find.d{2} /\
      decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1} /\
      !(V.guess /\ same_key V.pk (fst pp) pv c /\ h = snd pp /\ t = V.t /\ V.c = c){1} /\
      ((in_dom (h, (decrypt V.sk pv c, t)) RCCA2.m){1} <=> 
       maybe_pms{2} <> None) /\
      (maybe_pms <> None => 
       maybe_pms = Some (decrypt PCA.V.sk pv c)){2}).
      sp; exists * pv{2}, c{2}, h{2}, t{2}; elim *; intros pv c h t.
      by call{2} (find_spec pv c h t); skip; progress; smt.  
      if => //.
        by wp; skip; smt.
        by wp; rnd.
  qed.

  local equiv RCCA2_OW_extract_choose : 
    RCCA2.O1.extract ~ Find(O).O1.extract :
    ={p, s} /\ ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1}
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1}. 
  proof.
    fun.
    sp; if => //.
      seq 0 2 : 
       (={pms, t, p, s, V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
        V.sk{1} = PCA.V.sk{2} /\ 
        V.pk{1} = Find.pk{2} /\
        RCCA2.m{1} = Find.m{2} /\ 
        RCCA2.d{1} = Find.d{2} /\
        decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1} /\ 
        ((in_dom t RCCA2.d /\ 
          let (ms, pv, h, c) = proj RCCA2.d.[t] in 
            p = h /\ decrypt V.sk pv c = pms){1} <=> 
         (in_dom t Find.d /\ p = h /\ found){2})).
        sp; exists * pms{2}, pv{2}, c{2}; elim *; intros pms pv c.
        by call{2} (check_spec pms pv c); skip; progress; smt.
        by if => //; wp; try rnd; skip; progress.
      by wp.
  qed.

  local equiv RCCA2_OW_dec_choose : 
    RCCA2.O2.dec ~ Find(O).O2.dec :
    ={p, t, c} /\ ={V.keys, V.labels, V.guess, V.t} /\
    !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1} 
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t} /\
    !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1}. 
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
      RCCA2.m{1} = Find.m{2} /\ 
      RCCA2.d{1} = Find.d{2} /\
      decrypt V.sk{1} (fst pp) V.c{1} = V.pms{1} /\
      !(V.guess /\ same_key V.pk (fst pp) pv c /\ h = snd pp /\ t = V.t /\ V.c = c){1} /\
      ((in_dom (h, (decrypt V.sk pv c, t)) RCCA2.m){1} <=> 
       maybe_pms{2} <> None) /\
      (maybe_pms <> None => 
       maybe_pms = Some (decrypt PCA.V.sk pv c)){2}).
      sp; exists * pv{2}, c{2}, h{2}, t{2}; elim *; intros pv c h t.
      by call{2} (find_spec pv c h t); skip; progress; smt.  
      if => //.
        by wp; skip; smt.
        by wp; rnd.
  qed.

  local equiv RCCA2_OW :
    RCCA2.main ~ OW_PCA0.main :
    true ==> (exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m){1} => res{2}.
  proof.
   fun.
   inline OW_PCA0.B.choose OW_PCA0.B.guess.
   swap{2} [4..8] -1; wp.
   seq 6 8 :
     (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
      RCCA2.m{1} = Find.m{2} /\ RCCA2.d{1} = Find.d{2} /\
      V.pk{1} = Find.pk{2} /\ V.sk{1} = PCA.V.sk{2} /\ 
      pk0{2} = pk{2} /\ pk{2} = Find.pk{2} /\
      V.pms{1} = k{2} /\ V.c{1} = c{2} /\ 
      (decrypt V.sk (fst pp) V.c = V.pms){1}).
   seq 5 6 : (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
      RCCA2.m{1} = Find.m{2} /\ RCCA2.d{1} = Find.d{2} /\
      V.sk{1} = PCA.V.sk{2} /\ pk0{2} = pk{2} /\ V.pk{1} = pk{2} /\
      keypair(V.pk, V.sk){1}).
   by inline V.init; wp; call keygen_spec_rel; call (_:true).
   exists * V.sk{1}, V.pk{1}; elim *; intros sk pk.
   call (enc_spec_rel sk pk (fst pp)); wp; skip; progress; smt.

   seq 6 9 : (={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\ V.sk{1} = PCA.V.sk{2} /\ 
    pk0{2} = pk{2} /\ pk{2} = Find.pk{2} /\
    V.pms{1} = k{2} /\ V.c{2} = c0{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = V.pms){1}).
   call (_: ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = V.pms){1}).
     by apply RCCA2_OW_dec.
     by apply RCCA2_OW_extract.
    wp; rnd; rnd; wp.
   call (_: ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = V.pms){1}).
     by apply RCCA2_OW_dec_choose.
     by apply RCCA2_OW_extract_choose.
   skip; progress.

    wp; exists * c0{2}; elim *; intros c.
    call{2} (find_any_spec (fst pp) c).
    by wp; skip; progress; smt.
  qed.
  
  local lemma Pr_RCCA2_OW : forall &m,
    Pr[RCCA2.main() @ &m : exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m] <=
    Pr[PCA.OW_PCA(PMS_KEM, B).main() @ &m : res].
  proof.
    intros &m.
    apply (Trans _ Pr[OW_PCA0.main() @ &m : res]).
    by equiv_deno RCCA2_OW.
    by equiv_deno OW_PCA0_OW_PCA.
  qed.
  
  
  (** RCCA2 -> NR *)

  (* REMARK: the condition !mem t labels in the decryption oracle in
   * the RCCA game could be dropped. A similar reduction to NR-PCA
   * would work, but the map d would no longer be functional on t, and so
   * the NR adversary would have to choose one decryption query for the
   * challenge label at random, incurring a q_dec loss factor.
   *)

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
      var k, k' : pms;
      var c, c' : ciphertext;
      PMS_KEM.init();
      (pk, PCA.V.sk) = PMS_KEM.keygen();
      (k, c) = PMS_KEM.enc((), pk, fst pp);
      t = C.choose(pk);
      (t', c') = C.guess(c);
      k' = PMS_KEM.dec((), PCA.V.sk, t', c');
      return (c <> c' /\ k' = k);
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
  
  local equiv RCCA2_NR :
    RCCA2.main ~ NR_PCA0.main :
    true ==> 
    (let (k, pv, h, c) = proj RCCA2.d.[V.t] in
       c <> V.c /\ decrypt V.sk pv c = V.pms){1} => res{2}.
  proof.
   fun.
   inline NR_PCA0.C.choose NR_PCA0.C.guess.
   swap{2} [4..8] -1; wp.
   seq 6 8 :
     (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
      RCCA2.m{1} = Find.m{2} /\ RCCA2.d{1} = Find.d{2} /\
      V.sk{1} = PCA.V.sk{2} /\ 
      V.pk{1} = pk{2} /\ pk0{2} = pk{2} /\ pk{2} = Find.pk{2} /\
      V.pms{1} = k{2} /\ V.c{1} = c{2} /\ 
      (decrypt V.sk (fst pp) V.c = V.pms){1}).
   seq 5 7 : (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
      RCCA2.m{1} = Find.m{2} /\ RCCA2.d{1} = Find.d{2} /\
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
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = V.pms){1}).
   call (_: ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = V.pms){1}).
     by apply RCCA2_OW_dec.
     by apply RCCA2_OW_extract.
    wp; rnd; rnd; wp.
   call (_: ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\ 
    RCCA2.m{1} = Find.m{2} /\ 
    RCCA2.d{1} = Find.d{2} /\
    (decrypt V.sk (fst pp) V.c = V.pms){1}).
     by apply RCCA2_OW_dec_choose.
     by apply RCCA2_OW_extract_choose.
   skip; progress.

    sp; wp; exists * PCA.V.sk{2}, t'{2}, c'{2}; elim *; intros sk pv c.
    call{2} (dec_spec sk pv c).
    by skip; progress; smt.
  qed.
  
  local lemma Pr_RCCA2_NR : forall &m,
    Pr[RCCA2.main() @ &m : let (k, pv, h, c) = proj RCCA2.d.[V.t] in
       c <> V.c /\ decrypt V.sk pv c = V.pms] <=
    Pr[PCA.NR_PCA(PMS_KEM, C).main() @ &m : res].
  proof.
    intros &m.
    apply (Trans _ Pr[NR_PCA0.main() @ &m : res]).
    by equiv_deno RCCA2_NR.
    by equiv_deno NR_PCA0_NR_PCA.
  qed.
  
  (** Conclusion **)
  lemma Conclusion : forall &m,
    exists (B <: PCA.OW_Adversary {PCA.V}) 
           (C <: PCA.NR_Adversary {PCA.V}),
     Pr[RCCA(KEM(RO_KEF, PMS_KEM), A(RO_KEF)).main() @ &m : res] - 1%r / 2%r <=
     Pr[PCA.OW_PCA(PMS_KEM, B).main() @ &m : res] +
     Pr[PCA.NR_PCA(PMS_KEM, C).main() @ &m : res].
  proof.
    intros &m; exists B, C.
    cut X : forall (x y z), 0%r <= z => x <= y + z => x - y <= z by smt.
    apply X; first by smt.
    apply (Trans _ (1%r / 2%r + Pr[RCCA1.main() @ &m : RCCA1.abort]));
    first by apply (Pr_RCCA_RCCA1 &m).
    apply addleM => //.
    apply (Trans _
      (Pr[RCCA2.main() @ &m : exists t, in_dom (snd pp, (V.pms, t)) RCCA2.m] +  
       Pr[RCCA2.main() @ &m : let (k, pv, h, c) = proj RCCA2.d.[V.t] in
          c <> V.c /\ decrypt V.sk pv c = V.pms])).
    by apply (Pr_RCCA1_RCCA2 &m).
    apply addleM.
      by apply (Pr_RCCA2_OW &m).
      by apply (Pr_RCCA2_NR &m).
  qed.

end section.

print axiom Conclusion.
