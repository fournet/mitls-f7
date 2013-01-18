module ENC

open Bytes
open Error
open TLSConstants
open TLSInfo

(* We do not open Encode so that we can syntactically check its usage restrictions *) 

type cipher = bytes

(* Early TLS chains IVs but this is not secure against adaptive CPA *)
let lastblock cipher alg =
    let ivl = blockSize alg in
    let (_,b) = split cipher (length cipher - ivl) in b

type key = {k:bytes}

type iv = bytes
type iv3 =
    | SomeIV of iv
    | NoIV

type blockState =
    {key: key;
     iv: iv3}
type streamState = 
    {skey: key; // Ghost: Only stored so that we can LEAK it
     sstate: CoreCiphers.rc4engine}

type state =
    | BlockCipher of blockState
    | StreamCipher of streamState
type encryptor = state
type decryptor = state

let GENOne ki =
    let si = epochSI(ki) in
    let alg = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match alg with
    | Stream_RC4_128 ->
        let k = Nonce.mkRandom (encKeySize alg) in
        let key = {k = k} in
        StreamCipher({skey = key; sstate = CoreCiphers.rc4create k})
    | CBC_Stale(cbc) ->
        let key = {k = Nonce.mkRandom (encKeySize alg)}
        let iv = SomeIV(Nonce.mkRandom (blockSize cbc))
        BlockCipher ({key = key; iv = iv})
    | CBC_Fresh(_) ->
        let key = {k = Nonce.mkRandom (encKeySize alg)}
        let iv = NoIV
        BlockCipher ({key = key; iv = iv})

let GEN (ki) = let k = GENOne ki in (k,k)
    
let COERCE (ki:epoch) k iv =
    let si = epochSI(ki) in
    let alg = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match alg with
    | Stream_RC4_128 ->
        let key = {k = k} in
        StreamCipher({skey = key; sstate = CoreCiphers.rc4create k})
    | CBC_Stale(_) ->
        BlockCipher ({key = {k=k}; iv = SomeIV(iv)})
    | CBC_Fresh(_) ->
        BlockCipher ({key = {k=k}; iv = NoIV})

let LEAK (ki:epoch) s =
    match s with
    | BlockCipher (bs) ->
        let iv =
            match bs.iv with
            | NoIV -> [||]
            | SomeIV(iv) -> iv
        (bs.key.k,iv)
    | StreamCipher (ss) ->
        ss.skey.k,[||]

let enc_int alg k iv d =
    match alg with
    | TDES_EDE -> CoreCiphers.des3_cbc_encrypt k iv d
    | AES_128 | AES_256  -> CoreCiphers.aes_cbc_encrypt  k iv d

(* Parametric ENC/DEC functions *)
let ENC ki s tlen data =
    let si = epochSI(ki) in
    let encAlg = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    let d = Encode.repr ki tlen data in
    match s,encAlg with
    | BlockCipher(s), CBC_Stale(alg) ->
        match s.iv with
        | NoIV -> unexpectedError "[ENC] Wrong combination of cipher algorithm and state"
        | SomeIV(iv) ->
            let cipher = enc_int alg s.key.k iv d
            if length cipher <> tlen || tlen > max_TLSCipher_fragment_length then
                // unexpected, because it is enforced statically by the
                // CompatibleLength predicate
                unexpectedError "[ENC] Length of encrypted data do not match expected length"
            else
                let s = {s with iv = SomeIV(lastblock cipher alg) } in
                (BlockCipher(s), cipher)
    | BlockCipher(s), CBC_Fresh(alg) ->
        match s.iv with
        | SomeIV(b) -> unexpectedError "[ENC] Wrong combination of cipher algorithm and state"
        | NoIV   ->
            let ivl = blockSize alg in
            let iv = Nonce.mkRandom ivl in
            let cipher = enc_int alg s.key.k iv d
            let res = iv @| cipher in
            if length res <> tlen || tlen > max_TLSCipher_fragment_length then
                // unexpected, because it is enforced statically by the
                // CompatibleLength predicate
                unexpectedError "[ENC] Length of encrypted data do not match expected length"
            else
                let s = {s with iv = NoIV} in
                (BlockCipher(s), res)
    | StreamCipher(s), Stream_RC4_128 ->
        let cipher = CoreCiphers.rc4process s.sstate d in
        if length cipher <> tlen || tlen > max_TLSCipher_fragment_length then
                // unexpected, because it is enforced statically by the
                // CompatibleLength predicate
                unexpectedError "[ENC] Length of encrypted data do not match expected length"
        else
            (StreamCipher(s),cipher)
    | _, _ -> unexpectedError "[ENC] Wrong combination of cipher algorithm and state"

let dec_int alg k iv e =
    match alg with
    | TDES_EDE -> CoreCiphers.des3_cbc_decrypt k iv e
    | AES_128 | AES_256  -> CoreCiphers.aes_cbc_decrypt k iv e

let DEC ki s cipher =
    let si = epochSI(ki) in
    let encAlg = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match s, encAlg with
    | BlockCipher(s), CBC_Stale(alg) ->
        match s.iv with
        | NoIV -> unexpectedError "[DEC] Wrong combination of cipher algorithm and state"
        | SomeIV(iv) ->
            let data = dec_int alg s.key.k iv cipher
            let d = Encode.plain ki (length cipher) data in
            let s = {s with iv = SomeIV(lastblock cipher alg)} in
            (BlockCipher(s), d)
    | BlockCipher(s), CBC_Fresh(alg) ->
        match s.iv with
        | SomeIV(_) -> unexpectedError "[DEC] Wrong combination of cipher algorithm and state"
        | NoIV ->
            let ivL = blockSize alg in
            let (iv,encrypted) = split cipher ivL in
            let data = dec_int alg s.key.k iv encrypted in
            let d = Encode.plain ki (length cipher) data in
            let s = {s with iv = NoIV} in
            (BlockCipher(s), d)
    | StreamCipher(s), Stream_RC4_128 ->
        let data = CoreCiphers.rc4process s.sstate cipher
        let d = Encode.plain ki (length cipher) data in
        (StreamCipher(s),d)
    | _,_ -> unexpectedError "[DEC] Wrong combination of cipher algorithm and state"

(* the SPRP game in F#, without indexing so far.
   the adversary gets 
   enc: block -> block
   dec: block -> block 

// two copies of assoc 
let rec findp pcs c = 
  match pcs with 
  | (p,c')::pcs -> if c = c' then Some(p) else findp pcs c
  | [] -> None
let rec findc pcs p = 
  match pcs with 
  | (p',c)::pcs -> if p = p' then Some(c) else findc pcs p
  | [] -> None
   
let k = mkRandom blocksize
let qe = ref 0
let qd = ref 0
#if ideal
let log = ref ([] : (block * block) list)
let F p = 
  match findc !pcs p with 
  | Some(c) -> c // non-parametric; 
                 // after CBC-collision avoidance,
                 // we will always use the "None" case
  | None    -> let c = mkfreshc !log blocksize 
               log := (p,c)::!log
               c
let G c = 
  match findp !log c with 
  | Some(p) -> p 
  | None    -> let p = mkfreshp !log blocksize 
               log := (p,c)::!log
               p
#else
let F = AES k
let G = AESminus k
#endif
let enc p = incr qe; F p
let dec c = incr qd; G c
*)
