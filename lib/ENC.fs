module ENC

open Bytes
open Error
open Algorithms
open CipherSuites
open TLSInfo
open Formats

type cipher = bytes

(* Raw symmetric functions for encryption and decryption.
   Although in principle their concrete implementations may throw exceptions,
   we claim they can never do that:
   ArgumentException:           we always pass a readable/writable and valid stream
   NotSupportedException:       we always give a writable (readable) stream to write (read)
   ArgumentOutOfRangeException: data.Length is always greater than zero
   ArgumentException:           0+data.Length is never longer than data.Length
   CryptographicException:      The key is never corrupt
*)

let symEncrypt enc data =
    let mems = new System.IO.MemoryStream() in
    let crs = new System.Security.Cryptography.CryptoStream(mems,enc,System.Security.Cryptography.CryptoStreamMode.Write) in
    crs.Write(data,0,data.Length) 
    crs.FlushFinalBlock() 
    let cipher = mems.ToArray() in
    mems.Close();
    crs.Close();
    cipher

let symDecrypt dec (data:bytes) =
    let mems = new System.IO.MemoryStream(data) in
    let crs = new System.Security.Cryptography.CryptoStream(mems,dec,System.Security.Cryptography.CryptoStreamMode.Read) in
    let plain = Array.zeroCreate(data.Length) in  
    let _ =  crs.Read(plain,0,plain.Length) in
    plain

let aesEncrypt ki key iv data =
    let aes = new System.Security.Cryptography.AesManaged() in
    aes.KeySize <- 8 * length key
    aes.Padding <- System.Security.Cryptography.PaddingMode.None
    let enc = aes.CreateEncryptor(key,iv) in
    symEncrypt enc data

let aesDecrypt ki key iv (data:bytes) =
    let aes = new System.Security.Cryptography.AesManaged() in
    aes.KeySize <- 8 * length key
    aes.Padding <- System.Security.Cryptography.PaddingMode.None;
    let dec = aes.CreateDecryptor(key,iv) in
    symDecrypt dec data
       
let tdesEncrypt ki key iv data =
    let tdes = new System.Security.Cryptography.TripleDESCryptoServiceProvider() in
    tdes.Padding <- System.Security.Cryptography.PaddingMode.None
    let enc = tdes.CreateEncryptor(key,iv) in
    symEncrypt enc data

let tdesDecrypt ki key iv (data:bytes) =
    let tdes = new System.Security.Cryptography.TripleDESCryptoServiceProvider() in
    tdes.Padding <- System.Security.Cryptography.PaddingMode.None;
    let dec = tdes.CreateDecryptor(key,iv) in
    symDecrypt dec data

let rc4Encrypt (ki:epoch) (state:ManagedRC4.RC4) data =
    let res = Array.copy data in
    state.Encrypt(res,uint32 (length res));
    res

let rc4Decrypt (ki:epoch) (state:ManagedRC4.RC4) data =
    let res = Array.copy data in
    state.Decrypt(res,uint32 (length res));
    res

(* Early TLS chains IVs but this is not secure against adaptive CPA *)
let lastblock cipher ivl =
    let (_,b) = split cipher (length cipher - ivl) in b

type key = {k:bytes}

type iv = bytes
type iv3 =
    | SomeIV of iv
    | NoIV of bool

type blockState =
    {key: key;
     iv: iv3}
type streamState = 
    {skey: key; // Ghost: Only stored so that we can LEAK it
     sstate: ManagedRC4.RC4}

type state =
    | BlockCipher of blockState
    | StreamCipher of streamState
type encryptor = state
type decryptor = state

let GENOne ki =
    let si = epochSI(ki) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    match alg with
    | RC4_128 ->
        let k = mkRandom (encKeySize alg) in
        let rc4 = new ManagedRC4.RC4() in
        rc4.Init(k,uint32 (length k));
        let key = {k = k} in
        StreamCipher({skey = key; sstate = rc4})
    | _ ->
    let key =
        {k = mkRandom (encKeySize alg)}
    let iv =
        match si.protocol_version with
        | SSL_3p0 | TLS_1p0 ->
            SomeIV(mkRandom (ivSize alg))
        | TLS_1p1 | TLS_1p2 ->
            NoIV(true)
    BlockCipher ({key = key; iv = iv})

let GEN (ki) = (GENOne ki, GENOne ki)
    
let COERCE (ki:epoch) k iv =
    let si = epochSI(ki) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    match alg with
    | RC4_128 ->
        let rc4 = new ManagedRC4.RC4() in
        rc4.Init(k,uint32 (length k));
        let key = {k = k} in
        StreamCipher({skey = key; sstate = rc4})
    | _ ->
    let ivOpt =
        match si.protocol_version with
        | SSL_3p0 | TLS_1p0 ->
            SomeIV(iv)
        | TLS_1p1 | TLS_1p2 ->
            NoIV(true)
    BlockCipher ({key = {k=k}; iv = ivOpt})

let LEAK (ki:epoch) s =
    match s with
    | BlockCipher (bs) ->
        let iv =
            match bs.iv with
            | NoIV(_) -> [||]
            | SomeIV(iv) -> iv
        (bs.key.k,iv)
    | StreamCipher (ss) ->
        ss.skey.k,[||]

(* Parametric ENC/DEC functions *)
let ENC ki s tlen data =
    let si = epochSI(ki) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    let d = AEPlain.repr ki tlen data in
    match s with
    | BlockCipher(s) ->
        let ivl = ivSize alg in
        let iv =
            match s.iv with
            | SomeIV(b) -> b
            | NoIV _    -> mkRandom ivl in
        let cipher =
            match alg with
            | TDES_EDE_CBC -> tdesEncrypt ki s.key.k iv d
            | AES_128_CBC  -> aesEncrypt  ki s.key.k iv d
            | AES_256_CBC  -> aesEncrypt  ki s.key.k iv d
            | RC4_128      -> unexpectedError "[ENC] Wrong combination of cipher algorithm and state"
        match s.iv with
        | SomeIV(_) ->
            if length cipher <> tlen || tlen > DataStream.max_TLSCipher_fragment_length then
                // unexpected, because it is enforced statically by the
                // CompatibleLength predicate
                unexpectedError "[ENC] Length of encrypted data do not match expected length"
            else
                let s = {s with iv = SomeIV(lastblock cipher ivl) } in
                (BlockCipher(s), cipher)
        | NoIV(b) ->
            let res = iv @| cipher in
            if length res <> tlen || tlen > DataStream.max_TLSCipher_fragment_length then
                // unexpected, because it is enforced statically by the
                // CompatibleLength predicate
                unexpectedError "[ENC] Length of encrypted data do not match expected length"
            else
                let s = {s with iv = NoIV(b)} in
                (BlockCipher(s), res)
    | StreamCipher(s) ->
        let cipher = 
            match alg with
            | RC4_128 -> rc4Encrypt ki s.sstate d
            | _ -> unexpectedError "[ENC] Wrong combination of cipher algorithm and state"
        if length cipher <> tlen || tlen > DataStream.max_TLSCipher_fragment_length then
                // unexpected, because it is enforced statically by the
                // CompatibleLength predicate
                unexpectedError "[ENC] Length of encrypted data do not match expected length"
        else
            (StreamCipher(s),cipher)

let DEC ki s cipher =
    let si = epochSI(ki) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    match s with
    | BlockCipher(s) ->
        let ivl = ivSize alg 
        let (iv,encrypted) =
            match s.iv with
            | SomeIV (iv) -> (iv,cipher)
            | NoIV (b)    -> split cipher ivl
        let data =
            match alg with
            | TDES_EDE_CBC -> tdesDecrypt ki s.key.k iv encrypted
            | AES_128_CBC  -> aesDecrypt  ki s.key.k iv encrypted
            | AES_256_CBC  -> aesDecrypt  ki s.key.k iv encrypted
            | RC4_128      -> unexpectedError "[DEC] Wrong combination of cipher algorithm and state"
        let d = AEPlain.plain ki (length cipher) data in
        match s.iv with
        | SomeIV(_) ->
            let s = {s with iv = SomeIV(lastblock cipher ivl)} in
            (BlockCipher(s), d)
        | NoIV(b)   ->
            let s = {s with iv = NoIV(b)} in
            (BlockCipher(s), d)
    | StreamCipher(s) ->
        let data = 
            match alg with
            | RC4_128 -> rc4Decrypt ki s.sstate cipher
            | _ -> unexpectedError "[DEC] Wrong combination of cipher algorithm and state"
        let d = AEPlain.plain ki (length cipher) data in
        (StreamCipher(s),d)

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
#if aes
let F = AES k
let G = AESminus k 
#else
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
#endif
let enc p = incr qe; F p
let dec c = incr qd; G c
*)
