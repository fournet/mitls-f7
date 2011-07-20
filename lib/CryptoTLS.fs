module CryptoTLS

open Data
open Error_handling

let symkey b = Crypto.symkey b
let symkeytobytes s = Crypto.symkeytobytes s

let hmacsha1 k b =
    try
        correct (Crypto.hmacsha1 k b)
    with
        | _ -> Error (MAC, Internal)

let hmacsha1Verify k b h =
    match hmacsha1 k b with
    | Error (x,y) -> Error (x,y)
    | Correct d ->
        if equalBytes d h then
            correct ()
        else
            Error (MAC, CheckFailed)

let hmacmd5 k b =
    try
        correct (Crypto.hmacmd5 k b)
    with
        | _ -> Error (MAC, Internal)


let hmacmd5Verify k b h =
    match hmacmd5 k b with
    | Error (x,y) -> Error (x,y)
    | Correct d ->
        if equalBytes d h then
            correct ()
        else
            Error (MAC, CheckFailed)

let keyedHash h_fun pad1 pad2 k b =
    let k = symkeytobytes k in
    let d = Formats.appendList [k; pad1; b] in
    match h_fun d with
    | Error (Hash,y) -> Error (MAC,y)
    | Error (x,y) -> unexpectedError "Only Hash errors should be risen by hash functions"
    | Correct step1 ->
        let msg = Formats.appendList [k; pad2; step1] in
        match h_fun msg with
        | Error (Hash,y) -> Error (MAC,y)
        | Error (x,y) -> unexpectedError "Only Hash errors should be risen by hash functions"
        | Correct res -> correct (res)

let keyedHashVerify h_fun pad1 pad2 k b orig =
    match keyedHash h_fun pad1 pad2 k b with
    | Error (x,y) -> Error (x,y)
    | Correct res ->
        if equalBytes res orig then
            correct ()
        else
            Error (MAC, CheckFailed)

let md5 x =
    try
        correct (Crypto.md5 x)
    with
        | _ -> Error (Hash, Internal)

let sha1 x =
    try
        correct (Crypto.sha1 x)
    with
        | _ -> Error (Hash, Internal)

let sha256 x =
    try
        correct (Crypto.sha256 x)
    with
        | _ -> Error (Hash,Internal)

let sha384 (x:bytes) =
    try
        let sha_instance = System.Security.Cryptography.SHA384.Create () in
        correct (sha_instance.ComputeHash x)
    with
        | _ -> Error (Hash,Internal)

let sha512 (x:bytes) =
    try
        let sha_instance = System.Security.Cryptography.SHA512.Create () in
        correct (sha_instance.ComputeHash x)
    with
        | _ -> Error (Hash,Internal)

let des_encrypt_wiv key iv data =
    try
        correct (Crypto.des_encrypt_wiv key iv data)
    with
        | _ -> Error (Encryption, Internal)

let aes_encrypt_wiv key iv data =
    try
        correct (Crypto.aes_encrypt_wiv key iv data)
    with
        | _ -> Error (Encryption, Internal)

let des_decrypt_wiv key iv data =
    try
        correct (Crypto.des_decrypt_wiv key iv data)
    with
        | _ -> Error (Encryption, Internal)

let aes_decrypt_wiv key iv data =
    try
        correct (Crypto.aes_decrypt_wiv key iv data)
    with
        | _ -> Error (Encryption, Internal)

let rsa_encrypt key data =
    try
        correct (Crypto.rsa_encrypt key data)
    with
        | _ -> Error (Encryption, Internal)

(* Low level TLS 1.2 functions *)
let hmacsha256_raw (k:Crypto.key) (x:bytes) : bytes = 
  match k with 
    | Crypto.SymKey key -> (new System.Security.Cryptography.HMACSHA256(key)).ComputeHash x
    | _ -> failwith "HMAC-SHA256 only defined for symmetric keys"

let p_sha256_raw secret seed nb = 
  let it = (nb/32)+1 in
  let res = Array.zeroCreate nb in
    let a = ref seed in
    for i=0 to it-2 do
      a := hmacsha256_raw secret !a;
      Array.blit (hmacsha256_raw secret (append !a seed)) 0 res (i*32) 32;
    done;
    a := hmacsha256_raw secret !a;
    let r=nb%32 in
    Array.blit (hmacsha256_raw secret (append !a seed)) 0 res (nb-r) r;
    res

let tls12prf_raw (secret:bytes) (label:str) (seed:bytes) (nb:int) =
  let newseed = append (utf8 label) seed in
  p_sha256_raw (symkey secret) newseed nb

(* TLS 1.2 PRF *)
let tls12prf (secret:bytes) (label:str) (seed:bytes) (nb:int) =
    try
        correct (tls12prf_raw secret label seed nb)
    with
        | _ -> Error (Encryption, Internal)


(* TLS 1.0 and 1.1 PRF *)
let prf (secret:bytes) (label:str) (seed:bytes) (nb:int) =
    try
        correct (Crypto.prf secret label seed nb)
    with
        | _ -> Error (Encryption, Internal)

(* Low-level SSL 3.0 functions *)
let ssl_prf1_raw secret label seed = Crypto.md5 (append secret (Crypto.sha1 (append (utf8 label) (append secret seed))))

let ssl_prf_raw secret seed nb = 
  let gen_label (i:int) = (*str (make_string (i+1) (char_of_int ((int_of_char 'A') + i))) *)
        new System.String(char((int 'A')+i),i+1) in
  let rec apply_prf res n = 
    if n > nb then 
      Array.sub res 0 nb
    else apply_prf (append res (ssl_prf1_raw secret (gen_label (n/16)) seed)) (n+16)
  in
  apply_prf (Array.zeroCreate 0) 0

(* SSL 3.0 PRF *)
let ssl_prf secret seed nb =
    try
        correct (ssl_prf_raw secret seed nb)
    with
        | _ -> Error (Encryption,Internal)