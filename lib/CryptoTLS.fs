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

let rsa_decrypt key data =
    try
        correct (Crypto.rsa_decrypt key data)
    with
        | _ -> Error (Encryption, Internal)

(* No padding encryption/decryption functions *)
let aes_encrypt_wiv_nopad_raw (k:Crypto.key) (iv:bytes) (plain:bytes) = 
  match k with 
      Crypto.SymKey key ->
        let rij = new System.Security.Cryptography.RijndaelManaged() in
        let keyl = 8 * key.Length  in
        rij.set_KeySize(keyl);
        rij.Padding <- System.Security.Cryptography.PaddingMode.None
        let enc = rij.CreateEncryptor(key,iv) in
        let mems = new System.IO.MemoryStream() in
        let crs = new System.Security.Cryptography.CryptoStream(mems,enc,System.Security.Cryptography.CryptoStreamMode.Write) in
        let _ =  crs.Write(plain,0,plain.Length) in
        let _ = crs.FlushFinalBlock() in
        let cipher = mems.ToArray() in
        mems.Close();
        crs.Close();
        cipher
    | _ -> failwith "AES only defined for symmetric keys"

let aes_encrypt_wiv_nopad key iv data =
    try
        correct (aes_encrypt_wiv_nopad_raw key iv data)
    with
        | _ -> Error (Encryption, Internal)

let aes_decrypt_wiv_nopad_raw (k:Crypto.key) (iv:bytes) (cipher:bytes) = 
  match k with 
      Crypto.SymKey key ->
        let rij = new System.Security.Cryptography.RijndaelManaged() in
        let keyl = 8 * key.Length  in
        rij.set_KeySize(keyl);
        rij.Padding <- System.Security.Cryptography.PaddingMode.None;
        let dec = rij.CreateDecryptor(key,iv) in
        let mems = new System.IO.MemoryStream(cipher) in
        let crs = new System.Security.Cryptography.CryptoStream(mems,dec,System.Security.Cryptography.CryptoStreamMode.Read) in
        let plain = Array.zeroCreate(cipher.Length) in  
        let _ =  crs.Read(plain,0,plain.Length) in
        plain
    | _ -> failwith "AES only defined for symmetric keys"

let aes_decrypt_wiv_nopad key iv data =
    try
        correct(aes_decrypt_wiv_nopad_raw key iv data)
    with
        | _ -> Error(Encryption,Internal)

let des_encrypt_wiv_nopad_raw (k:Crypto.key) (iv:bytes) (plain:bytes) = 
  match k with 
      Crypto.SymKey key ->        
        let des = new System.Security.Cryptography.DESCryptoServiceProvider() in
        //let keyl = 8 * key.Length  in
        //let block = 8 in (* 64 bits *)
        //des.set_KeySize(keyl);
        //print_any (des.get_Padding());
        des.Padding <- System.Security.Cryptography.PaddingMode.None
        let enc = des.CreateEncryptor(key,iv) in
        let mems = new System.IO.MemoryStream() in
        let crs = new System.Security.Cryptography.CryptoStream(mems,enc,System.Security.Cryptography.CryptoStreamMode.Write) in
        let _ =  crs.Write(plain,0,plain.Length) in
        let _ = crs.FlushFinalBlock() in 
        let cip = mems.ToArray() in
        mems.Close();
        crs.Close();
        cip
    | _ -> failwith "DES only defined for symmetric keys"

let des_encrypt_wiv_nopad key iv data =
    try
        correct (des_encrypt_wiv_nopad_raw key iv data)
    with
        | _ -> Error (Encryption, Internal)

let des_decrypt_wiv_nopad_raw (k:Crypto.key) (iv:bytes) (cipher:bytes) = 
  match k with 
      Crypto.SymKey key ->
        let des = new System.Security.Cryptography.DESCryptoServiceProvider() in
        //let keyl = 8 * key.Length  in
        //des.set_KeySize(keyl);*)
        //let block = 8 in (* 64 bits *)
        //print_any (des.get_Padding());
        des.Padding <- System.Security.Cryptography.PaddingMode.None
        let dec = des.CreateDecryptor(key,iv) in
        let mems = new System.IO.MemoryStream(cipher) in
        let crs = new System.Security.Cryptography.CryptoStream(mems,dec,System.Security.Cryptography.CryptoStreamMode.Read) in
        let plain = Array.zeroCreate(cipher.Length) in 
        let _ =  crs.Read(plain,0,plain.Length) in
        mems.Close();
        crs.Close();
        plain
    | _ -> failwith "DES only defined for symmetric keys"

let des_decrypt_wiv_nopad key iv data =
    try
        correct (des_decrypt_wiv_nopad_raw key iv data)
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
(* FIXME: the used hash algorithm should depend on the ciphersuite.
   (function prfHashFun_of_ciphersuite already available)
   Now it is fixed to sha256 *)
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