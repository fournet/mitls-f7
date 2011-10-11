module StdCrypto

open Data
open Error_handling
open Algorithms

type macKey = bytes
type symKey = bytes

(* Raw hash algorithms -- can throw exceptions *)
let md5Instance = System.Security.Cryptography.MD5.Create ()
let md5 (x:bytes) : bytes = md5Instance.ComputeHash x

let sha1Instance = System.Security.Cryptography.SHA1.Create ()
let sha1 (x:bytes) : bytes = sha1Instance.ComputeHash x

let sha256Instance = System.Security.Cryptography.SHA256.Create ()
let sha256 (x:bytes) : bytes = sha256Instance.ComputeHash x

let sha384Instance = System.Security.Cryptography.SHA384.Create ()
let sha384 (x:bytes) : bytes = sha384Instance.ComputeHash x

(* Parametric hash algorithm (implements interface) *)
let hash alg data =
    try
        match alg with
        | MD5    -> correct (md5 data)
        | SHA    -> correct (sha1 data)
        | SHA256 -> correct (sha256 data)
        | SHA384 -> correct (sha384 data)
    with
    | _ -> Error (Hash, Internal)

(* Raw hmac algorithms -- can throw exceptions *)
let hmacmd5 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACMD5 (key) in
    hmacobj.ComputeHash (data)

let hmacsha1 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA1 (key) in
    hmacobj.ComputeHash (data)

let hmacsha256 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA256 (key) in
    hmacobj.ComputeHash (data)

let hmacsha384 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA384 (key) in
    hmacobj.ComputeHash (data)

(* Parametric hmac algorithms (implement interface) *)
let hmac alg key data =
    try
        match alg with
        | MD5    -> correct (hmacmd5 key data)
        | SHA    -> correct (hmacsha1 key data)
        | SHA256 -> correct (hmacsha256 key data)
        | SHA384 -> correct (hmacsha384 key data)
    with
    | _ -> Error (MAC, Internal)

let hmacVerify alg key data expected =
    match hmac alg key data with
    | Correct (result) ->
        if equalBytes result expected then
            correct ()
        else
            Error (MAC, CheckFailed)
    | Error (x,y) -> Error(x,y)

(* Raw SSL-specific keyed hash algorithm -- can throw exceptions *)
let ssl_pad1_md5  = Bytearray.createBytes 48 0x36
let ssl_pad2_md5  = Bytearray.createBytes 48 0x5c
let ssl_pad1_sha1 = Bytearray.createBytes 40 0x36
let ssl_pad2_sha1 = Bytearray.createBytes 40 0x5c

let sslKeyedHash_raw (h_fun: bytes -> bytes) (pad1:bytes) (pad2:bytes) (key:macKey) (data:bytes) =
    let dataStep1 = Array.concat [key; pad1; data] in
    let step1 = h_fun dataStep1 in
    let dataStep2 = Array.concat [key; pad2; step1] in
    h_fun dataStep2

(* Parametric SSL-specific keyed hash function -- implements interface *)
let sslKeyedHash alg key data =
    let (h_fun, pad1, pad2) =
        match alg with
        | MD5 -> (md5, ssl_pad1_md5, ssl_pad2_md5)
        | SHA -> (sha1, ssl_pad1_sha1, ssl_pad2_sha1)
        | _ -> unexpectedError "[sslKeyedHash] invoked on unsupported algorithm"
    try
        correct (sslKeyedHash_raw h_fun pad1 pad2 key data)
    with 
    | _ -> Error(MAC,Internal)

(* Raw symmetric enc/dec functions -- can throw exceptions *)
let commonEnc enc data =
    let mems = new System.IO.MemoryStream() in
    let crs = new System.Security.Cryptography.CryptoStream(mems,enc,System.Security.Cryptography.CryptoStreamMode.Write) in
    let _ =  crs.Write(data,0,data.Length) in
    let _ = crs.FlushFinalBlock() in
    let cipher = mems.ToArray() in
    mems.Close();
    crs.Close();
    cipher

let commonDec dec (data:bytes) =
    let mems = new System.IO.MemoryStream(data) in
    let crs = new System.Security.Cryptography.CryptoStream(mems,dec,System.Security.Cryptography.CryptoStreamMode.Read) in
    let plain = Array.zeroCreate(data.Length) in  
    let _ =  crs.Read(plain,0,plain.Length) in
    plain

let aesEncrypt (key:symKey) iv data =
    let aesObj = new System.Security.Cryptography.AesManaged() in
    aesObj.KeySize <- 8 * key.Length
    aesObj.Padding <- System.Security.Cryptography.PaddingMode.None
    let enc = aesObj.CreateEncryptor(key,iv) in
    commonEnc enc data

let aesDecrypt (key:symKey) iv (data:bytes) =
    let aesObj = new System.Security.Cryptography.AesManaged() in
    aesObj.KeySize <- 8 * key.Length
    aesObj.Padding <- System.Security.Cryptography.PaddingMode.None;
    let dec = aesObj.CreateDecryptor(key,iv) in
    commonDec dec data
    
let threeDesEncrypt (key:symKey) iv data =
    let tdesObj = new System.Security.Cryptography.TripleDESCryptoServiceProvider() in
    tdesObj.Padding <- System.Security.Cryptography.PaddingMode.None
    let enc = tdesObj.CreateEncryptor(key,iv) in
    commonEnc enc data

let threeDesDecrypt (key:symKey) iv (data:bytes) =
    let tdesObj = new System.Security.Cryptography.TripleDESCryptoServiceProvider() in
    tdesObj.Padding <- System.Security.Cryptography.PaddingMode.None;
    let dec = tdesObj.CreateDecryptor(key,iv) in
    commonDec dec data

(* Parametric symmetric enc/dec functions (implement interfaces) *)
let symEncrypt alg key iv data =
    (* Should never be invoked on a stream (right now) encryption algorithm *)
    try
        match alg with
        | THREEDES_EDE_CBC -> correct (threeDesEncrypt key iv data)
        | AES_128_CBC      -> correct (aesEncrypt key iv data)
        | AES_256_CBC      -> correct (aesEncrypt key iv data)
        | RC4_128          -> Error (Encryption, Internal)
    with
    | _ -> Error (Encryption, Internal)

let symDecrypt alg key iv data =
    (* Should never be invoked on a stream (right now) encryption algorithm *)
    try
        match alg with
        | THREEDES_EDE_CBC -> correct (threeDesDecrypt key iv data)
        | AES_128_CBC      -> correct (aesDecrypt key iv data)
        | AES_256_CBC      -> correct (aesDecrypt key iv data)
        | RC4_128          -> Error (Encryption, Internal)
    with
    | _ -> Error (Encryption, Internal)

(* RSA functions required by key exchange.
   This is a mess I won't fix right now. *)
type asymKey = AsymKey of System.Security.Cryptography.RSACryptoServiceProvider

let rsaEncrypt (k:asymKey)  (v:bytes)  = 
   try
      match k with 
      | AsymKey pkey -> correct (pkey.Encrypt(v,false))
   with
   | _ -> Error (Encryption, Internal)

let rsaDecrypt (k:asymKey) (v:bytes) =
  try
      match k with 
      | AsymKey skey -> correct (skey.Decrypt(v,false))
  with
  | _ -> Error (Encryption, Internal)

let rng = new System.Security.Cryptography.RNGCryptoServiceProvider ()
let mkRandom len =
    let x = Array.zeroCreate len in
    rng.GetBytes x; x