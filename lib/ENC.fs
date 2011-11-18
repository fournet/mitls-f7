module ENC

open Data
open Bytearray
open Error
open Algorithms
open CipherSuites
open TLSInfo
open TLSPlain
open Formats

type symKey = {bytes:bytes}
let bytes_to_key b = {bytes = b}
type iv = bytes
type iv3 =
    | SomeIV of iv
    | NoIV of unit
type cipher = bytes

(* Raw symmetric enc/dec functions -- can throw exceptions *)

let symEncrypt enc data =
    let mems = new System.IO.MemoryStream() in
    let crs = new System.Security.Cryptography.CryptoStream(mems,enc,System.Security.Cryptography.CryptoStreamMode.Write) in
    crs.Write(data,0,data.Length) 
    crs.FlushFinalBlock() 
    let cipher = mems.ToArray() in
    mems.Close();
    crs.Close();
    correct (cipher)

let symDecrypt dec (data:bytes) =
    let mems = new System.IO.MemoryStream(data) in
    let crs = new System.Security.Cryptography.CryptoStream(mems,dec,System.Security.Cryptography.CryptoStreamMode.Read) in
    let plain = Array.zeroCreate(data.Length) in  
    let _ =  crs.Read(plain,0,plain.Length) in
    correct (plain)

let aesEncrypt (key:symKey) iv data =
    try
        let aes = new System.Security.Cryptography.AesManaged() in
        aes.KeySize <- 8 * key.bytes.Length
        aes.Padding <- System.Security.Cryptography.PaddingMode.None
        let enc = aes.CreateEncryptor(key.bytes,iv) in
        symEncrypt enc data
    with
    | _ -> Error(Encryption, Internal)

let aesDecrypt (key:symKey) iv (data:bytes) =
    try
        let aes = new System.Security.Cryptography.AesManaged() in
        aes.KeySize <- 8 * key.bytes.Length
        aes.Padding <- System.Security.Cryptography.PaddingMode.None;
        let dec = aes.CreateDecryptor(key.bytes,iv) in
        symDecrypt dec data
    with
    | _ -> Error(Encryption, Internal)
       
let tdesEncrypt (key:symKey) iv data =
    try
        let tdes = new System.Security.Cryptography.TripleDESCryptoServiceProvider() in
        tdes.Padding <- System.Security.Cryptography.PaddingMode.None
        let enc = tdes.CreateEncryptor(key.bytes,iv) in
        symEncrypt enc data
    with
    | _ -> Error(Encryption, Internal)

let tdesDecrypt (key:symKey) iv (data:bytes) =
    try
        let tdes = new System.Security.Cryptography.TripleDESCryptoServiceProvider() in
        tdes.Padding <- System.Security.Cryptography.PaddingMode.None;
        let dec = tdes.CreateDecryptor(key.bytes,iv) in
        symDecrypt dec data
    with
    | _ -> Error(Encryption, Internal)

(* Early TLS chains IVs but this is not secure against adaptive CPA *)
let lastblock cipher ivl =
    let (_,b) = split cipher (length cipher - ivl) in b

(* Parametric ENC/DEC functions *)
let ENC ki key iv3 data =
    (* Should never be invoked on a stream (right now) encryption algorithm *)
    let alg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
    let ivl = ivSize alg in
    let iv =
        match iv3 with
        | SomeIV(b) -> b
        | NoIV()    -> OtherCrypto.mkRandom ivl in 
    match 
      ( let data = plain_to_bytes data in
        match alg with
        | TDES_EDE_CBC -> tdesEncrypt key iv data
        | AES_128_CBC  -> aesEncrypt  key iv data
        | AES_256_CBC  -> aesEncrypt  key iv data
        | RC4_128      -> Error (Encryption, Internal) ) with 
    | Correct(cipher) ->
        match iv3 with
        | SomeIV(_) -> correct (SomeIV(lastblock cipher ivl), cipher)
        | NoIV()    -> correct (NoIV(), iv @| cipher)
    | Error(x,y) -> Error(x,y)

let DEC ki key iv3 cipher =
    (* Should never be invoked on a stream (right now) encryption algorithm *)
    let alg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
    let ivl = ivSize alg 
    let (iv,cipher) =
        match iv3 with
        | SomeIV (iv) -> (iv,cipher)
        | NoIV ()     -> split cipher ivl
    match
      ( match alg with
        | TDES_EDE_CBC -> tdesDecrypt key iv cipher
        | AES_128_CBC  -> aesDecrypt  key iv cipher
        | AES_256_CBC  -> aesDecrypt  key iv cipher
        | RC4_128      -> Error (Encryption, Internal)
      ) with 
    | Correct (data) ->
        let data = bytes_to_plain data in
        match iv3 with
        | SomeIV(_) -> correct (SomeIV(lastblock cipher ivl), data)
        | NoIV()    -> correct (NoIV(), data)
    | Error(x,y) -> Error(x,y)
