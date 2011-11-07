module ENC

open Data
open Bytearray
open Error_handling
open Algorithms
open HS_ciphersuites
open TLSInfo
open TLSPlain
open Formats

type symKey = {bytes:bytes}
type iv = bytes
type ivOpt =
    | SomeIV of iv
    | NoneIV
type cipher = bytes

(* Raw symmetric enc/dec functions -- can throw exceptions *)
let commonEnc enc data =
    let mems = new System.IO.MemoryStream() in
    let crs = new System.Security.Cryptography.CryptoStream(mems,enc,System.Security.Cryptography.CryptoStreamMode.Write) in
    let _ =  crs.Write(data,0,data.Length) in
    let _ = crs.FlushFinalBlock() in
    let cipher = mems.ToArray() in
    mems.Close();
    crs.Close();
    correct (cipher)

let commonDec dec (data:bytes) =
    let mems = new System.IO.MemoryStream(data) in
    let crs = new System.Security.Cryptography.CryptoStream(mems,dec,System.Security.Cryptography.CryptoStreamMode.Read) in
    let plain = Array.zeroCreate(data.Length) in  
    let _ =  crs.Read(plain,0,plain.Length) in
    correct (plain)

let aesEncrypt (key:symKey) iv data =
    try
        let aesObj = new System.Security.Cryptography.AesManaged() in
        aesObj.KeySize <- 8 * key.bytes.Length
        aesObj.Padding <- System.Security.Cryptography.PaddingMode.None
        let enc = aesObj.CreateEncryptor(key.bytes,iv) in
        commonEnc enc data
    with
    | _ -> Error(Encryption, Internal)

let aesDecrypt (key:symKey) iv (data:bytes) =
    try
        let aesObj = new System.Security.Cryptography.AesManaged() in
        aesObj.KeySize <- 8 * key.bytes.Length
        aesObj.Padding <- System.Security.Cryptography.PaddingMode.None;
        let dec = aesObj.CreateDecryptor(key.bytes,iv) in
        commonDec dec data
    with
    | _ -> Error(Encryption, Internal)
       
let threeDesEncrypt (key:symKey) iv data =
    try
        let tdesObj = new System.Security.Cryptography.TripleDESCryptoServiceProvider() in
        tdesObj.Padding <- System.Security.Cryptography.PaddingMode.None
        let enc = tdesObj.CreateEncryptor(key.bytes,iv) in
        commonEnc enc data
    with
    | _ -> Error(Encryption, Internal)

let threeDesDecrypt (key:symKey) iv (data:bytes) =
    try
        let tdesObj = new System.Security.Cryptography.TripleDESCryptoServiceProvider() in
        tdesObj.Padding <- System.Security.Cryptography.PaddingMode.None;
        let dec = tdesObj.CreateDecryptor(key.bytes,iv) in
        commonDec dec data
    with
    | _ -> Error(Encryption, Internal)

(* Early TLS insecure way of computing IV *)
let get_next_iv alg data =
    let ivLen = ivSize alg in
    let (_,res) = split data ((length data) - ivLen) in
    res

(* Latest TLS IV handling *)
let split_iv alg data =
    let ivLen = ivSize alg in
    split data ivLen

(* Parametric ENC/DEC functions (implement interfaces) *)
let ENC ki key ivopt (tlen:int) data =
    (* Should never be invoked on a stream (right now) encryption algorithm *)
    let alg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
    let iv =
        match ivopt with
        | SomeIV (b) -> b
        | NoneIV ->
            let ivLen = ivSize alg in
            OtherCrypto.mkRandom ivLen
    let res =
        let data = plain_to_bytes data in
        match alg with
        | THREEDES_EDE_CBC -> threeDesEncrypt key iv data
        | AES_128_CBC      -> aesEncrypt key iv data
        | AES_256_CBC      -> aesEncrypt key iv data
        | RC4_128          -> Error (Encryption, Internal)
    match res with
    | Error(x,y) -> Error(x,y)
    | Correct(encr) ->
        match ivopt with
        | SomeIV (_) ->
            let nextIV = get_next_iv alg encr
            correct (SomeIV (nextIV), encr)
        | NoneIV ->
            let res = iv @| encr in
            correct (NoneIV,res)

let DEC ki key ivopt (tlen:int) data =
    (* Should never be invoked on a stream (right now) encryption algorithm *)
    let alg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
    let (iv,data) =
        match ivopt with
        | NoneIV -> split_iv alg data
        | SomeIV (b) -> (b,data)
    let res =
        match alg with
        | THREEDES_EDE_CBC -> threeDesDecrypt key iv data
        | AES_128_CBC      -> aesDecrypt key iv data
        | AES_256_CBC      -> aesDecrypt key iv data
        | RC4_128          -> Error (Encryption, Internal)
    match res with
    | Error(x,y) -> Error(x,y)
    | Correct (decr) ->
        let decr = bytes_to_plain decr in
        match ivopt with
        | NoneIV -> correct (NoneIV, decr)
        | SomeIV (_) ->
            let nextIV = get_next_iv alg data in
            correct (SomeIV(nextIV), decr)