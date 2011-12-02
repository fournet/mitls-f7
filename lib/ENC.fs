module ENC

open Bytes
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

(* Raw symmetric enc/dec functions -- 
   Although in principle these functions could throw exceptions,
   we claim they can never do that:
   ArgumentException: we always pass a readable/writable and valid stream
   NotSupportedException: we always give a writable (readable) stream to write (read)
   ArgumentOutOfRangeException: data.Length is always greater than zero
   ArgumentException: 0+data.Length is never longer than data.Length
   CryptographicException: The key is never corrupt
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

let aesEncrypt (key:symKey) iv data =
    let aes = new System.Security.Cryptography.AesManaged() in
    aes.KeySize <- 8 * key.bytes.Length
    aes.Padding <- System.Security.Cryptography.PaddingMode.None
    let enc = aes.CreateEncryptor(key.bytes,iv) in
    symEncrypt enc data

let aesDecrypt (key:symKey) iv (data:bytes) =
    let aes = new System.Security.Cryptography.AesManaged() in
    aes.KeySize <- 8 * key.bytes.Length
    aes.Padding <- System.Security.Cryptography.PaddingMode.None;
    let dec = aes.CreateDecryptor(key.bytes,iv) in
    symDecrypt dec data
       
let tdesEncrypt (key:symKey) iv data =
    let tdes = new System.Security.Cryptography.TripleDESCryptoServiceProvider() in
    tdes.Padding <- System.Security.Cryptography.PaddingMode.None
    let enc = tdes.CreateEncryptor(key.bytes,iv) in
    symEncrypt enc data

let tdesDecrypt (key:symKey) iv (data:bytes) =
    let tdes = new System.Security.Cryptography.TripleDESCryptoServiceProvider() in
    tdes.Padding <- System.Security.Cryptography.PaddingMode.None;
    let dec = tdes.CreateDecryptor(key.bytes,iv) in
    symDecrypt dec data

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
        | NoIV()    -> mkRandom ivl in
    let data = plain_to_bytes data in
    let cipher =
        match alg with
        | TDES_EDE_CBC -> tdesEncrypt key iv data
        | AES_128_CBC  -> aesEncrypt  key iv data
        | AES_256_CBC  -> aesEncrypt  key iv data
        | RC4_128      -> unexpectedError "[ENC] invoked on stream cipher"
    match iv3 with
    | SomeIV(_) -> (SomeIV(lastblock cipher ivl), cipher)
    | NoIV()    -> (NoIV(), iv @| cipher)

let DEC ki key iv3 cipher =
    (* Should never be invoked on a stream (right now) encryption algorithm *)
    let alg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
    let ivl = ivSize alg 
    let (iv,cipher) =
        match iv3 with
        | SomeIV (iv) -> (iv,cipher)
        | NoIV ()     -> split cipher ivl
    let data =
        match alg with
        | TDES_EDE_CBC -> tdesDecrypt key iv cipher
        | AES_128_CBC  -> aesDecrypt  key iv cipher
        | AES_256_CBC  -> aesDecrypt  key iv cipher
        | RC4_128      -> unexpectedError "[DEC] invoked on stream cipher"
    let data = bytes_to_plain data in
    match iv3 with
    | SomeIV(_) -> (SomeIV(lastblock cipher ivl), data)
    | NoIV()    -> (NoIV(), data)
