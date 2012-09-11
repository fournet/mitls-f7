﻿module RSA

open Bytes
open Error

(** RSA encryption of PMS **)

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

let rsa_skey (key:string) = 
  let rsa = new System.Security.Cryptography.RSACryptoServiceProvider () in
    rsa.FromXmlString(key);
    AsymKey rsa

let rsa_pkey_bytes (key:byte[]) = 
  let mutable rkey = new System.Security.Cryptography.RSAParameters() in
  rkey.Exponent <- Array.sub key (key.Length - 3) 3;
  rkey.Modulus  <- Array.sub key (key.Length - 128 - 5) 128; 
  let rsa = new System.Security.Cryptography.RSACryptoServiceProvider () in
    rsa.ImportParameters(rkey);
    AsymKey rsa
