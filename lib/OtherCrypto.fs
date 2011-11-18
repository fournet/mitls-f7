module OtherCrypto

open Data
open Error

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

let rsa_skey (key:str) = 
  let rsa = new System.Security.Cryptography.RSACryptoServiceProvider () in
    rsa.FromXmlString(key);
    AsymKey rsa

let rsa_pkey_bytes (key:byte[]) = 
  let mutable rkey = new System.Security.Cryptography.RSAParameters() in
  rkey.Exponent <- Array.sub key (key.Length - 3) 3;
  rkey.Modulus <- Array.sub key (key.Length - 128 - 5) 128; 
  let rsa = new System.Security.Cryptography.RSACryptoServiceProvider () in
    rsa.ImportParameters(rkey);
    AsymKey rsa

let rng = new System.Security.Cryptography.RNGCryptoServiceProvider ()
let mkRandom len =
    let x = Array.zeroCreate len in
    rng.GetBytes x; x
