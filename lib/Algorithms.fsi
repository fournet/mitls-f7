module Algorithms

(* Not abstracts, but only meant to be used by
   CryptoTLS and HS_Ciphersuites *)
type kexAlg =
    | NULL
    | RSA
    | DH_DSS
    | DH_RSA
    | DHE_DSS
    | DHE_RSA
    | DH_anon

type cipherAlg =
    | NULL
    | RC4_128
    | THREEDES_EDE_CBC
    | AES_128_CBC
    | AES_256_CBC

type hashAlg =
    | NULL
    | MD5
    | SHA
    | SHA256
    | SHA384

type aeadAlg =
    | AES_128_GCM
    | AES_256_GCM

type authencAlg =
    | EncMAC of cipherAlg * hashAlg
    | AEAD of aeadAlg * hashAlg

val keyMaterialSize: cipherAlg -> int
val blockSize: cipherAlg -> int
val ivSize: cipherAlg -> int
val macKeyLength: hashAlg -> int
val macLength: hashAlg -> int

val isNullCipherAlg: cipherAlg -> bool
val isNullHashAlg: hashAlg -> bool