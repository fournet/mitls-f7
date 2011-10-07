module Algorithms

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

let keyMaterialSize ciph =
    match ciph with
    | cipherAlg.NULL    -> 0
    | RC4_128           -> 16
    | THREEDES_EDE_CBC  -> 24
    | AES_128_CBC       -> 16
    | AES_256_CBC       -> 32

let blockSize ciph =
    match ciph with
    | cipherAlg.NULL    -> 0
    | RC4_128           -> 0
    | THREEDES_EDE_CBC  -> 8
    | AES_128_CBC       -> 16
    | AES_256_CBC       -> 16

let ivSize ciph =
    match ciph with
    | cipherAlg.NULL    -> 0
    | RC4_128           -> 0
    | THREEDES_EDE_CBC  -> 8
    | AES_128_CBC       -> 16
    | AES_256_CBC       -> 16

let macKeyLength mac =
    match mac with
    | hashAlg.NULL   -> 0
    | MD5           -> 16
    | SHA           -> 20
    | SHA256        -> 32
    | SHA384        -> 48

let macLength mac =
    match mac with
    | hashAlg.NULL   -> 0
    | MD5           -> 16
    | SHA           -> 20
    | SHA256        -> 32
    | SHA384        -> 48

let isNullCipherAlg alg =
    match alg with
    | cipherAlg.NULL -> true
    | _ -> false

let isNullHashAlg alg =
    match alg with
    | hashAlg.NULL -> true
    | _ -> false