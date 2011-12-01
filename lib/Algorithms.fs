module Algorithms

open Bytes

type kexAlg =
    | RSA
    | DH_DSS
    | DH_RSA
    | DHE_DSS
    | DHE_RSA
    | DH_anon

type cipherAlg =
    | RC4_128
    | TDES_EDE_CBC
    | AES_128_CBC
    | AES_256_CBC

type hashAlg =
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

let encKeySize ciph =
    match ciph with
    | RC4_128           -> 16
    | TDES_EDE_CBC      -> 24
    | AES_128_CBC       -> 16
    | AES_256_CBC       -> 32

let blockSize ciph =
    match ciph with
    | RC4_128           -> 0
    | TDES_EDE_CBC      -> 8
    | AES_128_CBC       -> 16
    | AES_256_CBC       -> 16

let ivSize ciph = blockSize ciph
//    match ciph with
//    | RC4_128           -> 0
//    | TDES_EDE_CBC      -> 8
//    | AES_128_CBC       -> 16
//    | AES_256_CBC       -> 16

let aeadKeySize ciph =
    match ciph with
    | AES_128_GCM -> 16
    | AES_256_GCM -> 16

let aeadIVSize ciph =
    match ciph with
    | AES_128_GCM -> 16
    | AES_256_GCM -> 16

let hashSize alg =
    match alg with
    | MD5           -> 16
    | SHA           -> 20
    | SHA256        -> 32
    | SHA384        -> 48

let macKeySize mac = hashSize mac
//    match mac with
//    | MD5           -> 16
//    | SHA           -> 20
//    | SHA256        -> 32
//    | SHA384        -> 48

let macSize alg = hashSize alg
//    match alg with
//    | MD5           -> 16
//    | SHA           -> 20
//    | SHA256        -> 32
//    | SHA384        -> 48


(* SSL constants *)

let ssl_pad1_md5  = createBytes 48 0x36
let ssl_pad2_md5  = createBytes 48 0x5c
let ssl_pad1_sha1 = createBytes 40 0x36
let ssl_pad2_sha1 = createBytes 40 0x5c