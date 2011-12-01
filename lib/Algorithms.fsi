﻿module Algorithms

open Bytes

(* Not abstracts, but only meant to be used by
   crypto modules and CipherSuites *)
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

val encKeySize: cipherAlg -> int
val blockSize: cipherAlg -> int
val ivSize: cipherAlg -> int
val aeadKeySize: aeadAlg -> int
val aeadIVSize: aeadAlg -> int
val macKeySize: hashAlg -> int
val macSize: hashAlg -> int
val hashSize: hashAlg -> int

(* SSL Constants *)
val ssl_pad1_md5: bytes
val ssl_pad2_md5: bytes
val ssl_pad1_sha1: bytes
val ssl_pad2_sha1: bytes