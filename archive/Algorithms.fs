module Algorithms

open Bytes
open Error
open TLSError

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

type sigAlg = 
  | SA_RSA
  | SA_DSA 
  | SA_ECDSA

let sigAlgBytes sa =
    match sa with
    | SA_RSA   -> [|1uy|]
    | SA_DSA   -> [|2uy|]
    | SA_ECDSA -> [|3uy|]

let parseSigAlg b =
    match b with
    | [|1uy|] -> correct(SA_RSA)
    | [|2uy|] -> correct(SA_DSA)
    | [|3uy|] -> correct(SA_ECDSA)
    | _ -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let hashAlgBytes ha =
    match ha with
    | MD5    -> [|1uy|]
    | SHA    -> [|2uy|]
    | SHA256 -> [|4uy|]
    | SHA384 -> [|5uy|]

let parseHashAlg b =
    match b with
    | [|1uy|] -> correct(MD5)
    | [|2uy|] -> correct(SHA)
    | [|4uy|] -> correct(SHA256)
    | [|5uy|] -> correct(SHA384)
    | _ -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

type aeadAlg =
    | AES_128_GCM
    | AES_256_GCM

type authencAlg =
    | MtE of cipherAlg * hashAlg
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

(* ------------------------------------------------------------------------ *)
(* Key parameters *)
type dsaparams = { p : bytes; q : bytes; g : bytes; }

type skeyparams =
| SK_RSA of bytes * bytes (* modulus x exponent *)
| SK_DSA of bytes * dsaparams

type pkeyparams =
| PK_RSA of bytes * bytes
| PK_DSA of bytes * dsaparams

let sigalg_of_skeyparams = function
| SK_RSA _ -> SA_RSA
| SK_DSA _ -> SA_DSA

let sigalg_of_pkeyparams = function
| PK_RSA _ -> SA_RSA
| PK_DSA _ -> SA_DSA
