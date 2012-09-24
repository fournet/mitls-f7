module Sig 

// see the .fs7 for comments and discussion
open Bytes
open Algorithms

open Org.BouncyCastle.Math
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Signers
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Security

(* ------------------------------------------------------------------------ *)
type alg = sigAlg * hashAlg

type text = bytes
type sigv = bytes 

(* ------------------------------------------------------------------------ *)
type skey = SKey of skeyparams * hashAlg
type vkey = VKey of pkeyparams * hashAlg

let create_skey ((s,h) : alg) (p : skeyparams) = SKey (p, h)
let create_vkey ((s,h) : alg) (p : pkeyparams) = VKey (p, h)

(* ------------------------------------------------------------------------ *)
let sigalg_of_skeyparams = function
| SK_RSA _ -> SA_RSA
| SK_DSA _ -> SA_DSA

let sigalg_of_vkeyparams = function
| PK_RSA _ -> SA_RSA
| PK_DSA _ -> SA_DSA

(* ------------------------------------------------------------------------ *)
let bytes_to_bigint (b : bytes) = new BigInteger(1, b)
let bytes_of_bigint (b : BigInteger) = b.ToByteArrayUnsigned()

(* ------------------------------------------------------------------------ *)
let new_hash_engine (h : hashAlg) : IDigest =
    match h with
    | MD5    -> (new MD5Digest   () :> IDigest)
    | SHA    -> (new Sha1Digest  () :> IDigest)
    | SHA256 -> (new Sha256Digest() :> IDigest)
    | SHA384 -> (new Sha384Digest() :> IDigest)

(* ------------------------------------------------------------------------ *)
let RSA_sign (m, e) (h : hashAlg) (t : text) : sigv =
    let signer = new RsaDigestSigner(new_hash_engine h) in

    signer.Init(true, new RsaKeyParameters(true, bytes_to_bigint m, bytes_to_bigint e))
    signer.BlockUpdate(t, 0, t.Length)
    signer.GenerateSignature()

let RSA_verify ((m, e) : bytes * bytes) (h : hashAlg) (t : text) (s : sigv) =
    let signer = new RsaDigestSigner(new_hash_engine h) in

    signer.Init(false, new RsaKeyParameters(false, bytes_to_bigint m, bytes_to_bigint e))
    signer.BlockUpdate(t, 0, t.Length)
    signer.VerifySignature(s)

let RSA_gen (h : hashAlg) =
    let generator = new RsaKeyPairGenerator() in
    generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048))
    let keys = generator.GenerateKeyPair() in
    let vkey = (keys.Public  :?> RsaKeyParameters) in
    let skey = (keys.Private :?> RsaKeyParameters) in

    (VKey (PK_RSA (bytes_of_bigint vkey.Modulus, bytes_of_bigint vkey.Exponent), h),
     SKey (SK_RSA (bytes_of_bigint skey.Modulus, bytes_of_bigint skey.Exponent), h))

(* ------------------------------------------------------------------------ *)
let bytes_of_dsaparams p q g =
    { p = bytes_of_bigint p;
      q = bytes_of_bigint q;
      g = bytes_of_bigint g; }

let DSA_sign (x, dsap) (h : hashAlg) (t : text) : sigv =
    let signer    = new DsaDigestSigner(new DsaSigner(), new_hash_engine h) in
    let dsaparams = new DsaParameters(bytes_to_bigint dsap.p,
                                      bytes_to_bigint dsap.q,
                                      bytes_to_bigint dsap.g)

    signer.Init(true, new DsaPrivateKeyParameters(bytes_to_bigint x, dsaparams))
    signer.BlockUpdate(t, 0, t.Length)
    signer.GenerateSignature()

let DSA_verify (y, dsap) (h : hashAlg) (t : text) (s : sigv) =
    let signer    = new DsaDigestSigner(new DsaSigner(), new_hash_engine h) in
    let dsaparams = new DsaParameters(bytes_to_bigint dsap.p,
                                      bytes_to_bigint dsap.q,
                                      bytes_to_bigint dsap.g)

    signer.Init(false, new DsaPublicKeyParameters(bytes_to_bigint y, dsaparams))
    signer.BlockUpdate(t, 0, t.Length)
    signer.VerifySignature(s)

let DSA_gen (h : hashAlg) =
    let paramsgen = new DsaParametersGenerator() in
    paramsgen.Init(2048, 80, new SecureRandom())
    let dsaparams = paramsgen.GenerateParameters() in
    let generator = new DsaKeyPairGenerator() in
    generator.Init(new DsaKeyGenerationParameters(new SecureRandom(), dsaparams))
    let keys = generator.GenerateKeyPair() in
    let vkey = (keys.Public  :?> DsaPublicKeyParameters) in
    let skey = (keys.Private :?> DsaPrivateKeyParameters) in

    (VKey (PK_DSA (bytes_of_bigint vkey.Y, bytes_of_dsaparams dsaparams.P dsaparams.Q dsaparams.G), h),
     SKey (SK_DSA (bytes_of_bigint skey.X, bytes_of_dsaparams dsaparams.P dsaparams.Q dsaparams.G), h))

(* ------------------------------------------------------------------------ *)
let sign (a : alg) (sk : skey) (t : text) : sigv =
    let asig, ahash = a in
    let (SKey (kparams, khash)) = sk in

    if ahash <> khash then
        Error.unexpectedError
            (sprintf "Sig.sign: requested sig-hash = %A, but key requires %A"
                ahash khash)
    if asig <> sigalg_of_skeyparams kparams then
        Error.unexpectedError
            (sprintf "Sig.sign: requested sig-algo = %A, but key requires %A"
                asig (sigalg_of_skeyparams kparams))

    match kparams with
    | SK_RSA (m, e) -> RSA_sign (m, e) khash t
    | SK_DSA (x, p) -> DSA_sign (x, p) khash t

(* ------------------------------------------------------------------------ *)
let verify (a : alg) (vk : vkey) (t : text) (s : sigv) =
    let asig, ahash = a in
    let (VKey (kparams, khash)) = vk in

    if ahash <> khash then
        Error.unexpectedError
            (sprintf "Sig.verify: requested sig-hash = %A, but key requires %A"
                ahash khash)
    if asig <> sigalg_of_vkeyparams kparams then
        Error.unexpectedError
            (sprintf "Sig.verify: requested sig-algo = %A, but key requires %A"
                asig (sigalg_of_vkeyparams kparams))

    match kparams with
    | PK_RSA (m, e) -> RSA_verify (m, e) khash t s
    | PK_DSA (y, p) -> DSA_verify (y, p) khash t s

(* ------------------------------------------------------------------------ *)
let gen (a:alg) : vkey * skey =
    let asig, ahash = a in

    match asig with
    | SA_RSA   -> RSA_gen ahash
    | SA_DSA   -> DSA_gen ahash
    | SA_ECDSA -> Error.unexpectedError "todo"

(* ------------------------------------------------------------------------ *)
let PkBytes (a:alg) (vk : vkey) : bytes = Error.unexpectedError "todo"
let SkBytes (a:alg) (sk : skey) : bytes = Error.unexpectedError "todo"
