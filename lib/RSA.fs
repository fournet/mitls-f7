module RSA

open Bytes
open Error

open Org.BouncyCastle.Math
open Org.BouncyCastle.Crypto.Encodings
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Parameters

type rsaskey = RSASKey of bytes * bytes
type rsapkey = RSAPKey of bytes * bytes

let rsaEncrypt (RSAPKey (m, e)) (v : bytes) =
    let m, e   = new BigInteger(m), new BigInteger(e) in
    let engine = new RsaEngine() in
    let engine = new Pkcs1Encoding(engine) in

    engine.Init(true, new RsaKeyParameters(false, m, e))
    correct (engine.ProcessBlock(v, 0, v.Length))

let rsaDecrypt (RSASKey (m, e)) (v : bytes) =
    let m, e   = new BigInteger(m), new BigInteger(e) in
    let engine = new RsaEngine() in
    let engine = new Pkcs1Encoding(engine) in

    engine.Init(false, new RsaKeyParameters(true, m, e))
    correct (engine.ProcessBlock(v, 0, v.Length))

let create_rsaskey ((m, e) : bytes * bytes) =
    RSASKey (m, e)

let create_rsapkey ((m, e) : bytes * bytes) =
    RSAPKey (m, e)
