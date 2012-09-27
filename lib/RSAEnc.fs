module RSAEnc

open Bytes
open Error
open RSA

open Org.BouncyCastle.Math
open Org.BouncyCastle.Crypto.Encodings
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Parameters

let encrypt (RSAPKey (m, e)) (v : bytes) =
    let m, e   = new BigInteger(1, m), new BigInteger(1, e) in
    let engine = new RsaEngine() in
    let engine = new Pkcs1Encoding(engine) in

    engine.Init(true, new RsaKeyParameters(false, m, e))
    engine.ProcessBlock(v, 0, v.Length)

let decrypt (RSASKey (m, e)) (v : bytes) =
    let m, e   = new BigInteger(1, m), new BigInteger(1, e) in
    let engine = new RsaEngine() in
    let engine = new Pkcs1Encoding(engine) in

    engine.Init(false, new RsaKeyParameters(true, m, e))
    correct (engine.ProcessBlock(v, 0, v.Length))

