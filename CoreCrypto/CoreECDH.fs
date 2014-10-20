module CoreECDH

open Org.BouncyCastle.Math
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Signers
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Math.EC
open Org.BouncyCastle.Security

let secp256r1 =
    let p256 = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
    let curve =
        new FpCurve(p256,
                    new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
                    new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16))
    let basepx = new FpFieldElement(p256, new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16))
    let basepy = new FpFieldElement(p256, new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16))
    let basep = new FpPoint(curve, basepx, basepy)
    let dom = new ECDomainParameters(curve, basep, new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"))
    (curve, dom, basep)

let getcurve =
    function
    | "" | "secp256r1" -> secp256r1
    | _ -> failwith "Unknown curve"
