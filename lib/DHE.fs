module DHE

open Bytes
open TLSInfo

(* ------------------------------------------------------------------------ *)
open System

open Org.BouncyCastle.Math
open Org.BouncyCastle.Security
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Parameters

type g = bytes
type p = bytes

type dhparams = g * p

type x = { x : bytes }
type y = bytes

type pms = { pms : bytes }

(* ------------------------------------------------------------------------ *)
let genParams () : dhparams =
    let random    = new SecureRandom() in
    let generator = new DHParametersGenerator() in
        generator.Init(1024, 80, random);
        let dhparams = generator.GenerateParameters() in
            (dhparams.G.ToByteArrayUnsigned(), dhparams.P.ToByteArrayUnsigned())

(* ------------------------------------------------------------------------ *)
let genKey ((g, p) : dhparams) : x * y =
    let dhparams = new DHParameters(new BigInteger(1, p), new BigInteger(1, g)) in
    let kparams  = new DHKeyGenerationParameters(new SecureRandom(), dhparams) in
    let kgen     = new DHKeyPairGenerator() in
        kgen.Init(kparams);
        let kpair = kgen.GenerateKeyPair() in
        let pkey  = (kpair.Public  :?> DHPublicKeyParameters ) in
        let skey  = (kpair.Private :?> DHPrivateKeyParameters) in
            ({ x = skey.X.ToByteArrayUnsigned() }, pkey.Y.ToByteArrayUnsigned())

(* ------------------------------------------------------------------------ *)
let genPMS (si : SessionInfo) ((g, p) : dhparams) ({ x = x } : x) (y : y) : pms =
    let x = new BigInteger(1, x) in
    let y = new BigInteger(1, y) in
    let p = new BigInteger(1, p) in
        { pms = y.ModPow(x, p).ToByteArrayUnsigned() }


(* ------------------------------------------------------------------------ *)
let loadParams (file : string) : dhparams option =
    None

(* ------------------------------------------------------------------------ *)
let saveParams (file : string) ((g, p) : dhparams) =
    ()

(* ------------------------------------------------------------------------ *)
let leak (si : SessionInfo) pms = pms.pms
