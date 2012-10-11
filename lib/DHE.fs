module DHE

open Bytes
open TLSInfo

(* ------------------------------------------------------------------------ *)
open System
open System.IO
open System.Text

open Org.BouncyCastle.Math
open Org.BouncyCastle.Security
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Utilities.IO.Pem
open Org.BouncyCastle.Asn1

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
let PEM_DH_PARAMETERS_HEADER = "DH PARAMETERS"

let dhparams = "-----BEGIN DH PARAMETERS-----
MIIBBwKBgQCctCTvtt225fYth0f8s/s+3K27xVqzrDf4fvgrmLj7OGSoJlghp6pQ
8nEGD+8jRQWak9JMrz1OlQ00YnaYuHb9QyO92O5ZVoBTXcZ07EUycXCWPmJaXUm2
X9XGm5BGhfncqc354ixfrt/+oi9h1PscSfiJvjC0rAjtfcE5xVHMNwKBgE/5q47Z
JhFd6fQhUYfiVyNuolP6z0FCZKrmLa9C6UgPLVTfEEOiW6KsCFh5uiCNYcINDZnb
lInlgrHXG2tlv4/QNCXmXBQeUBkVM+4EXOl2ZciEvFv2zAlkUig/CUcLGo/OwsJV
c8o7MMjRcCH7fDi4BIAzdEKdDYB7uEqnGJgn
-----END DH PARAMETERS-----"

(* ------------------------------------------------------------------------ *)
let saveParams (stream : Stream) ((g, p) : dhparams) =
    let writer    = new PemWriter(new StreamWriter(stream)) in
    let derparams = new DerSequence([| new DerInteger(new BigInteger(1, p)) :> Asn1Encodable;
                                       new DerInteger(new BigInteger(1, g)) :> Asn1Encodable|])
                        :> Asn1Encodable in

    writer.WriteObject(new PemObject(PEM_DH_PARAMETERS_HEADER, derparams.GetDerEncoded()));
    writer.Writer.Flush()

let saveParamsToFile (file : string) ((g, p) : dhparams) =
    let filestream = new FileStream(file, FileMode.Create, FileAccess.Write) in

    try
        try
            saveParams filestream (g, p)
            true
        finally
            filestream.Close()
    with _ ->
        false

(* ------------------------------------------------------------------------ *)
let loadParams (stream : Stream) =
    let reader = new PemReader(new StreamReader(stream)) in
    let obj    = reader.ReadPemObject() in

    if obj.Type <> PEM_DH_PARAMETERS_HEADER then
        raise (new SecurityUtilityException());

    let obj = DerSequence.GetInstance(Asn1Object.FromByteArray(obj.Content)) in

    if obj.Count <> 2 then
        raise (new SecurityUtilityException());

    (DerInteger.GetInstance(obj.Item(1)).PositiveValue.ToByteArrayUnsigned(),
     DerInteger.GetInstance(obj.Item(0)).PositiveValue.ToByteArrayUnsigned())

let loadParamsFromFile (file : string) : dhparams option =
    let filestream = new FileStream(file, FileMode.Open, FileAccess.Read) in

    try
        try
            Some (loadParams filestream)
        finally
            filestream.Close()
    with _ -> None

(* ------------------------------------------------------------------------ *)
let loadDefaultParams () =
    try
        loadParams (new MemoryStream(Encoding.ASCII.GetBytes(dhparams), false))
    with _ ->
        Error.unexpectedError "cannot load default DH parameters"

(* ------------------------------------------------------------------------ *)
let leak (si : SessionInfo) pms = pms.pms
