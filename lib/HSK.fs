module HSK

(* ------------------------------------------------------------------------ *)
open System.Text
open System.Collections.Generic
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates

open Bytes
open Algorithms

(* ------------------------------------------------------------------------ *)
type hint = string
type cert = bytes

(* ------------------------------------------------------------------------ *)
let OID_RSAEncryption     = "1.2.840.113549.1.1.1"
let OID_DSASignatureKey   = "1.2.840.10040.4.1" (* FIX: CHECK *)
let OID_ECDSASignatureKey = "1.2.840.10045.4.1" (* FIX: CHECK *)

let oid_of_sigalg = function
| Sig.SA_RSA   -> OID_RSAEncryption
| Sig.SA_DSA   -> OID_DSASignatureKey
| Sig.SA_ECDSA -> OID_ECDSASignatureKey

(* ------------------------------------------------------------------------ *)
let x509_to_keys (x509 : X509Certificate2) =
    match x509.GetKeyAlgorithm() with
    | x when x = OID_RSAEncryption ->
        let skey = (x509.PrivateKey    :?> RSA).ExportParameters(true ) in
        let pkey = (x509.PublicKey.Key :?> RSA).ExportParameters(false) in

        Some (SK_RSA (skey.Modulus, skey.Exponent),
              PK_RSA (pkey.Modulus, pkey.Exponent))

    | x when x = OID_DSASignatureKey ->
        let skey = (x509.PrivateKey    :?> DSA).ExportParameters(true ) in
        let pkey = (x509.PublicKey.Key :?> DSA).ExportParameters(false) in

        let dsaparams = { p = pkey.P; q = pkey.Q; g = pkey.G } in

        Some (SK_DSA (skey.X, dsaparams), PK_DSA (pkey.Y, dsaparams))

    | _ -> None

(* ------------------------------------------------------------------------ *)
let x509_is_for_signing (x509 : X509Certificate2) =
    try
        let kue =
            x509.Extensions
                |> Seq.cast
                |> Seq.find (fun (e : X509Extension) -> e.Oid.Value = "2.5.29.15") in
        let kue = kue :?> X509KeyUsageExtension in

            kue.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)

    with :? KeyNotFoundException ->
        true

(* ------------------------------------------------------------------------ *)
let for_signing (h : hint) ((asig, ahash) : Sig.alg) =
    let kaoid = oid_of_sigalg asig in
    let store = new X509Store(StoreName.My, StoreLocation.CurrentUser) in

    store.Open(OpenFlags.ReadOnly ||| OpenFlags.OpenExistingOnly)
    try
        try
            let x509 =
                store.Certificates.Find(X509FindType.FindBySubjectName, h, true)
                    |> Seq.cast
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509.Version >= 3)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509.HasPrivateKey)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509.GetKeyAlgorithm() = kaoid)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509_is_for_signing x509)
                    |> Seq.head
            in
                match x509_to_keys x509 with
                | Some (skey, pkey) ->
                    Some (x509.Export(X509ContentType.Cert),
                          Sig.create_skey ahash skey,
                          Sig.create_vkey ahash pkey)
                | None -> None
        with :? KeyNotFoundException -> None
    finally
        store.Close()
