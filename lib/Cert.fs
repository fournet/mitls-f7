module Cert

(* ------------------------------------------------------------------------ *)
open System.Text
open System.Collections.Generic
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates

open Bytes
open Algorithms
open Error

(* ------------------------------------------------------------------------ *)
type hint = string
type cert = bytes

type certType =
    | RSA_sign
    | DSA_sign
    | RSA_fixed_dh
    | DSA_fixed_dh

let certTypeBytes ct =
    match ct with
    | RSA_sign     -> [|1uy|]
    | DSA_sign     -> [|2uy|]
    | RSA_fixed_dh -> [|3uy|]
    | DSA_fixed_dh -> [|4uy|]

let parseCertType b =
    match b with
    | [|1uy|] -> Correct(RSA_sign)
    | [|2uy|] -> Correct(DSA_sign)
    | [|3uy|] -> Correct(RSA_fixed_dh)
    | [|4uy|] -> Correct(DSA_fixed_dh)
    | _ -> Error(Parsing,WrongInputParameters)

(* ------------------------------------------------------------------------ *)
let OID_RSAEncryption     = "1.2.840.113549.1.1.1"
let OID_DSASignatureKey   = "1.2.840.10040.4.1" (* FIX: CHECK *)
let OID_ECDSASignatureKey = "1.2.840.10045.4.1" (* FIX: CHECK *)

let oid_of_sigalg = function
| SA_RSA   -> OID_RSAEncryption
| SA_DSA   -> OID_DSASignatureKey
| SA_ECDSA -> OID_ECDSASignatureKey

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
let x509_has_key_usage_flag strict flag (x509 : X509Certificate2) =
    try
        let kue =
            x509.Extensions
                |> Seq.cast
                |> Seq.find (fun (e : X509Extension) -> e.Oid.Value = "2.5.29.15") in
        let kue = kue :?> X509KeyUsageExtension in

            kue.KeyUsages.HasFlag(flag)

    with :? KeyNotFoundException ->
        not strict

(* ------------------------------------------------------------------------ *)
let x509_is_for_signing (x509 : X509Certificate2) =
    x509_has_key_usage_flag false X509KeyUsageFlags.DigitalSignature x509

let x509_is_for_key_encryption (x509 : X509Certificate2) =
    x509_has_key_usage_flag false X509KeyUsageFlags.KeyEncipherment x509

(* ------------------------------------------------------------------------ *)
let for_signing (h : hint) ((asig, ahash) as a: Sig.alg) =
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
                    // FIXME: We should return the full certificate chain
                    Some ([ x509.Export(X509ContentType.Cert) ],
                          Sig.create_skey a skey,
                          Sig.create_vkey a pkey)
                | None -> None
        with :? KeyNotFoundException -> None
    finally
        store.Close()

(* ------------------------------------------------------------------------ *)
let for_key_encryption (h : hint) =
    let store = new X509Store(StoreName.My, StoreLocation.CurrentUser) in

    store.Open(OpenFlags.ReadOnly ||| OpenFlags.OpenExistingOnly)
    try
        try
            let x509 =
                store.Certificates.Find(X509FindType.FindBySubjectName, h, true)
                    |> Seq.cast
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509.Version >= 3)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509.HasPrivateKey)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509.GetKeyAlgorithm() = OID_RSAEncryption)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509_is_for_key_encryption x509)
                    |> Seq.head
            in
                match x509_to_keys x509 with
                | Some (SK_RSA(sm, se) , PK_RSA (pm, pe)) ->
                    // FIXME: We should return the full certificate chain
                    Some ([ x509.Export(X509ContentType.Cert) ],
                          RSA.create_rsaskey (sm, se),
                          RSA.create_rsapkey (pm, pe))
                | _ -> None
        with :? KeyNotFoundException -> None
    finally
        store.Close()

let is_for_signing (l:cert list) =
    let x509 = new X509Certificate2(l.Head) in
    x509_is_for_signing x509

let is_for_key_encryption (l:cert list) =
    let x509 = new X509Certificate2(l.Head) in
    x509_is_for_key_encryption x509