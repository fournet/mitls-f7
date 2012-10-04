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

(* ------------------------------------------------------------------------ *)
let OID_RSAEncryption     = "1.2.840.113549.1.1.1"
let OID_DSASignatureKey   = "1.2.840.10040.4.1" (* FIX: CHECK *)
let OID_ECDSASignatureKey = "1.2.840.10045.4.1" (* FIX: CHECK *)

let oid_of_sigalg = function
| SA_RSA   -> OID_RSAEncryption
| SA_DSA   -> OID_DSASignatureKey
| SA_ECDSA -> OID_ECDSASignatureKey

(* ------------------------------------------------------------------------ *)
let x509_to_public_key (x509 : X509Certificate2) =
    match x509.GetKeyAlgorithm() with
    | x when x = OID_RSAEncryption ->
        try
            let pkey = (x509.PublicKey.Key :?> RSA).ExportParameters(false) in
                Some (PK_RSA (pkey.Modulus, pkey.Exponent))
        with :? CryptographicException -> None

    | x when x = OID_DSASignatureKey ->
        try
            let pkey = (x509.PublicKey.Key :?> DSA).ExportParameters(false) in
            let dsaparams = { p = pkey.P; q = pkey.Q; g = pkey.G } in
                Some (PK_DSA (pkey.Y, dsaparams))
        with :? CryptographicException -> None

    | _ -> None

let x509_to_secret_key (x509 : X509Certificate2) =
    match x509.GetKeyAlgorithm() with
    | x when x = OID_RSAEncryption ->
        try
            let skey = (x509.PrivateKey :?> RSA).ExportParameters(true ) in
                Some (SK_RSA (skey.Modulus, skey.Exponent))
        with :? CryptographicException -> None

    | x when x = OID_DSASignatureKey ->
        try
            let skey = (x509.PrivateKey :?> DSA).ExportParameters(true ) in
            let dsaparams = { p = skey.P; q = skey.Q; g = skey.G } in
                Some (SK_DSA (skey.X, dsaparams))
        with :? CryptographicException -> None

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
let x509_chain (x509 : X509Certificate2) = (* FIXME *)
    ([] : X509Certificate2 list)

(* ------------------------------------------------------------------------ *)
let x509_export_public (x509 : X509Certificate2) : bytes =
    x509.Export(X509ContentType.Cert)

(* ------------------------------------------------------------------------ *)
let x509_is_for_signing (x509 : X509Certificate2) =
       x509.Version >= 3
    && x509_has_key_usage_flag false X509KeyUsageFlags.DigitalSignature x509

let x509_is_for_key_encryption (x509 : X509Certificate2) =
       x509.Version >= 3
    && x509_has_key_usage_flag false X509KeyUsageFlags.KeyEncipherment x509

(* ------------------------------------------------------------------------ *)
let for_signing (h : hint) (algs : Sig.alg list) =
    let store = new X509Store(StoreName.My, StoreLocation.CurrentUser) in

    store.Open(OpenFlags.ReadOnly ||| OpenFlags.OpenExistingOnly)
    try
        try
            let (x509, alg) =
                let pick (x509 : X509Certificate2) =
                    let testalg ((asig, _) : Sig.alg) =
                        x509.GetKeyAlgorithm() = oid_of_sigalg asig
                    in

                    if  x509.HasPrivateKey && x509_is_for_signing x509 then
                        match List.tryFind testalg algs with
                        | None     -> None
                        | Some alg -> Some (x509, alg)
                    else
                        None
                in
                    store.Certificates.Find(X509FindType.FindBySubjectName, h, true)
                        |> Seq.cast
                        |> Seq.pick pick
            in
                match x509_to_secret_key x509 with
                | Some skey ->
                    let chain = x509_chain x509 in
                        Some (x509_export_public x509,
                              chain |> List.map x509_export_public,
                              Sig.create_skey alg skey)
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
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509.HasPrivateKey)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509_is_for_key_encryption x509)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509.GetKeyAlgorithm() = OID_RSAEncryption)
                    |> Seq.head
            in
                match x509_to_secret_key x509 with
                | Some (SK_RSA(sm, se)) ->
                    let chain = x509_chain x509 in
                        Some (x509_export_public x509,
                              chain |> List.map x509_export_public,
                              RSA.create_rsaskey (sm, se))
                | _ -> None
        with :? KeyNotFoundException -> None
    finally
        store.Close()

(* ------------------------------------------------------------------------ *)
let is_for_signing (c : cert) =
    try
        x509_is_for_signing (new X509Certificate2(c))
    with :? CryptographicException -> false

let is_for_key_encryption (c : cert) =
    try
        x509_is_for_key_encryption (new X509Certificate2(c))
    with :? CryptographicException -> false

(* ------------------------------------------------------------------------ *)
let get_public_signing_key (c : cert) ((siga, hasha) as a : Sig.alg) : Sig.vkey Result =
    try
        let x509 = new X509Certificate2(c) in
            if x509_is_for_signing x509 then
                match x509_to_public_key x509 with
                | Some k -> Correct (Sig.create_vkey a k)
                | None   -> Error(CertificateParsing, Internal)
            else
                Error(CertificateParsing, Internal)
    with :? CryptographicException -> Error(CertificateParsing, Internal)

let get_public_encryption_key (c : cert) : RSA.pk Result =
    try
        let x509 = new X509Certificate2(c) in
            if x509_is_for_key_encryption x509 then
                match x509_to_public_key x509 with
                | Some (PK_RSA(pm, pe)) -> Correct (RSA.create_rsapkey (pm, pe))
                | _ -> Error(CertificateParsing, Internal)
            else
                Error(CertificateParsing, Internal)
    with :? CryptographicException -> Error(CertificateParsing, Internal)

(* ------------------------------------------------------------------------ *)
let validate_chain (c : cert) (issuers : cert list) =
    (failwith "TODO" : bool)

