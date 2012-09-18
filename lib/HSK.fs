module HSK

(* ------------------------------------------------------------------------ *)
open System.Text
open System.Collections.Generic
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates

open Bytes

(* ------------------------------------------------------------------------ *)
type hint = string
type cert = bytes
type pkey = PK of bytes

(* ------------------------------------------------------------------------ *)
let is_oid_RSAEncryption     (oid : Oid) = oid.Value = "1.2.840.113549.1.1.1"
let is_oid_KeyUsageExtension (oid : Oid) = oid.Value = "2.5.29.15"

(* ------------------------------------------------------------------------ *)
let x509_to_bytes (x509 : X509Certificate2) =
    let cert = x509.Export(X509ContentType.Cert) in
    let pkey = Encoding.Unicode.GetBytes(x509.PrivateKey.ToXmlString(true)) in

    (cert, PK pkey)

(* ------------------------------------------------------------------------ *)
let RSA_x509_validate (h : hint) (x509 : X509Certificate2) =
    try
        if x509.Version >= 3 && is_oid_RSAEncryption x509.PublicKey.Oid && x509.HasPrivateKey then
            try
                let kue =
                    x509.Extensions
                        |> Seq.cast
                        |> Seq.find (fun (e : X509Extension) -> is_oid_KeyUsageExtension e.Oid)
                in
                    (kue :?> X509KeyUsageExtension).KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)
            with :? KeyNotFoundException -> true
        else
            false
    with :? CryptographicException -> false

(* ------------------------------------------------------------------------ *)
let RSA_pkey (h : hint) =
    let store = new X509Store(StoreName.My, StoreLocation.CurrentUser) in

    store.Open(OpenFlags.ReadOnly ||| OpenFlags.OpenExistingOnly)
    try
        try
            store.Certificates
                |> Seq.cast
                |> Seq.find (RSA_x509_validate h)
                |> x509_to_bytes
                |> Some
        with
            | :? KeyNotFoundException   -> None
            | :? CryptographicException -> None
    finally
        store.Close()
