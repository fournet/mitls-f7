module Principal

open Bytes
open Error
open OtherCrypto
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates

type cert =
    | PriCert of X509Certificate2

let certificate_of_bytes (cert_list:bytes) =
    try correct (PriCert(new X509Certificate2(cert_list))) with
    | :? CryptographicException -> Error(CertificateParsing,Internal)

let bytes_of_certificate (PriCert(cert)) = cert.Export(X509ContentType.Cert)

let pubKey_of_certificate (PriCert(cert)) =
    let rawkey = cert.GetPublicKey () in
    rsa_pkey_bytes rawkey

let priKey_of_certificate (PriCert(cert)) =
    let rawkey = cert.PrivateKey.ToXmlString(true)
    rsa_skey rawkey

let set_priKey (PriCert(cert)) data =
    let asimKey = AsymmetricAlgorithm.Create("RSA") in
    asimKey.FromXmlString(data)
    cert.PrivateKey <- asimKey
    PriCert(cert)

let certificate_has_signing_capability (PriCert(cert)) =
    (* TODO *) true

let certificate_is_dsa (PriCert(cert)) =
    (* FIXME: no idea of what the friendly name is expected to be *)
    cert.SignatureAlgorithm.FriendlyName = "DSA"

let get_CN (PriCert(cert)) =
    cert.Subject