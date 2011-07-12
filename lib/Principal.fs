module Principal

open Data
open Error_handling
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates

type pri_cert =
    | PriCert of X509Certificate2

let certificate_of_bytes (cert_list:bytes) =
    try correct (PriCert(new X509Certificate2(cert_list))) with
    | :? CryptographicException -> Error(CertificateParsing,Internal)

let bytes_of_certificate (PriCert(cert)) = cert.Export(X509ContentType.Cert)