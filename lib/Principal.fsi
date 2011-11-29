module Principal

// X.509 certificates (as used for TLS)

open Bytes
open Error
open RSA

type cert

val certificate_of_bytes: bytes -> cert Result
val bytes_of_certificate: cert -> bytes
val pubKey_of_certificate: cert -> asymKey
val priKey_of_certificate: cert -> asymKey
val set_priKey: cert -> string -> cert
val certificate_has_signing_capability: cert -> bool
val certificate_is_dsa: cert -> bool
val get_CN: cert -> string
