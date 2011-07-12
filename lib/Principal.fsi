module Principal

open Data
open Error_handling

type pri_cert

val certificate_of_bytes: bytes -> pri_cert Result
val bytes_of_certificate: pri_cert -> bytes