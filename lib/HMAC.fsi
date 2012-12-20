module HMAC

open Bytes
open TLSConstants

type key = bytes
type data = bytes
type mac = bytes

val sslKeyedHash:       hashAlg -> key -> data -> mac
val sslKeyedHashVerify: hashAlg -> key -> data -> mac -> bool

val HMAC:       hashAlg -> key -> data -> mac
val HMACVERIFY: hashAlg -> key -> data -> mac -> bool