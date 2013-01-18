module HMAC

open Bytes
open TLSConstants

type key = bytes
type data = bytes
type mac = bytes

val MAC:       macAlg -> key -> data -> mac
val MACVERIFY: macAlg -> key -> data -> mac -> bool