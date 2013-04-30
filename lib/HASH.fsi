module HASH

open Bytes
open TLSConstants

val hash: hashAlg -> bytes -> bytes