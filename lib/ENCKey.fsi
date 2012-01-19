module ENCKey

open Bytes
open TLSInfo

type key

val keysize: KeyInfo -> int

val GEN: KeyInfo -> key
val LEAK:   KeyInfo -> key -> bytes
val COERCE: KeyInfo -> bytes -> key

type iv = bytes
type iv3 =
    | SomeIV of iv
    | NoIV of unit