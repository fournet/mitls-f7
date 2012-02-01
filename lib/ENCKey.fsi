module ENCKey

open Bytes
open TLSInfo

type key

val GEN: KeyInfo -> key
val LEAK:   KeyInfo -> key -> bytes
val COERCE: KeyInfo -> bytes -> key

type iv = bytes
type iv3 =
    | SomeIV of iv
    | NoIV of bool

val reIndexKey: KeyInfo -> KeyInfo -> key -> key
val reIndexIV:  KeyInfo -> KeyInfo -> iv3 -> iv3