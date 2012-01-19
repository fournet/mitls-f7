module MACPlain

open Bytes
open TLSInfo

// Plaintext of MAC (addData + TLSFragment.fragment)
type MACPlain
type addData = bytes
val MACPlain: KeyInfo -> int -> addData -> TLSFragment.fragment -> MACPlain
val reprMACPlain: KeyInfo -> MACPlain -> bytes

// Result of MAC
type MACed
val MACed: KeyInfo -> bytes -> MACed
val reprMACed: KeyInfo -> MACed -> bytes