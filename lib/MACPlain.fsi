module MACPlain

open Bytes
open TLSInfo
open Formats

// Plaintext of MAC (addData + TLSFragment.fragment)
type MACPlain
val MACPlain: KeyInfo -> int -> TLSFragment.addData -> TLSFragment.AEADPlain -> MACPlain
val reprMACPlain: KeyInfo -> int -> MACPlain -> bytes

// Result of MAC
type MACed
val MACed: KeyInfo -> int -> bytes -> MACed
val reprMACed: KeyInfo -> int -> MACed -> bytes

// MAC-only ciphersuites
val parseNoPad: KeyInfo -> int -> TLSFragment.addData -> bytes -> (TLSFragment.AEADPlain * MACed)
