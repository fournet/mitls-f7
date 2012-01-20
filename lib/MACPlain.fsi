module MACPlain

open Bytes
open TLSInfo

// Plaintext of MAC (addData + TLSFragment.fragment)
type MACPlain
val MACPlain: KeyInfo -> int -> TLSFragment.addData -> TLSFragment.AEADFragment -> MACPlain
val reprMACPlain: KeyInfo -> MACPlain -> bytes

// Result of MAC
type MACed
val MACed: KeyInfo -> bytes -> MACed
val reprMACed: KeyInfo -> MACed -> bytes

// MAC-only ciphersuites
val parseNoPad: KeyInfo -> int -> TLSFragment.addData -> bytes -> (TLSFragment.AEADFragment * MACed)