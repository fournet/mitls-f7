module MACPlain

open Bytes
open TLSInfo
open Formats
open DataStream
// Plaintext of MAC (addData + TLSFragment.fragment)
type MACPlain
val MACPlain: KeyInfo -> range -> TLSFragment.addData -> AEADPlain.plain -> MACPlain
val reprMACPlain: KeyInfo -> range -> MACPlain -> bytes

// Result of MAC
type MACed
val MACed: KeyInfo -> range -> bytes -> MACed
val reprMACed: KeyInfo -> range -> MACed -> bytes

// MAC-only ciphersuites
val parseNoPad: KeyInfo -> range -> TLSFragment.addData -> bytes -> (AEADPlain.plain * MACed)
