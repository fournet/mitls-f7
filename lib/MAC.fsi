module MAC

open Bytes
open Algorithms
// open TLSInfo

type id = {ki:TLSInfo.KeyInfo; tlen:int}

val MAC:    id -> MACKey.key -> MACPlain.MACPlain -> MACPlain.MACed
val VERIFY: id -> MACKey.key -> MACPlain.MACPlain -> MACPlain.MACed -> bool