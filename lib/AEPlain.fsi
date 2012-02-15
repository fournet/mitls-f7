module AEPlain

open Bytes
open TLSInfo
open Formats

type plain
val plain: KeyInfo -> DataStream.range -> bytes -> plain
val repr: KeyInfo -> DataStream.range -> plain -> bytes

type MACPlain
type tag
val concat: KeyInfo -> DataStream.range -> AEADPlain.addData -> AEADPlain.plain -> MACPlain
val mac: KeyInfo -> MAC.key -> MACPlain -> tag
val verify: KeyInfo -> MAC.key -> MACPlain -> tag -> bool

// only for MACOnly ciphersuites, untile they get integrated into AEAD
val tagRepr: KeyInfo -> tag -> bytes
val decodeNoPad: KeyInfo -> AEADPlain.addData -> plain -> (DataStream.range * AEADPlain.plain * tag)


val encode: KeyInfo -> DataStream.range -> AEADPlain.addData -> AEADPlain.plain -> tag -> plain
val decode: KeyInfo -> AEADPlain.addData -> plain -> (DataStream.range * AEADPlain.plain * tag * bool)
