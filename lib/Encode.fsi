module Encode

open Bytes
open TLSInfo
open TLSConstants

type adata = AEADPlain.adata

type AEFragment
type AEPlain = AEFragment

val AEPlain: epoch -> range -> adata -> bytes -> AEPlain
val AERepr:  epoch -> range -> adata -> AEPlain -> bytes

//val AEConstruct: epoch -> range -> data -> fragment -> AEPlain
//val AEContents:  epoch -> range -> data -> AEPlain -> fragment

type MACPlain
type tag
val macPlain: epoch -> range -> adata -> AEPlain -> MACPlain
val mac: epoch -> MAC.key -> MACPlain -> tag
val verify: epoch -> MAC.key -> MACPlain -> tag -> bool

type plain

val plain: epoch -> nat -> bytes -> plain
val repr: epoch -> nat -> plain -> bytes

val encode: epoch -> range -> adata -> AEPlain -> tag -> nat * plain
val encodeNoPad: epoch -> range -> adata -> AEPlain -> tag -> nat * plain

val decode: epoch -> adata -> nat -> plain -> (range * AEPlain * tag * bool)
val decodeNoPad: epoch -> adata -> nat -> plain -> (range * AEPlain * tag)

val AEADPlainToAEPlain: epoch -> range -> AEADPlain.adata -> AEADPlain.plain -> AEPlain
val AEPlainToAEADPlain: epoch -> range -> AEADPlain.adata -> AEPlain -> AEADPlain.plain
