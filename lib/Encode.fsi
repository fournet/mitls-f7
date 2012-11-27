module Encode

open Bytes
open TLSInfo
open TLSConstants

type data = bytes

type AEPlain

val AEPlain: epoch -> range -> data -> bytes -> AEPlain
val AERepr:  epoch -> range -> data -> AEPlain -> bytes

//val AEConstruct: epoch -> range -> data -> fragment -> AEPlain
//val AEContents:  epoch -> range -> data -> AEPlain -> fragment

type MACPlain
type tag
val macPlain: epoch -> range -> data -> AEPlain -> MACPlain
val mac: epoch -> MAC.key -> MACPlain -> tag
val verify: epoch -> MAC.key -> MACPlain -> tag -> bool

type plain

val plain: epoch -> nat -> bytes -> plain
val repr: epoch -> nat -> plain -> bytes

val encode: epoch -> range -> data -> AEPlain -> tag -> nat * plain
val encodeNoPad: epoch -> range -> data -> AEPlain -> tag -> nat * plain

val decode: epoch -> data -> nat -> plain -> (range * AEPlain * tag * bool)
val decodeNoPad: epoch -> data -> nat -> plain -> (range * AEPlain * tag)

val AEADPlainToAEPlain: epoch -> range -> AEADPlain.data -> AEADPlain.AEADPlain -> AEPlain
val AEPlainToAEADPlain: epoch -> range -> AEADPlain.data -> AEPlain -> AEADPlain.AEADPlain
