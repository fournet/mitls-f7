module AEPlain

open Bytes
open TLSInfo
open Formats
open DataStream
open Fragment

type data = bytes

type AEPlain

val AEPlain: KeyInfo -> range -> data -> bytes -> AEPlain
val AERepr:  KeyInfo -> range -> data -> AEPlain -> bytes

val AEConstruct: KeyInfo -> range -> data -> fragment -> AEPlain
val AEContents:  KeyInfo -> range -> data -> AEPlain -> fragment

type MACPlain
type tag
val macPlain: KeyInfo -> range -> data -> AEPlain -> MACPlain
val mac: KeyInfo -> MAC.key -> MACPlain -> tag
val verify: KeyInfo -> MAC.key -> MACPlain -> tag -> bool

type plain

val plain: KeyInfo -> nat -> bytes -> plain
val repr: KeyInfo -> nat -> plain -> bytes

val encode: KeyInfo -> range -> data -> AEPlain -> tag -> nat * plain
val encodeNoPad: KeyInfo -> range -> data -> AEPlain -> tag -> nat * plain

val decode: KeyInfo -> data -> nat -> plain -> (range * AEPlain * tag * bool)
val decodeNoPad: KeyInfo -> data -> nat -> plain -> (range * AEPlain * tag)

