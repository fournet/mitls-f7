module AEPlain

open Bytes
open TLSInfo
open Formats
open DataStream

type data = bytes

type AEPlain

val AEPlain: KeyInfo -> range -> data -> bytes -> AEPlain
val AERepr:  KeyInfo -> range -> data -> AEPlain -> bytes

val AEConstruct: KeyInfo -> range -> data -> sbytes -> AEPlain
val AEContents:  KeyInfo -> range -> data -> AEPlain -> sbytes

type MACPlain
type tag
val concat: KeyInfo -> range -> data -> AEPlain -> MACPlain
val mac: KeyInfo -> MAC.key -> MACPlain -> tag
val verify: KeyInfo -> MAC.key -> MACPlain -> tag -> bool

// only for MACOnly ciphersuites, untile they get integrated into AEAD
val tagRepr: KeyInfo -> tag -> bytes

type plain

val plain: KeyInfo -> nat -> bytes -> plain
val repr: KeyInfo -> nat -> plain -> bytes

val encode: KeyInfo -> range -> data -> AEPlain -> tag -> nat * plain
val encodeNoPad: KeyInfo -> range -> data -> AEPlain -> tag -> nat * plain

val decode: KeyInfo -> data -> nat -> plain -> (range * AEPlain * tag * bool)
val decodeNoPad: KeyInfo -> data -> nat -> plain -> (range * AEPlain * tag)

