module AEADPlain
open Bytes
open TLSInfo
open DataStream
open AEPlain

type data = bytes
type preAEADPlain
type AEADPlain = preAEADPlain

val AEADPlain: KeyInfo -> range -> data -> bytes -> AEADPlain
val AEADRepr:  KeyInfo -> range -> data -> AEADPlain -> bytes

val contents:  KeyInfo -> range -> data -> AEADPlain -> sbytes
val construct: KeyInfo -> range -> data -> sbytes -> AEADPlain

val AEADPlainToAEPlain: KeyInfo -> range -> data -> AEADPlain -> AEPlain
val AEPlainToAEADPlain: KeyInfo -> range -> data -> AEPlain -> AEADPlain
