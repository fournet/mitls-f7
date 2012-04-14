module AEADPlain
open Bytes
open TLSInfo
open DataStream
open Fragment
open AEPlain

type data = bytes
type AEADPlain

val AEADPlain: KeyInfo -> range -> data -> bytes -> AEADPlain
val AEADRepr:  KeyInfo -> range -> data -> AEADPlain -> bytes

val contents:  KeyInfo -> range -> data -> AEADPlain -> fragment
val construct: KeyInfo -> range -> data -> fragment -> AEADPlain

val AEADPlainToAEPlain: KeyInfo -> range -> data -> AEADPlain -> AEPlain
val AEPlainToAEADPlain: KeyInfo -> range -> data -> AEPlain -> AEADPlain
