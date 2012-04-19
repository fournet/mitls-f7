module AEADPlain
open Bytes
open TLSInfo
open DataStream
open Fragment
open AEPlain

type data = bytes
type AEADPlain

val AEADPlain: epoch -> range -> data -> bytes -> AEADPlain
val AEADRepr:  epoch -> range -> data -> AEADPlain -> bytes

val contents:  epoch -> range -> data -> AEADPlain -> fragment
val construct: epoch -> range -> data -> fragment -> AEADPlain

val AEADPlainToAEPlain: epoch -> range -> data -> AEADPlain -> AEPlain
val AEPlainToAEADPlain: epoch -> range -> data -> AEPlain -> AEADPlain
