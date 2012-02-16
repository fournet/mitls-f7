module AEADPlain
open Bytes
open Error
open TLSInfo
open DataStream
open StatefulPlain

type data = bytes
type plain 

val plain: KeyInfo ->  range -> data -> bytes -> plain
val repr:  KeyInfo -> range -> data -> plain -> bytes

val fragmentToPlain: KeyInfo -> state -> data -> range -> fragment -> plain
val plainToFragment: KeyInfo -> state -> data -> range -> plain -> fragment
