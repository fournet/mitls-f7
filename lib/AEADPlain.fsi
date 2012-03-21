module AEADPlain
open Bytes
open Error
open TLSInfo
open DataStream
open StatefulPlain

type data = bytes
type plain 

val plain: KeyInfo -> range -> data -> bytes -> plain
val repr:  KeyInfo -> range -> data -> plain -> bytes

val fragmentToPlain: KeyInfo -> TLSFragment.history -> data -> range -> fragment -> plain
val plainToFragment: KeyInfo -> TLSFragment.history -> data -> range -> plain -> fragment
