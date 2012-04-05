module AEADPlain
open Bytes
open Error
open TLSInfo
open DataStream
open StatefulPlain

type data = bytes
type plain = sbytes

val plain: KeyInfo -> range -> data -> bytes -> plain
val repr:  KeyInfo -> range -> data -> plain -> bytes

val fragmentToPlain: KeyInfo -> history -> data -> range -> fragment -> plain
val plainToFragment: KeyInfo -> history -> data -> range -> plain -> fragment
