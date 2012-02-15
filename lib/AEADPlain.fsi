module AEADPlain
open Bytes
open Error
open TLSInfo
open DataStream
open StatefulPlain

type addData = bytes
type plain 

val plain: KeyInfo ->  range -> addData -> bytes -> plain
val repr:  KeyInfo -> range -> addData -> plain -> bytes
val fragmentToPlain: KeyInfo -> state -> addData -> range -> fragment -> plain
val plainToFragment: KeyInfo -> state -> addData -> range -> plain -> fragment
