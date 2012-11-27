module AEADPlain
open Bytes
open TLSInfo
open StatefulPlain

type data = bytes
type AEADPlain

val AEADPlain: epoch -> range -> data -> bytes -> AEADPlain
val AEADRepr:  epoch -> range -> data -> AEADPlain -> bytes

//val contents:  epoch -> range -> data -> AEADPlain -> fragment
//val construct: epoch -> range -> data -> fragment -> AEADPlain

val makeAD: epoch -> history -> StatefulPlain.data -> data
val parseAD: epoch -> data -> StatefulPlain.data
val StatefulToAEADPlain: epoch -> history -> StatefulPlain.data -> range -> statefulPlain -> AEADPlain
val AEADPlainToStateful: epoch -> history -> StatefulPlain.data -> range -> AEADPlain -> statefulPlain