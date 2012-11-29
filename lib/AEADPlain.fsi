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

val makeAD: epoch -> history -> StatefulPlain.adata -> data
val parseAD: epoch -> data -> StatefulPlain.adata
val StatefulToAEADPlain: epoch -> history -> StatefulPlain.adata -> range -> plain -> AEADPlain
val AEADPlainToStateful: epoch -> history -> StatefulPlain.adata -> range -> AEADPlain -> plain