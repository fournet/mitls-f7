module StatefulPlain
open Bytes
open TLSConstants
open TLSInfo
open DataStream
open AEADPlain

type data = bytes

type prehistory = (data * range * Fragment.fragment) list
type history  = (nat * prehistory)
type statefulPlain

val emptyHistory: epoch -> history
val addToHistory: epoch -> history -> data -> range -> statefulPlain -> history

val makeAD: epoch -> history -> data -> AEADPlain.data

val statefulPlain: epoch -> history -> data -> range -> bytes -> statefulPlain
val statefulRepr:     epoch -> history -> data -> range -> statefulPlain -> bytes

val contents:  epoch -> history -> data -> range -> statefulPlain -> Fragment.fragment
val construct: epoch -> history -> data -> range -> Fragment.fragment -> statefulPlain
 
val StatefulToAEADPlain: epoch -> history -> data -> range -> statefulPlain -> AEADPlain
val AEADPlainToStateful: epoch -> history -> data -> range -> AEADPlain -> statefulPlain
