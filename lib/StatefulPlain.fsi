module StatefulPlain
open Bytes
open TLSConstants
open TLSInfo
open DataStream

type data = bytes

type prehistory = (data * range * Fragment.fragment) list
type history  = (nat * prehistory)
type statefulPlain

val emptyHistory: epoch -> history
val addToHistory: epoch -> history -> data -> range -> statefulPlain -> history

val statefulPlain: epoch -> history -> data -> range -> bytes -> statefulPlain
val statefulRepr:     epoch -> history -> data -> range -> statefulPlain -> bytes

val contents:  epoch -> history -> data -> range -> statefulPlain -> Fragment.fragment
val construct: epoch -> history -> data -> range -> Fragment.fragment -> statefulPlain

val makeAD: epoch -> ContentType -> data 
val TLSFragmentToFragment: epoch -> ContentType -> TLSFragment.history -> history -> range -> TLSFragment.fragment -> statefulPlain
val fragmentToTLSFragment: epoch -> ContentType -> TLSFragment.history -> history -> range -> statefulPlain -> TLSFragment.fragment
