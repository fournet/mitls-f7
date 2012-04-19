module StatefulPlain
open Bytes
open Formats
open TLSInfo
open DataStream
open AEADPlain

type data = bytes

type prehistory
type history  = (nat * prehistory)
type fragment

val emptyHistory: epoch -> history
val addToHistory: epoch -> history -> data -> range -> fragment -> history

val makeAD: epoch -> history -> data -> AEADPlain.data

val fragment: epoch -> history -> data -> range -> bytes -> fragment
val repr:     epoch -> history -> data -> range -> fragment -> bytes

val contents:  epoch -> history -> data -> range -> fragment -> Fragment.fragment
val construct: epoch -> history -> data -> range -> Fragment.fragment -> fragment

val FragmentToAEADPlain: epoch -> history -> data -> range -> fragment -> AEADPlain
val AEADPlainToFragment: epoch -> history -> data -> range -> AEADPlain -> fragment