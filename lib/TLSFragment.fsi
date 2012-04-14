module TLSFragment

open Bytes
open TLSInfo
open Formats
open CipherSuites
open DataStream
open StatefulPlain

type history

type fragment =
    | FHandshake of Fragment.fragment
    | FCCS of Fragment.fragment
    | FAlert of Fragment.fragment
    | FAppData of Fragment.fragment

val emptyHistory: KeyInfo -> history
val addToStreams: KeyInfo -> ContentType -> history -> range -> fragment -> history

val makeAD: KeyInfo -> ContentType -> data 
val fragmentPlain: KeyInfo -> ContentType -> history -> range -> bytes -> fragment
val fragmentRepr:     KeyInfo -> ContentType -> history -> range -> fragment -> bytes

val contents:  KeyInfo -> ContentType -> history -> range -> fragment -> Fragment.fragment
val construct: KeyInfo -> ContentType -> history -> range -> Fragment.fragment -> fragment

val TLSFragmentToFragment: KeyInfo -> ContentType -> history -> StatefulPlain.history -> range -> fragment -> StatefulPlain.fragment
val fragmentToTLSFragment: KeyInfo -> ContentType -> history -> StatefulPlain.history -> range -> StatefulPlain.fragment -> fragment
