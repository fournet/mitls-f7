module TLSFragment

open Bytes
open TLSInfo
open Formats
open CipherSuites
open DataStream
open StatefulPlain

type history

type fragment =
    | FHandshake of delta // Handshake.fragment
    | FCCS of delta // Handshake.ccsFragment
    | FAlert of delta // Alert.fragment
    | FAppData of delta // AppDataStream.fragment

val emptyHistory: KeyInfo -> history
val addToStreams: KeyInfo -> ContentType -> history -> range -> fragment -> history

val makeAD: KeyInfo -> ContentType -> data

val fragment: KeyInfo -> ContentType -> history -> range -> bytes -> fragment
val repr:     KeyInfo -> ContentType -> history -> range -> fragment -> bytes

val contents:  KeyInfo -> ContentType -> history -> range -> fragment -> sbytes
val construct: KeyInfo -> ContentType -> history -> range -> sbytes -> fragment

val TLSFragmentToFragment: KeyInfo -> ContentType -> history -> StatefulPlain.history -> range -> fragment -> StatefulPlain.fragment
val fragmentToTLSFragment: KeyInfo -> ContentType -> history -> StatefulPlain.history -> range -> StatefulPlain.fragment -> fragment