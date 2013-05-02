module StatefulLHAE

open Bytes
open Error
open TLSError
open TLSInfo
open Range

open StatefulPlain 

type state
type reader = state
type writer = state

val GEN: epoch -> reader * writer
val COERCE: epoch -> rw -> bytes -> state
val LEAK: epoch -> rw -> state -> bytes

val history: epoch -> rw -> state -> history

type cipher = ENC.cipher

val encrypt: epoch -> writer ->  adata -> range -> plain -> (writer * cipher)
val decrypt: epoch -> reader ->  adata -> cipher -> (reader * range * plain) Result
