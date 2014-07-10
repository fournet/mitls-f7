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

val GEN:    id -> reader * writer
val COERCE: id -> rw -> bytes -> state
val LEAK:   id -> rw -> state -> bytes

val history: id -> rw -> state -> history

type cipher = LHAE.cipher

val encrypt: id -> writer ->  adata -> range -> plain -> (writer * cipher)
val decrypt: id -> reader ->  adata -> cipher -> Result<(reader * range * plain)>
