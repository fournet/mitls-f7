module StatefulAEAD

open Bytes
open Error
open TLSInfo
open DataStream
open StatefulPlain 

type prestate
type state = prestate
type reader = state
type writer = state

val GEN: epoch -> state * state
val COERCE: epoch -> bytes -> state
val LEAK: epoch -> state -> bytes

val history: epoch -> state -> history

type cipher = ENC.cipher

val encrypt: epoch -> writer ->  data -> range -> fragment -> 
  (writer * cipher)

val decrypt: epoch -> reader ->  data -> cipher -> 
  (reader * range * fragment) Result
