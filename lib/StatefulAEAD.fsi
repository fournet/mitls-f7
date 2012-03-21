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

val initState: KeyInfo -> AEAD.AEADKey -> state

val history: KeyInfo -> state -> TLSFragment.history

type cipher = ENC.cipher

val encrypt: KeyInfo -> writer ->  data -> DataStream.range -> fragment -> 
  (writer * cipher)

val decrypt: KeyInfo -> reader ->  data -> cipher -> 
  (reader * range * fragment) Result
