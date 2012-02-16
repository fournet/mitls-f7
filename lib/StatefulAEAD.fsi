module StatefulAEAD

open Bytes
open Error
open TLSInfo
open TLSKey
open DataStream
open StatefulPlain 

type cipher = ENC.cipher

val encrypt: KeyInfo -> writer ->  data -> DataStream.range -> fragment -> 
  (reader * cipher)

val decrypt: KeyInfo -> reader ->  data -> cipher -> 
  (reader * range * fragment) Result
