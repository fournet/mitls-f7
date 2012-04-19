module AEAD

open Bytes
open Error
open TLSInfo
open DataStream
open AEADPlain

type AEADKey

type cipher = bytes

val GEN: epoch -> AEADKey * AEADKey
val COERCE: epoch -> bytes -> AEADKey
val LEAK: epoch -> AEADKey -> bytes

val encrypt: epoch -> AEADKey -> data -> 
             range -> AEADPlain -> (AEADKey * cipher)
val decrypt: epoch -> AEADKey -> data -> 
             cipher -> (AEADKey * range * AEADPlain) Result
