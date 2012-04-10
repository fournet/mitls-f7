module AEAD

open Bytes
open Error
open TLSInfo
open DataStream
open AEADPlain

type AEADKey

type cipher = bytes

val GEN: KeyInfo -> AEADKey * AEADKey
val COERCE: KeyInfo -> bytes -> AEADKey
val LEAK: KeyInfo -> AEADKey -> bytes

val encrypt: KeyInfo -> AEADKey -> data -> 
             range -> AEADPlain -> (AEADKey * cipher)
val decrypt: KeyInfo -> AEADKey -> data -> 
             cipher -> (AEADKey * range * AEADPlain) Result
