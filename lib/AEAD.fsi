module AEAD

open Bytes
open Error
open TLSInfo
open AEADPlain
open Range

type AEADKey

type cipher = bytes

val GEN: epoch -> AEADKey * AEADKey
val COERCE: epoch -> bytes -> AEADKey
val LEAK: epoch -> AEADKey -> bytes

val encrypt: epoch -> AEADKey -> adata -> 
             range -> plain -> (AEADKey * cipher)
val decrypt: epoch -> AEADKey -> adata -> 
             cipher -> (AEADKey * range * plain) Result
