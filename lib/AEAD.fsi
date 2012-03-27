module AEAD

open Bytes
open Error
open TLSInfo

type AEADKey

type cipher = bytes

val GEN: KeyInfo -> AEADKey * AEADKey
val COERCE: KeyInfo -> bytes -> AEADKey
val LEAK: KeyInfo -> AEADKey -> bytes

val encrypt: KeyInfo -> AEADKey -> AEADPlain.data -> 
             DataStream.range -> AEADPlain.plain -> (AEADKey * cipher)
val decrypt: KeyInfo -> AEADKey -> AEADPlain.data -> 
             cipher -> (AEADKey * DataStream.range * AEADPlain.plain) Result
