module LHAE

open Bytes
open Error
open TLSError
open TLSInfo
open LHAEPlain
open Range

type LHAEKey

type cipher = bytes

val GEN: epoch -> LHAEKey * LHAEKey
val COERCE: epoch -> bytes -> LHAEKey
val LEAK: epoch -> LHAEKey -> bytes

val encrypt: epoch -> LHAEKey -> adata -> 
             range -> plain -> (LHAEKey * cipher)
val decrypt: epoch -> LHAEKey -> adata -> 
             cipher -> (LHAEKey * range * plain) Result
