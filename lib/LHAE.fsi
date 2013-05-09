module LHAE

open Bytes
open Error
open TLSError
open TLSInfo
open LHAEPlain
open Range

type LHAEKey

type cipher = bytes

val GEN: id -> LHAEKey * LHAEKey
val COERCE: id -> bytes -> LHAEKey
val LEAK: id -> LHAEKey -> bytes

val encrypt: id -> LHAEKey -> adata -> 
             range -> plain -> (LHAEKey * cipher)
val decrypt: id -> LHAEKey -> adata -> 
             cipher -> (LHAEKey * range * plain) Result
