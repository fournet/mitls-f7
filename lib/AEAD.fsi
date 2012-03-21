module AEAD

open Bytes
open Error
open TLSInfo

type AEADKey =
    | MtE of MAC.key * ENC.state
    | MACOnly of MAC.key
(*  |   GCM of AENC.state  *)

val encrypt: KeyInfo -> AEADKey -> AEADPlain.data -> 
             DataStream.range -> AEADPlain.plain -> (AEADKey * bytes)
val decrypt: KeyInfo -> AEADKey -> AEADPlain.data -> 
             bytes -> (AEADKey * DataStream.range * AEADPlain.plain) Result
