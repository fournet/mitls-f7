module StatefulAEAD

open Bytes
open Error
open TLSInfo
open TLSKey

val encrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> DataStream.range -> 
  StatefulPlain.addData -> StatefulPlain.state -> StatefulPlain.fragment -> 
  (ENCKey.iv3 * ENC.cipher * StatefulPlain.state)

val decrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> DataStream.range -> 
  StatefulPlain.addData -> StatefulPlain.state -> ENC.cipher -> 
  (ENCKey.iv3 * StatefulPlain.fragment * StatefulPlain.state) Result
