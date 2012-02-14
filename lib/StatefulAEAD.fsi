omodule StatefulAEAD

open Bytes
open Error
open TLSInfo
open TLSKey

val encrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> DataStream.range -> TLSFragment.addData -> StatefulPlain.fragmentSequence -> StatefulPlain.fragment -> 
  (ENCKey.iv3 * ENC.cipher * StatefulPlain.fragmentSequence)
val decrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> DataStream.range -> TLSFragment.addData -> StatefulPlain.fragmentSequence -> ENC.cipher -> 
  (ENCKey.iv3 * StatefulPlain.fragment * StatefulPlain.fragmentSequence) Result
