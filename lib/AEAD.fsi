module AEAD

open Data
open Error_handling
open TLSInfo
open TLSPlain

type AEADKey =
    | MtE of MAC.macKey * ENC.symKey
 (* | GCM of GCM.GCMSalt * GCM.GCMKey *)

val AEAD_ENC: KeyInfo -> AEADKey -> ENC.ivOpt -> int -> add_data -> fragment -> (ENC.ivOpt * ENC.cipher) Result
val AEAD_DEC: KeyInfo -> AEADKey -> ENC.ivOpt -> int -> add_data -> ENC.cipher -> (ENC.ivOpt * fragment) Result