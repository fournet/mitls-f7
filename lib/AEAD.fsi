module AEAD

open Data
open Error_handling
open TLSInfo
open MAC
open ENC

type AEADKey =
    | MtE of HMAC.macKey * ENC.symKey
 (* | GCM of GCM.GCMSalt * GCM.GCMKey *)

type data = bytes (* Additional data, includes seq_num *)
type plain = bytes
type cipher = bytes

val AEAD_ENC: KeyInfo -> AEADKey -> ivOpt -> data -> plain -> (ivOpt * cipher) Result
val AEAD_DEC: KeyInfo -> AEADKey -> ivOpt -> data -> cipher -> (ivOpt * plain) Result