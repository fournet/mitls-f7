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

val AEAD_ENC: KeyInfo -> AEADKey -> ivOpt -> data -> plain -> (iv * cipher) Result
val AEAD_DEC: KeyInfo -> AEADKey -> iv -> data -> cipher -> (ivOpt * plain) Result

#if f7

type (;ki:KeyInfo) AEADKey =
    | MtE of MAC.macKey * ENC.symKey
 (* | GCM of GCM.GCMKey *)

type (;ki:KeyInfo) data
type (;ki:KeyInfo) plain
type (;ki:KeyInfo) cipher

val ENC: ki:KeyInfo -> (;ki) AEADKey -> (;ki) data -> (;ki) plain -> ((;ki) cipher) Result
val DEC: ki:KeyInfo -> (;ki) AEADKey -> (;ki) data -> (;ki) cipher -> ((;ki) plain) Result

#endif