module AEAD

open Data
open Error
open TLSInfo
open TLSPlain

type AEADKey =
    | MtE of MAC.macKey * ENC.symKey
 (* | GCM of GCM.GCMSalt * GCM.GCMKey *)

val encrypt: KeyInfo -> AEADKey -> ENC.iv3 -> int -> add_data -> fragment -> (ENC.iv3 * ENC.cipher) Result
val decrypt: KeyInfo -> AEADKey -> ENC.iv3 -> int -> add_data -> ENC.cipher -> (ENC.iv3 * fragment) Result