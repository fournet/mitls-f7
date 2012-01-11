module TLSKey

open TLSInfo

type AEADKey =
    | MtE of Mac.key * ENC.symKey
 (* | GCM of GCM.GCMSalt * GCM.GCMKey *)

type recordKey =
    | RecordAEADKey of AEADKey
    | RecordMACKey of Mac.key
    | NoneKey

type ccs_data =
    { key: recordKey;
      iv3: ENC.iv3;
    }
val nullCCSData: KeyInfo -> ccs_data