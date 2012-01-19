module TLSKey

open TLSInfo

type AEADKey =
    | MtE of MACKey.key * ENCKey.key
 (* | GCM of GCM.GCMSalt * GCM.GCMKey *)

type recordKey =
    | RecordAEADKey of AEADKey
    | RecordMACKey of MACKey.key
    | NoneKey

type ccs_data =
    { key: recordKey;
      iv3: ENCKey.iv3;
    }
val nullCCSData: KeyInfo -> ccs_data