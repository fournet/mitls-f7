module TLSKey

open TLSInfo

type AEADKey =
    | MtE of MAC.key * ENCKey.key
    | MACOnly of MAC.key
 (* | GCM of GCM.GCMSalt * GCM.GCMKey *)

type recordKey =
    | RecordAEADKey of AEADKey
    | NoneKey

type ccs_data =
    { ccsKey: recordKey;
      ccsIV3: ENCKey.iv3;
    }
val nullCCSData: KeyInfo -> ccs_data
