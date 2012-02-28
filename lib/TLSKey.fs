module TLSKey

open TLSInfo

type AEADKey =
    | MtE of MAC.key * ENCKey.key
 (* | GCM of GCM.GCMKey *)

type recordKey =
    | RecordAEADKey of AEADKey
    | RecordMACKey of MAC.key
    | NoneKey

type ccs_data =
    { ccsKey: recordKey;
      ccsIV3: ENCKey.iv3;
    }

let nullCCSData (ki:KeyInfo) =
    { ccsKey = NoneKey;
      ccsIV3 = ENCKey.NoIV true}
