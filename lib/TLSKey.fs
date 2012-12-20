module TLSKey

open TLSInfo

type AEADKey =
    | MtE of MAC.key * ENCKey.key
    | MACOnly of MAC.key
 (* | GCM of GCM.GCMKey *)

type recordKey =
    | RecordAEADKey of AEADKey
    | NoneKey

type ccs_data =
    { ccsKey: recordKey;
      ccsIV3: ENCKey.iv3;
    }

let nullCCSData (ki:KeyInfo) =
    { ccsKey = NoneKey;
      ccsIV3 = ENCKey.NoIV true}
