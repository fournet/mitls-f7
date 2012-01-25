module TLSKey

open TLSInfo

type AEADKey =
    | MtE of MACKey.key * ENCKey.key
 (* | GCM of GCM.GCMKey *)

type recordKey =
    | RecordAEADKey of AEADKey
    | RecordMACKey of MACKey.key
    | NoneKey

type ccs_data =
    { ccsKey: recordKey;
      ccsIV3: ENCKey.iv3;
    }

let nullCCSData (ki:KeyInfo) =
    { ccsKey = NoneKey;
      ccsIV3 = ENCKey.NoIV ()}