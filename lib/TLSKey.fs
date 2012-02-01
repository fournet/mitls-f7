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
      ccsIV3 = ENCKey.NoIV true}

let reIndex oldKI newKI recKey =
    match recKey with
    | NoneKey -> NoneKey
    | RecordMACKey(mk) ->
        let newMACKey = MACKey.reIndex oldKI newKI mk in
        RecordMACKey(newMACKey)
    | RecordAEADKey(aeadK) ->
        match aeadK with
        | MtE(mk,ek) ->
            let newMK = MACKey.reIndex oldKI newKI mk in
            let newEK = ENCKey.reIndexKey oldKI newKI ek in
            RecordAEADKey(MtE(newMK,newEK))