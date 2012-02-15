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

let reIndex oldKI newKI recKey =
    match recKey with
    | NoneKey -> NoneKey
    | RecordMACKey(mk) ->
        let newMACKey = MAC.reIndex oldKI newKI mk in
        RecordMACKey(newMACKey)
    | RecordAEADKey(aeadK) ->
        match aeadK with
        | MtE(mk,ek) ->
            let newMK = MAC.reIndex oldKI newKI mk in
            let newEK = ENCKey.reIndexKey oldKI newKI ek in
            RecordAEADKey(MtE(newMK,newEK))