module PRFs

open Data
open Formats
open TLSInfo
open Error_handling

(* Used when generating verifiData for the Finished message *)
type masterSecret
val empty_masterSecret: masterSecret
val prfVerifyData: KeyInfo -> masterSecret ->
                   Direction (* From which a label is derived *) ->
                   bytes (* msgLog *) ->
                   bytes Result (* length depends on cs, 12 by default *)

(* Used when generating the MS from the PMS *)
type preMasterSecret
val prfMS: SessionInfo -> preMasterSecret ->
           (* No label, it's hardcoded. Of course we can make it explicit -> *)
           (* No seed (crandom @| srandom), it can be retrieved from SessionInfo -> *)
           masterSecret Result (* of length 48 *)

(* Used when generating key material from the MS. The result must still be split into the various keys. Of course this method can do the splitting internally and return a record/pair *)
type keyBlob
val prfKeyExp: KeyInfo -> masterSecret ->
               (* No label, it's hardcoded. Of course we can make it explicit -> *)
               (* No seed (crandom @| srandom), it can be retrieved from KeyInfo (and not SessionInfo!) -> *)
               keyBlob Result (* length depends on cs *)

val splitKeys: KeyInfo -> KeyInfo -> keyBlob -> (MAC.macKey * MAC.macKey * ENC.symKey * ENC.symKey * bytes * bytes)

#if f7
type (;si:SessionInfo) masterSecret
type (;ki:KeyInfo) msgLog

val prfVerifyData: ki:KeyInfo ->
                   (;ki.sinfo) masterSecret ->
                   (;ki) msgLog ->
                   bytes Result (* prfResult type? *)
#endif