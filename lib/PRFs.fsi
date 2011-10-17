module PRFs

open Data
open Formats
open TLSInfo
open Error_handling

(* Used when generating verifiData for the Finished message *)
type masterSecret = bytes
val prfVerifyData: KeyInfo -> masterSecret ->
                   role (* From which a label is derived *) ->
                   bytes (* msgLog *) ->
                   bytes Result (* length depends on cs, 12 by default *)

(* Used when generating the MS from the PMS *)
type preMasterSecret = bytes
val prfMS: SessionInfo -> preMasterSecret ->
           (* No label, it's hardcoded. Of course we can make it explicit -> *)
           (* No seed (crandom @| srandom), it can be retrieved from SessionInfo -> *)
           bytes Result (* of length 48 *)

(* Used when generating key material from the MS. The result must still be split into the various keys. Of course this method can do the splitting internally and return a record/pair *)
val prfKeyExp: KeyInfo -> masterSecret ->
               (* No label, it's hardcoded. Of course we can make it explicit -> *)
               (* No seed (crandom @| srandom), it can be retrieved from KeyInfo (and not SessionInfo!) -> *)
               bytes Result (* length depends on cs *)

#if f7
type (;si:SessionInfo) masterSecret
type (;ki:KeyInfo) msgLog

val prfVerifyData: ki:KeyInfo ->
                   (;ki.sinfo) masterSecret ->
                   (;ki) msgLog ->
                   bytes Result (* prfResult type? *)
#endif