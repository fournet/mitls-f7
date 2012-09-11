module PRFs

open Bytes
open Formats
open TLSInfo
open RSA
open Error

(* see .fs7 for comments *) 

type preMasterSecret
val genPMS: SessionInfo -> CipherSuites.ProtocolVersion -> preMasterSecret
val rsaEncryptPMS: SessionInfo -> asymKey -> preMasterSecret -> bytes Result
val getPMS: SessionInfo -> CipherSuites.ProtocolVersion -> bool -> Certificate.cert -> bytes -> preMasterSecret

val empty_pms: SessionInfo -> preMasterSecret (* Used to implement a dummy DH key exchange *)


type masterSecret
val empty_masterSecret: SessionInfo -> masterSecret (*$ deprecate? *)

(* Generates verifyData for the Finished message *)

val prfVerifyData: SessionInfo -> Role -> masterSecret -> bytes (* msgLog *) -> bytes (* length depends on cs, 12 by default *)

val prfMS: SessionInfo -> preMasterSecret ->
           (* No label, it's hardcoded. Of course we can make it explicit -> *)
           (* No seed (crandom @| srandom), it can be retrieved from SessionInfo -> *)
           masterSecret (* of length 48 *)

(* Used when generating key material from the MS. 
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)

type keyBlob
val prfKeyExp: ConnectionInfo -> masterSecret -> keyBlob (* length depends on cs *)
    (* No label, it's hardcoded. Of course we can make it explicit -> *)
    (* No seed (crandom @| srandom), it can be retrieved from epoch (and not SessionInfo!) -> *)

val splitStates: ConnectionInfo -> keyBlob -> (StatefulAEAD.state * StatefulAEAD.state)

val makeTimestamp: unit -> int
