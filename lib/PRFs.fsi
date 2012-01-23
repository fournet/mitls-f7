module PRFs

open Bytes
open Formats
open TLSInfo
open RSA
open Error

(* Used when generating verifiData for the Finished message *)
type masterSecret
val empty_masterSecret: SessionInfo -> masterSecret
val prfVerifyData: KeyInfo -> masterSecret ->
                   bytes (* msgLog *) ->
                   bytes (* length depends on cs, 12 by default *)

(* Used when generating the MS from the PMS *)
type preMasterSecret
(* TODO: this only works for RSA, when client arbitrarily chooses PMS. A different interface is required for DH *)
(* Note: we need an external version type, and not the one contained in the session info. This is because
   we need to use the highest client supported version type, and not the negotiated one, to avoid version rollback attacks. *)
(* Client side: use genPMS and rsaEncryptPMS separately, by now. No idea yet on how to do it computationally-friendly *)
val genPMS: SessionInfo -> CipherSuites.ProtocolVersion -> preMasterSecret
val rsaEncryptPMS: SessionInfo -> asymKey -> preMasterSecret -> bytes Result
(* Server side: embed RSA decryiption and some sanity checks. Again, fully flexibility in making this computationally-friendly *)
val getPMS: SessionInfo -> CipherSuites.ProtocolVersion -> bool -> (* Whether we should check protocol version in old TLS versions *)
        Principal.cert -> bytes ->
        preMasterSecret (* No Result type: in case of error, we return random value *)

val empty_pms: SessionInfo -> preMasterSecret (* Used to implement a dummy DH key exchange *)

val prfMS: SessionInfo -> preMasterSecret ->
           (* No label, it's hardcoded. Of course we can make it explicit -> *)
           (* No seed (crandom @| srandom), it can be retrieved from SessionInfo -> *)
           masterSecret (* of length 48 *)

(* Used when generating key material from the MS. The result must still be split into the various keys. Of course this method can do the splitting internally and return a record/pair *)
type keyBlob
val prfKeyExp: KeyInfo -> masterSecret ->
               (* No label, it's hardcoded. Of course we can make it explicit -> *)
               (* No seed (crandom @| srandom), it can be retrieved from KeyInfo (and not SessionInfo!) -> *)
               keyBlob (* length depends on cs *)

val splitKeys: KeyInfo -> keyBlob -> (MACKey.key * MACKey.key * ENCKey.key * ENCKey.key * bytes * bytes)