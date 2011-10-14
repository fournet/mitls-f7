module TLSCrypto

open Data
open Formats (* for ProtocolVersionType and role *)
open StdCrypto
open Algorithms
open HS_ciphersuites
open Error_handling

(* TLS-aware MAC function
   - Use standard HMAC for TLS
   - Use custom keyed hash for SSL
*)

val MAC: ProtocolVersionType -> hashAlg -> macKey -> bytes -> bytes Result
val VERIFY: ProtocolVersionType -> hashAlg -> macKey -> bytes -> bytes -> unit Result

(* PRF *)

(* Used when generating verifiData for the Finished message *)
type masterSecret
val prfVerifyData: ProtocolVersionType -> cipherSuite -> masterSecret -> role (* From which a label is derived *) -> bytes -> bytes Result (* length depends on cs, 12 by default *)

(* Used when generating the MS from the PMS *)
type preMasterSecret
val prfMS: ProtocolVersionType -> cipherSuite -> preMasterSecret -> (* No label, it's hardcoded. Of course we can make it explicit -> *) bytes (* crandom @| srandom, do we want bytes * bytes ? *) -> bytes Result (* of length 48 *)

(* Used when generating key material from the MS. The result must still be split into the various keys. Of course this method can do the splitting internally and return a record/pair *)
val prfKeyExp: ProtocolVersionType -> cipherSuite -> masterSecret -> (* No label, it's hardcoded. Of course we can make it explicit -> *) bytes (* crandom @| srandom, do we want bytes * bytes ? *) -> bytes Result (* length depends on cs *)

#if f7
type (;si:SessionInfo) masterSecret
type (;ki:KeyInfo) msgLog

val prfVerifyData: ki:KeyInfo ->
                   (;ki.sinfo) masterSecret ->
                   (;ki) msgLog ->
                   bytes Result (* prfResult type? *)
#endif