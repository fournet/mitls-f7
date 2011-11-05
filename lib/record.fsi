module Record

open Data
open Tcp
open Formats
open Error_handling
open TLSInfo
open TLSPlain
open HS_ciphersuites

type ConnectionState
type sendState = ConnectionState (* both implemented as ConnectionState for now *)
type recvState = ConnectionState

type recordKey =
    | RecordAEADKey of AEAD.AEADKey
    | RecordMACKey of HMAC.macKey
    | NoneKey

val create: KeyInfo -> KeyInfo -> ProtocolVersionType -> sendState * recvState
(* we do not explicitly close connection states *)

val recordPacketOut: sendState -> int -> ContentType -> fragment -> (sendState * bytes) Result
val send_setVersion: sendState -> ProtocolVersionType -> sendState
val send_setCrypto:  KeyInfo -> recordKey -> ENC.ivOpt -> sendState

(* val dataAvailable: recvState -> bool Result *)
val recordPacketIn: recvState -> int -> ContentType -> bytes -> (recvState * fragment) Result
val recv_setVersion: recvState -> ProtocolVersionType -> recvState (* server-side only *)
val recv_checkVersion: recvState -> ProtocolVersionType -> unit Result    (* client-side only *)
val recv_setCrypto:  KeyInfo -> recordKey -> ENC.ivOpt -> recvState

(* val coherentrw: SessionInfo -> recvState -> sendState -> bool *)

(* ProtocolVersion: 
  - the interface can be used only for setting and checking them (they are never passed up)
  - initially, sendState is the minimal and recvState is Unknown. 
  - for receiving only, the "Unknown" ProtocolVersion means that we do not know yet, 
    so we are accepting any reasonable one in each record.
    Conservatively, we change from Unknown to the first received version. *)

(* for now, we do not provide an interface for reporting sequence number overflows *)

 