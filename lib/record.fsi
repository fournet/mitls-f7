module Record

open Bytes
open Tcp
open Formats
open Error
open TLSInfo
open TLSPlain
open CipherSuites

type ConnectionState
type sendState = ConnectionState (* both implemented as ConnectionState for now *)
type recvState = ConnectionState

type recordKey =
    | RecordAEADKey of AEAD.AEADKey
    | RecordMACKey of Mac.key
    | NoneKey

type ccs_data =
    { ki: KeyInfo;
      key: recordKey;
      iv3: ENC.iv3;
    }

val create: KeyInfo -> KeyInfo -> ProtocolVersionType -> sendState * recvState
(* we do not explicitly close connection states *)

val recordPacketOut: sendState -> int -> ContentType -> fragment -> (sendState * bytes)
val send_setVersion: sendState -> ProtocolVersionType -> sendState
val send_setCrypto:  ccs_data -> sendState

(* val dataAvailable: recvState -> bool Result *)
val recordPacketIn: recvState -> bytes -> (recvState * ContentType * int * fragment) Result
val recv_setVersion: recvState -> ProtocolVersionType -> recvState (* server-side only *)
val recv_checkVersion: recvState -> ProtocolVersionType -> unit Result    (* client-side only *)
val recv_setCrypto:  ccs_data -> recvState

(* val coherentrw: SessionInfo -> recvState -> sendState -> bool *)

(* ProtocolVersion: 
  - the interface can be used only for setting and checking them (they are never passed up)
  - initially, sendState is the minimal and recvState is Unknown. 
  - for receiving only, the "Unknown" ProtocolVersion means that we do not know yet, 
    so we are accepting any reasonable one in each record.
    Conservatively, we change from Unknown to the first received version. *)

(* for now, we do not provide an interface for reporting sequence number overflows *)

 
