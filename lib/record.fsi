module Record

open Data
open Tcp
open Formats
open Error_handling
open Sessions

type CipherState = 
  | BlockCipherState of Crypto.key * bytes    // (key,iv)
  | StreamCipherState

(* Internal interface for individual record processing *)

type fragment = bytes (* f:bytes { f.Length in 0..2^14-1 } *)

type preDirection =
    | CtoS
    | StoC

type Direction = preDirection

type ConnectionState
type sendState = ConnectionState (* both implemented as ConnectionState for now *)
type recvState = ConnectionState
type ccs_data = {
    ccs_info: SessionInfo;
    ccs_pv: ProtocolVersionType;
    ccs_comp: Compression;
    ccs_sparams: SecurityParameters;
    ccs_mkey: Crypto.key;
    ccs_ciphstate: CipherState}

val create: NetworkStream -> SessionInfo -> ProtocolVersionType -> sendState * recvState
(* we do not explicitly close connection states *)

val send: sendState -> ContentType -> fragment -> sendState Result
val send_setVersion: sendState -> ProtocolVersionType -> sendState
val send_setCrypto:  sendState -> ccs_data -> sendState

val dataAvailable: recvState -> bool Result
val recv: recvState -> (ContentType * fragment * recvState) Result
val recv_setVersion: recvState -> ProtocolVersionType -> recvState (* server-side only *)
val recv_checkVersion: recvState -> ProtocolVersionType -> unit Result    (* client-side only *)
val recv_setCrypto:  recvState -> ccs_data -> recvState

val coherentrw: SessionInfo -> recvState -> sendState -> bool

(* ProtocolVersion: 
  - the interface can be used only for setting and checking them (they are never passed up)
  - initially, sendState is the minimal and recvState is Unknown. 
  - for receiving only, the "Unknown" ProtocolVersion means that we do not know yet, 
    so we are accepting any reasonable one in each record.
    Conservatively, we change from Unknown to the first received version. *)

(* for now, we do not provide an interface for reporting sequence number overflows *)

 