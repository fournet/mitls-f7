module TLS

open Bytes
open Error
open Dispatch
open TLSInfo
open Tcp
open DataStream

(* Event-driven interface *)

val read     : Connection -> ioresult_i
val write    : Connection -> msg_o -> ioresult_o
val shutdown : Connection -> Connection

val connect : NetworkStream -> protocolOptions -> Connection
val resume  : NetworkStream -> sessionID -> protocolOptions -> Connection Result

val rehandshake : Connection -> protocolOptions -> nextCn
val rekey       : Connection -> protocolOptions -> nextCn
val request     : Connection -> protocolOptions -> nextCn

val accept           : TcpListener   -> protocolOptions -> Connection
val accept_connected : NetworkStream -> protocolOptions -> Connection

val authorize: Connection -> query -> Connection
val refuse:    Connection -> query -> unit

val getEpochIn:  Connection -> epoch
val getEpochOut: Connection -> epoch
val getSessionInfo: epoch -> SessionInfo
val getInStream:  Connection -> stream
val getOutStream: Connection -> stream