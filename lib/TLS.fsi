module TLS

open Bytes
open Error
open Dispatch
open TLSInfo
open Tcp
open DataStream

type ioresult_i =
    | ReadError of ioerror
    | Close     of Tcp.NetworkStream
    | Fatal     of alertDescription
    | Warning   of nextCn * alertDescription 
    | CertQuery of nextCn * query
    | Handshaken of Connection
    | Read      of nextCn * msg_i
    | DontWrite of Connection
    
type ioresult_o =
    | WriteError    of ioerror
    | WriteComplete of nextCn
    | WritePartial  of nextCn * msg_o
    | MustRead      of Connection

(* Event-driven interface *)

val read     : Connection -> ioresult_i
val write    : Connection -> msg_o -> ioresult_o
val shutdown : Connection -> Connection

val connect : NetworkStream -> config -> Connection
val resume  : NetworkStream -> sessionID -> config -> Connection Result

val rehandshake : Connection -> config -> bool * nextCn
val rekey       : Connection -> config -> bool * nextCn
val request     : Connection -> config -> bool * nextCn

val accept           : TcpListener   -> config -> Connection
val accept_connected : NetworkStream -> config -> Connection

val authorize: Connection -> query -> Connection
val refuse:    Connection -> query -> unit

val getEpochIn:  Connection -> epoch
val getEpochOut: Connection -> epoch
val getSessionInfo: epoch -> SessionInfo
val getInStream:  Connection -> stream
val getOutStream: Connection -> stream
