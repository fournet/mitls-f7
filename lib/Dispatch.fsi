module Dispatch

open Bytes
open Formats
open Tcp
open Error
open Record
open Handshake
open TLSInfo
open DataStream

[<NoEquality;NoComparison>]
type Connection
type nextCn = Connection
type query = Certificate.cert
type msg_i = (range * delta)
type msg_o = (range * delta)

val init: NetworkStream -> Role -> protocolOptions -> Connection

val resume: NetworkStream -> sessionID -> protocolOptions -> Connection Result

val rehandshake: Connection -> protocolOptions -> nextCn
val rekey: Connection -> protocolOptions -> nextCn
val request: Connection -> protocolOptions -> nextCn

val shutdown: Connection -> Connection

(*
val resume_session: NetworkStream -> SessionInfo -> Connection (* New connection same session *)
val resume_connection: Connection -> Connection (* New crypto same TCP stream same session *)
val renegotiate: Connection -> protocolOptions -> Connection (* New session same TCP stream *)
*)

(* FIXME: unsure we want still to expose those functions to the upper levels *)
(*
val sendNextFragments: Connection -> (unit Result) * Connection
val readNextAppFragment: Connection -> (unit Result) * Connection
*)

type ioerror =
    | EInternal of ErrorCause * ErrorKind
    | EFatal of alertDescription

type ioresult_i =
    | ReadError of ioerror
    | Close     of Tcp.NetworkStream
    | Fatal     of alertDescription
    | Warning   of nextCn * alertDescription 
    | CertQuery of nextCn * query
    | Handshaken of Connection
    | Read      of nextCn * msg_i
    | ReadMustRead of Connection * msg_i
    
type ioresult_o =
    | WriteError    of ioerror
    | WriteComplete of nextCn
    | WritePartial  of nextCn * msg_o
    | MustRead      of Connection
    
val write: Connection -> msg_o -> ioresult_o
val read: Connection -> ioresult_i
(* val appDataAvailable: Connection -> bool *)

val authorize: Connection -> query -> Connection
val refuse:    Connection -> query -> unit

val getSessionInfo: Connection -> SessionInfo