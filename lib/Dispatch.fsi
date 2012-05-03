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

val networkStream: Connection -> NetworkStream

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
type writeOutcome =
    | WError of ioerror
    | WriteAgain (* Possibly more data to send *)
    | WAppDataDone (* No more data to send in the current state *)
    | WHSDone
    | WMustRead (* Read until completion of Handshake *)
    | SentFatal of alertDescription
    | SentClose

type readOutcome =
    | WriteOutcome of writeOutcome 
    | RError of ioerror
    | RAgain
    | RAppDataDone
    | RQuery of query
    | RHSDone
    | RClose
    | RFatal of alertDescription
    | RWarning of alertDescription

    
val write: Connection -> msg_o -> Connection * writeOutcome * msg_o option
val read: Connection -> Connection * readOutcome * msg_i option
(* val appDataAvailable: Connection -> bool *)

val authorize: Connection -> query -> Connection
val refuse:    Connection -> query -> unit

val getEpochIn:  Connection -> epoch
val getEpochOut: Connection -> epoch
val getInStream:  Connection -> stream
val getOutStream: Connection -> stream
