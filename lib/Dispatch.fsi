module Dispatch

open Bytes
open TLSConstants
open Tcp
open Error
open Record
open Handshake
open TLSInfo
open DataStream

[<NoEquality;NoComparison>]
type Connection
type nextCn = Connection
type nullCn = Connection
type query = Cert.certchain
type msg_i = (range * delta)
type msg_o = (range * delta)

val networkStream: Connection -> NetworkStream

val init: NetworkStream -> Role -> config -> Connection

val resume: NetworkStream -> sessionID -> config -> Connection

val rehandshake: Connection -> config -> bool * nextCn
val rekey: Connection -> config -> bool * nextCn
val request: Connection -> config -> bool * nextCn

val full_shutdown: Connection -> Connection
val half_shutdown: Connection -> unit

(*
val resume_session: NetworkStream -> SessionInfo -> Connection (* New connection same session *)
val resume_connection: Connection -> Connection (* New crypto same TCP stream same session *)
val renegotiate: Connection -> config -> Connection (* New session same TCP stream *)
*)

(* FIXME: unsure we want still to expose those functions to the upper levels *)
(*
val sendNextFragments: Connection -> (unit Result) * Connection
val readNextAppFragment: Connection -> (unit Result) * Connection
*)

type writeOutcome =
    | WError of string (* internal *)
    | WriteAgain (* Possibly more data to send *)
    | WAppDataDone (* No more data to send in the current state *)
    | WHSDone
    | WMustRead (* Read until completion of Handshake *)
    | SentFatal of alertDescription * string (* The alert that has been sent *)
    | SentClose

type readOutcome =
    | WriteOutcome of writeOutcome 
    | RError of string (* internal *)
    | RAgain
    | RAppDataDone
    | RQuery of query
    | RHSDone
    | RClose
    | RFatal of alertDescription (* The received alert *)
    | RWarning of alertDescription (* The received alert *)

    
val write: Connection -> msg_o -> Connection * writeOutcome * msg_o option
val read: Connection -> Connection * readOutcome * msg_i option
(* val appDataAvailable: Connection -> bool *)

val authorize: Connection -> query -> Connection
val refuse:    Connection -> query -> unit

val getEpochIn:  Connection -> epoch
val getEpochOut: Connection -> epoch
val getInStream:  Connection -> stream
val getOutStream: Connection -> stream
