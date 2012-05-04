module UTLS

open Error
open Bytes
open TLSInfo
open Dispatch

type rawfd = int
type fd = int

type ioresult_i =
    | ReadError  of ioerror
    | Close
    | Fatal      of alertDescription
    | Warning    of alertDescription 
    | CertQuery  of query
    | Handshaken
    | Read       of int * int
    | DontWrite
    
type ioresult_o =
    | WriteError    of ioerror
    | WriteComplete
    | WritePartial  of int * int
    | MustRead

val read     : fd -> ioresult_i option
val shutdown : fd -> unit

(*
val write    : fd -> bytes -> ioresult_o
val connect : rawfd -> protocolOptions -> fd
val resume  : rawfd -> sessionID -> protocolOptions -> unit Result

val rehandshake : fd -> protocolOptions -> unit
val rekey       : fd -> protocolOptions -> unit
val request     : fd -> protocolOptions -> unit

val accept_connected : rawfd -> protocolOptions -> Connection

val authorize: fd -> query -> unit
val refuse:    fd -> query -> unit
*)
