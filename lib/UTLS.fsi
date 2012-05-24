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
val connect : rawfd -> config -> fd
val resume  : rawfd -> sessionID -> config -> unit Result

val rehandshake : fd -> config -> unit
val rekey       : fd -> config -> unit
val request     : fd -> config -> unit

val accept_connected : rawfd -> config -> Connection

val authorize: fd -> query -> unit
val refuse:    fd -> query -> unit
*)
