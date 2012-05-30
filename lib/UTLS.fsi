module UTLS

open Error
open Bytes
open TLSInfo
open Dispatch

type rawfd   = Tcp.NetworkStream
type fd      = int
type queryhd = int

val EI_BADHANDLE  : int
val EI_BADCERTIDX : int
val EI_READERROR  : int
val EI_CLOSE      : int
val EI_FATAL      : int
val EI_WARNING    : int
val EI_CERTQUERY  : int
val EI_HANDSHAKEN : int
val EI_DONTWRITE  : int
val EI_WRITEERROR : int
val EI_MUSTREAD   : int
val EI_HSONGOING  : int

val read     : fd -> int * bytes
val write    : fd -> bytes -> int
val shutdown : fd -> unit

val get_query : fd -> queryhd -> int * bytes

val authorize : fd -> queryhd -> int
val refuse    : fd -> queryhd -> int

val rehandshake : fd -> config -> int
val rekey       : fd -> config -> int
val request     : fd -> config -> int

val connect          : rawfd -> config -> fd
val accept_connected : rawfd -> config -> fd

val resume : rawfd -> bytes -> config -> int
