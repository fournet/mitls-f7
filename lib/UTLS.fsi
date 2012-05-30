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

type read_t =
| E_BADHANDLE
| E_READERROR
| E_CLOSE
| E_FATAL      of bytes
| E_WARNING    of bytes
| E_CERTQUERY  of queryhd
| E_HANDSHAKEN
| E_DONTWRITE
| E_READ

type write_t =
| EW_BADHANDLE
| EW_WRITEERROR
| EW_MUSTREAD
| EW_WRITTEN of int

type query_t =
| EQ_BADHANDLE
| EQ_BADCERTIDX
| EQ_QUERY of bytes

val read     : fd -> read_t
val write    : fd -> bytes -> write_t
val shutdown : fd -> unit

val get_query : fd -> queryhd -> query_t

val authorize : fd -> queryhd -> int
val refuse    : fd -> queryhd -> int

val rehandshake : fd -> config -> int
val rekey       : fd -> config -> int
val request     : fd -> config -> int

val connect          : rawfd -> config -> fd
val accept_connected : rawfd -> config -> fd

val resume : rawfd -> bytes -> config -> int
