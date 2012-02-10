module TLS2

open Bytes
open Error
open Dispatch
open TLSInfo
open Tcp
open AppConfig

(* Event-driven interface *)

type ioerror = ErrorCause * ErrorKind

type iointerrupt =
| IOIWarning     of alertDescription
| IOIAuthRequest of Certificate.cert list
| IOIAgain

type 'a ioresult =
| IOSuccess     of 'a
| IOInterrupted of iointerrupt
| IOError       of ioerror

type ioresult_o = unit  ioresult
type ioresult_i = bytes ioresult

val getSessionInfo: Connection -> SessionInfo

val read     : Connection -> Connection * ioresult_i
val write    : Connection -> bytes -> Connection * ioresult_o
val flush    : Connection -> Connection * ioresult_o
val shutdown : Connection -> Connection * ioresult_o

val connect : NetworkStream -> protocolOptions -> Connection ioresult
val resume  : NetworkStream -> protocolOptions -> Connection ioresult

val rehandshake     : Connection -> protocolOptions -> Connection
val rehandshake_now : Connection -> protocolOptions -> Connection * ioresult_o

val rekey     : Connection -> protocolOptions -> Connection
val rekey_now : Connection -> protocolOptions -> Connection * ioresult_o

val handshakeRequest     : Connection -> protocolOptions -> Connection
val handshakeRequest_now : Connection -> protocolOptions -> Connection * ioresult_o

val accept           : TcpListener   -> protocolOptions -> Connection ioresult
val accept_connected : NetworkStream -> protocolOptions -> Connection ioresult
