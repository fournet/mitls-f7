module TLS2

open Bytes
open Error
open Dispatch
open TLSInfo
open Tcp
open AppConfig

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

let getSessionInfo conn =
    Dispatch.getSessionInfo conn

let read     (c : Connection)             : _ * ioresult_i = (c, IOInterrupted IOIAgain)
let write    (c : Connection) (b : bytes) : _ * ioresult_o = (c, IOInterrupted IOIAgain)
let flush    (c : Connection)             : _ * ioresult_o = (c, IOInterrupted IOIAgain)
let shutdown (c : Connection)             : _ * ioresult_o = (c, IOInterrupted IOIAgain)

let connect (s : NetworkStream) (opt : protocolOptions) : Connection ioresult = IOInterrupted IOIAgain
let resume  (s : NetworkStream) (opt : protocolOptions) : Connection ioresult = IOInterrupted IOIAgain

let rehandshake     = fun (c : Connection) (opt : protocolOptions) -> c
let rehandshake_now = fun (c : Connection) (opt : protocolOptions) -> (c, (IOInterrupted IOIAgain : ioresult_o))

let rekey     = fun (c : Connection) (opt : protocolOptions) -> c
let rekey_now = fun (c : Connection) (opt : protocolOptions) -> (c, (IOInterrupted IOIAgain : ioresult_o))

let handshakeRequest     = fun (c : Connection) (opt : protocolOptions) -> c
let handshakeRequest_now = fun (c : Connection) (opt : protocolOptions) -> (c, (IOInterrupted IOIAgain : ioresult_o))

let accept            (s : TcpListener  ) (opt : protocolOptions) : Connection ioresult = IOInterrupted IOIAgain
let accept_connected  (s : NetworkStream) (opt : protocolOptions) : Connection ioresult = IOInterrupted IOIAgain
