module Tcp

open Data
open Error
open TLSError_handling

type NetworkStream = N of unit
type TcpListener = T of unit

let listen (addr:string) (port:int) = T ()

let acceptTimeout (t:int) (l:TcpListener) = N ()
let accept (l:TcpListener) = N ()

let stop  (l:TcpListener) = ()

let connectTimeout (t:int) (addr:string) (port:int) = N ()
let connect (addr:string) (port:int) =  N ()

let dataAvailable (n:NetworkStream) = Correct true

let netChan: bytes Pi.chan = Pi.chan "net"
let read (n:NetworkStream) (i:int) = 
  Correct (Pi.recv netChan)
let write (n:NetworkStream) (b:bytes) = 
  Pi.send netChan b;
  Correct ()

let close (n:NetworkStream) = ()
