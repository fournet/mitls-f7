module Tcp

open Bytes
open Error

type NetworkStream 
type TcpListener 

(* Create a network stream from a given stream.
   Only used by the application interface TLSharp
   Does not have an fs7 refinement, as it is not supposed to be used
   by typechecked implementations *)
val create: System.Net.Sockets.NetworkStream -> NetworkStream

(* Server side *)

val listen: string -> int -> TcpListener
val acceptTimeout: int -> TcpListener -> NetworkStream
val accept: TcpListener -> NetworkStream
val stop: TcpListener -> unit

(* Client side *)

val connectTimeout: int -> string -> int -> NetworkStream
val connect: string -> int -> NetworkStream

(* Input/Output *)

// val dataAvailable: NetworkStream -> bool Result
val read: NetworkStream -> int -> bytes Result
val write: NetworkStream -> bytes -> unit Result
val close: NetworkStream -> unit
