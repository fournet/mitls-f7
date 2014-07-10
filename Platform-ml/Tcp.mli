open Bytes
open Error

type ty_NetworkStream 
type ty_TcpListener 

(* Create a network stream from a given stream.
   Only used by the application interface TLSharp. *)
(* val create: System.IO.Stream -> NetworkStream*)

(* Server side *)

val listen: string -> int -> ty_TcpListener
val acceptTimeout: int -> ty_TcpListener -> ty_NetworkStream
val accept: ty_TcpListener -> ty_NetworkStream
val stop: ty_TcpListener -> unit

(* Client side *)

val connectTimeout: int -> string -> int -> ty_NetworkStream
val connect: string -> int -> ty_NetworkStream

(* Input/Output *)

val read: ty_NetworkStream -> int -> (string,bytes) ty_OptResult
val write: ty_NetworkStream -> bytes -> (string,unit) ty_OptResult
val close: ty_NetworkStream -> unit
