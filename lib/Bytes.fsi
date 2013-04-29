﻿module Bytes

type nat = int 
type cbytes = byte[]
type bytes
type lbytes = bytes
val empty_bytes: bytes
val abytes: byte[] -> bytes
val abyte: byte -> bytes
val abyte2: byte * byte -> bytes
val cbytes: bytes -> byte[]
val cbyte: bytes -> byte
val cbyte2: bytes -> byte * byte 


val createBytes: int -> int -> bytes

val bytes_of_int: int -> int -> bytes

val int_of_bytes: bytes -> int

val length: bytes -> int

val equalBytes: bytes -> bytes -> bool
val xor: bytes -> bytes -> int -> bytes

(* append *)
val (@|): bytes -> bytes -> bytes
val split: bytes -> int -> (bytes * bytes)
val split2: bytes -> int -> int -> (bytes * bytes * bytes)
(* strings *)
val utf8: string -> bytes
val iutf8: bytes -> string

(* List operations *)

val fold: (bytes -> bytes -> bytes) -> bytes -> bytes list -> bytes
val filter: ('a -> bool) -> 'a list -> 'a list // In HS, only used with 'a = HT_type, but it's not defined here.
val foldBack: (bytes -> bytes -> bytes) -> bytes list -> bytes -> bytes
val exists: ('a -> bool) -> 'a list -> bool
val memr: 'a list -> 'a -> bool when 'a : equality
val choose: ('a -> 'b option) -> 'a list -> 'b list // Not used parametrically in HS, but types are not defined here.
val tryFind: ('a -> bool) -> 'a list -> 'a option
#if ideal
// TODO not in f7
val find: ('a -> bool) -> 'a list -> 'a
val map: ('a -> 'b) -> 'a list -> 'b list
//val assoc: 'a -> ('a * 'b) list -> 'b option
//val assoc2_1: ('a*'b) -> ('a * 'b *'c) list -> 'b option
#endif
val listLength: ('a list) -> int
val listHead: ('a list) -> 'a

val random: nat -> bytes
