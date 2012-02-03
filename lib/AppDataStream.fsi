module AppDataStream

open TLSInfo
open Bytes
open Error

type lengths = int list

type preAppDataStream = {
  history: bytes;
  lengths_history: lengths;
  data: bytes;
  lengths: lengths; 
}
type AppDataStream = preAppDataStream


val emptyAppDataStream: SessionInfo -> AppDataStream
val isEmptyAppDataStream: SessionInfo -> int -> 
  lengths -> AppDataStream -> bool

val writeAppDataBytes: SessionInfo -> int -> lengths -> AppDataStream ->
                bytes -> lengths -> (lengths * AppDataStream)

val readAppDataBytes: SessionInfo -> int -> lengths -> AppDataStream ->
                 (bytes * AppDataStream)

type fragment = {b:bytes}

val fragment: KeyInfo -> int -> int -> bytes -> fragment
val repr: KeyInfo -> int -> int -> fragment -> bytes

val readAppDataFragment: KeyInfo -> int -> lengths -> AppDataStream -> int -> (int * fragment * AppDataStream)

val writeAppDataFragment: KeyInfo -> int -> lengths -> AppDataStream -> int -> int -> fragment -> (lengths * AppDataStream)

val reIndex: SessionInfo -> SessionInfo -> int -> lengths -> AppDataStream -> AppDataStream
