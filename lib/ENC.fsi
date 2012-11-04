module ENC

open Bytes
open TLSInfo
open Error

type state
type encryptor = state
type decryptor = state

val GEN: epoch -> encryptor * decryptor
val LEAK: epoch -> state -> bytes * bytes
val COERCE: epoch -> bytes -> bytes-> state

type cipher = bytes

val ENC: epoch -> encryptor -> int -> Encode.plain -> (encryptor * cipher)
val DEC: epoch -> decryptor -> cipher -> (decryptor * Encode.plain)
