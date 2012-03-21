module ENC

open Bytes
open TLSInfo
open Error

type state
type encryptor = state
type decryptor = state

val GEN: KeyInfo -> encryptor * decryptor
val LEAK:   KeyInfo -> state -> bytes * bytes
val COERCE: KeyInfo -> bytes -> bytes-> state

type cipher = bytes

val ENC: KeyInfo -> encryptor -> int -> AEPlain.plain -> (encryptor * cipher)
val DEC: KeyInfo -> decryptor -> cipher -> (decryptor * AEPlain.plain)
