module AEAD_GCM

open Bytes
open TLSInfo
open Range
open TLSError

type cipher = bytes
type state
type encryptor = state
type decryptor = state

val GEN: id -> encryptor * decryptor
val COERCE: id -> rw -> bytes -> bytes -> state
val LEAK: id -> rw -> state -> bytes

val ENC: id -> encryptor -> LHAEPlain.adata -> range -> LHAEPlain.plain ->
    (encryptor * bytes)

val DEC: id -> decryptor -> LHAEPlain.adata -> range -> bytes ->
    Result<(decryptor * LHAEPlain.plain)>
