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
val COERCE: id -> bytes -> bytes -> state
val LEAK: id -> state -> bytes

val ENC: id -> encryptor -> LHAEPlain.adata -> range -> GCMPlain.plain ->
    (encryptor * bytes)

val DEC: id -> decryptor -> LHAEPlain.adata -> range -> bytes ->
    (decryptor * LHAEPlain.plain) Result