(* Copyright (C) 2012--2014 Microsoft Research and INRIA *)

#light "off"

module ENC

open Bytes
open TLSInfo

type state
type encryptor = state
type decryptor = state

val GEN:    id -> encryptor * decryptor
val LEAK:   id -> rw -> state -> bytes * bytes
val COERCE: id -> rw -> bytes -> bytes-> state

type cipher = bytes

val ENC: id -> encryptor -> LHAEPlain.adata -> Range.range -> Encode.plain -> (encryptor * cipher)
val DEC: id -> decryptor -> LHAEPlain.adata -> cipher -> (decryptor * Encode.plain)

