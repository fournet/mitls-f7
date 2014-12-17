(* Copyright (C) 2012--2014 Microsoft Research and INRIA *)

#light "off"

module MAC_SHA1

open Bytes
open TLSConstants
open TLSInfo

val a: macAlg
type text = bytes
type tag = bytes

type key

val Mac:    id -> key -> text -> tag
val Verify: id -> key -> text -> tag -> bool

val GEN: id -> key
