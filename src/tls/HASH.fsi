﻿(* Copyright (C) 2012--2014 Microsoft Research and INRIA *)

#light "off"

module HASH

open Bytes
open TLSConstants

val hash: hashAlg -> bytes -> bytes
