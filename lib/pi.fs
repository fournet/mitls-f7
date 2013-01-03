(* Copyright (c) Microsoft Corporation.  All rights reserved.  *)

(* This file provides trivial F# definitions for F7 specification primitives *)

module Pi

type formula = bool
let pred (x:'a) = true
let forall (f:'a -> formula) = true
let exists (f:'a -> formula) = true

let assume x = ()
let expect x = ()
