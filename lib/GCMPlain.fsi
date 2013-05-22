module GCMPlain

open Bytes
open TLSInfo
open Range

type plain

val prepare: id -> LHAEPlain.adata -> range -> LHAEPlain.plain -> plain

val repr: id -> LHAEPlain.adata -> range -> plain -> (bytes * bytes)