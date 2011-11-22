module HASH

open Bytes
open Error
open Algorithms

val hash: hashAlg -> bytes -> bytes Result