module HASH

open Data
open Error
open Algorithms

val hash: hashAlg -> bytes -> bytes Result