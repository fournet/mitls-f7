module HASH

open Data
open Error_handling
open Algorithms

val hash: hashAlg -> bytes -> bytes Result