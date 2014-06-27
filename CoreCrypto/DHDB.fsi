module DHDB

open Bytes

// p, g, q, true  => prime(p) /\ prime(q) /\ g^q mod p = 1 /\ p = 2*q + 1
// p, g, q, false => prime(p) /\ prime(q) /\ g^q mod p = 1 /\ ?j. p = j*q + 1 /\ length(q) >= threshold
type Key   = bytes * bytes
type Value = bytes * bool

type t

val create: string -> t
val select: t -> bytes -> bytes -> Value option
val insert: t -> bytes -> bytes -> Value -> t
val remove: t -> bytes -> bytes -> t
val keys  : t -> Key list
