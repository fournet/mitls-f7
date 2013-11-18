module Range

open Bytes
open TLSInfo

type range = nat * nat (* length range *)
type rbytes = bytes
val sum: range -> range -> range

val ivSize: id -> nat
val fixedPadSize: id -> nat
val maxPadSize: id -> nat
val alignedRange: id -> range -> range
val targetLength: id -> range -> nat
val cipherRangeClass: id -> nat -> range
val rangeClass: id -> range -> range