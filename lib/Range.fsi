module Range

open Bytes
open TLSInfo

type range = nat * nat (* length range *)
type rbytes = bytes
val rangeSum: range -> range -> range

val ivLength: epoch -> nat
val targetLength: epoch -> range -> nat
val cipherRangeClass: epoch -> nat -> range
val rangeClass: epoch -> range -> range