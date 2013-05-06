module Range

open Bytes
open TLSInfo

type range = nat * nat (* length range *)
type rbytes = bytes
val sum: range -> range -> range

val ivSize: epoch -> nat
val fixedPadSize: SessionInfo -> nat
val maxPadSize: SessionInfo -> nat
val targetLength: epoch -> range -> nat
val cipherRangeClass: epoch -> nat -> range
val rangeClass: epoch -> range -> range