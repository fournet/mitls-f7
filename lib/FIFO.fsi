module FIFO

open Data
open Record

type Fifo = bytes

val empty_Fifo: Fifo
val is_empty_Fifo: Fifo -> bool
val enqueue_data: Fifo -> bytes -> Fifo
val enqueue_fragment: Fifo -> fragment -> Fifo
val dequeue_data: Fifo -> int -> (bytes * Fifo)
val dequeue_fragment: Fifo -> int -> (fragment * Fifo)

