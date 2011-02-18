module FIFO

open Data
open Record
open Formats

type Fifo = bytes


type preds =
    | FIFOSend of fragment

let empty_Fifo = empty_bstr

let is_empty_Fifo f =
    equalBytes f empty_bstr

let enqueue_data f d =
    append f d

let enqueue_fragment f d =
    append f d

let dequeue_data f len =
    split f len

let dequeue_fragment f len =
    let (frag,fifo) = split f len in
    Pi.assume(FIFOSend(frag));
    (frag,fifo)
    
