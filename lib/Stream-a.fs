module Stream

open Data
open Bytearray

type Stream = {
    id: Pi.name;
    history: bytes;
    buffer: bytes}

type preds =
    | StreamWrite of Stream * bytes * Stream
    | StreamRead of Stream * bytes * Stream

let empty_stream =
    {id = Pi.name "Stream";
     history = empty_bstr;
     buffer = empty_bstr}

let new_stream () =
    {id = Pi.name "Stream";
     history = empty_bstr;
     buffer = empty_bstr}

let is_empty_stream s =
    (equalBytes s.history empty_bstr) && (equalBytes s.buffer empty_bstr)

let stream_write s d =
    let new_buff = append s.buffer d in
    let new_s = {s with buffer = new_buff} in
    Pi.assume(StreamWrite(s,d,new_s));
    new_s

let stream_read s len =
    let (d,new_buff) = split s.buffer len in
    let new_hist = append s.history d in
    let new_s = {s with buffer = new_buff
                        history = new_hist}
    Pi.assume(StreamRead(s,d,new_s));
    (d,new_s)
