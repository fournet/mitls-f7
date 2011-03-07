module Stream

open Data
open Bytearray

type prestream = {
    id: bytes;
    history: bytes;
    buffer: bytes}

type stream = prestream

type preds =
    | StreamWrite of stream * bytes
    | StreamRead of stream * bytes

let new_stream d =
    {id = d;
     history = empty_bstr;
     buffer = empty_bstr}

let is_empty_stream s =
    (equalBytes s.history empty_bstr) && (equalBytes s.buffer empty_bstr)

let stream_write s d =
    let new_buff = append s.buffer d in
    let new_s = {s with buffer = new_buff} in
    Pi.assume(StreamWrite(s,d));
    new_s

let stream_read s len =
    let (d,new_buff) = split s.buffer len in
    let new_hist = append s.history d in
    let new_s = {s with buffer = new_buff
                        history = new_hist}
    Pi.assume(StreamRead(s,d));
    (d,new_s)
