(*** conversions between bytes and "basic" types: int, etc ***)

module Byteconv

open Data

let int_to_bytes (nb:int) i = Data.int_to_bytes i
let bytes_of_int (nb:int) i = int_to_bytes nb i
let int_of_bytes (nb:int) (t:bytes) = Data.bytes_to_int t

let intpair_of_bytes (msg: bytes) : (int*int) =
  let b1,b2 = iconcat msg in
    (Data.bytes_to_int b1, Data.bytes_to_int b2)

let bytes_of_intpair ((i,j): (int*int)) : bytes =
  concat (Data.int_to_bytes i) (Data.int_to_bytes j)

let empty_bstr = Data.int_to_bytes 0

let bytes_of_seq sn = Data.int_to_bytes sn
