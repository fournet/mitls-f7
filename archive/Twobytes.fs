module Foo
type bytes = byte array

let twobytes (b0:byte) (b1:byte) : bytes =
#if fs
  [| b0 ; b1 |] 
#else  
  failwith "not yet"  
#endif

let t = twobytes 0uy 1uy