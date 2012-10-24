module Bytes

type nat = int
type bytes = byte[]

let length (d:bytes) = d.Length
type lbytes = bytes

let createBytes len (value:int) : bytes =
    try Array.create len (byte value)
    with :? System.OverflowException -> failwith "Default integer for createBytes was greater than max_value"

let bytes_of_int nb i =
  let rec put_bytes bb lb n =
    if lb = 0 then failwith "not enough bytes"
    else
      begin
        Array.set bb (lb-1) (byte (n%256));
        if n/256 > 0 then
          put_bytes bb (lb-1) (n/256)
        else bb
      end
  in
  let b = Array.zeroCreate nb in
    put_bytes b nb i

let int_of_bytes (b:bytes) : int =
    List.fold (fun x y -> 256 * x + y) 0 (List.map (int) (Array.toList b))

let equalBytes (b1:bytes) (b2:bytes) =
    if length b1 <> length b2 then
        false
    else
        Array.fold2 (fun ok x y -> (x = y) && ok) true b1 b2

let rng = new System.Security.Cryptography.RNGCryptoServiceProvider ()
let mkRandom len =
    let x = Array.zeroCreate len in
    rng.GetBytes x; x

let (@|) (a:bytes) (b:bytes) = Array.append a b
let split (b:bytes) i : bytes * bytes = 
  Array.sub b 0 i,
  Array.sub b i (b.Length-i)
let split2 (b:bytes) i j : bytes * bytes * bytes =
  Array.sub b 0 i,
  Array.sub b i j,
  Array.sub b (i+j) (b.Length-(i+j))
   
 
let utf8 (x:string) : bytes = System.Text.Encoding.UTF8.GetBytes x
let iutf8 (x:bytes) : string = System.Text.Encoding.UTF8.GetString x

(* Time spans *)
type DateTime = DT of System.DateTime
type TimeSpan = TS of System.TimeSpan
let now () = DT (System.DateTime.Now)
let newTimeSpan h d m s = TS (new System.TimeSpan(h,d,m,s))
let addTimeSpan (DT(a)) (TS(b)) = DT (a + b)
let greaterDateTime (DT(a)) (DT(b)) = a > b