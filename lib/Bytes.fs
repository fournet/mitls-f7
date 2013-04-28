﻿module Bytes

type nat = int
type cbytes = byte[]
type bytes = {b:byte[]}
let length (d:bytes) = (d.b).Length
type lbytes = bytes

let empty_bytes = {b = [||]}
let abytes (b:byte[]) = {b=b}
let abyte (b:byte) = {b=[|b|]}
let abyte2 (b1,b2) = {b=[|b1;b2|]}
let cbytes (b:bytes) = b.b
let cbyte (b:bytes) = if length b = 1 then b.b.[0] else failwith "cbyte invoked on bytes of length <> 1"
let cbyte2 (b:bytes) = if length b = 2 then (b.b.[0],b.b.[1]) else failwith "cbyte invoked on bytes of length <> 2"

let createBytes len (value:int) : bytes =
    try abytes (Array.create len (byte value))
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
    abytes(put_bytes b nb i)

let int_of_bytes (b:bytes) : int =
    List.fold (fun x y -> 256 * x + y) 0 (List.map (int) (Array.toList b.b))

//@ Constant time comparison (to mitigate timing attacks)
//@ The number of byte comparisons depends only on the lengths of both arrays.
let equalBytes (b1:bytes) (b2:bytes) =
    length b1 = length b2 && 
    Array.fold2 (fun ok x y -> x = y && ok) true b1.b b2.b

let xor s1 s2 nb =
  let s1 = cbytes s1 in
  let s2 = cbytes s2 in
  if Array.length s1 < nb || Array.length s2 < nb then
    Error.unexpected "[xor] arrays too short"
  else
    let res = Array.zeroCreate nb in  
    for i=0 to nb-1 do
      res.[i] <- byte (int s1.[i] ^^^ int s2.[i])
    done;
    abytes res


let (@|) (a:bytes) (b:bytes) = abytes(Array.append (cbytes a) (cbytes b))
let split (b:bytes) i : bytes * bytes = 
  abytes (Array.sub (cbytes b) 0 i),
  abytes (Array.sub (cbytes b) i ((length b) - i))
let split2 (b:bytes) i j : bytes * bytes * bytes =
  let b = cbytes b in
  abytes (Array.sub b 0 i),
  abytes (Array.sub b i j),
  abytes (Array.sub b (i+j) (b.Length-(i+j)))
 
let utf8 (x:string) : bytes = abytes (System.Text.Encoding.UTF8.GetBytes x)
let iutf8 (x:bytes) : string = System.Text.Encoding.UTF8.GetString (cbytes x)

(* Time spans *)
type DateTime = DT of System.DateTime
type TimeSpan = TS of System.TimeSpan
let now () = DT (System.DateTime.Now)
let newTimeSpan d h m s = TS (new System.TimeSpan(d,h,m,s))
let addTimeSpan (DT(a)) (TS(b)) = DT (a + b)
let greaterDateTime (DT(a)) (DT(b)) = a > b

(* List operation functions. Currently only used by the Handshake. *)
let fold (op: bytes-> bytes-> bytes) state data = List.fold op state data
let filter f l = List.filter f l
let foldBack (f:bytes -> bytes -> bytes) bl s = List.foldBack f bl s
let exists f l = List.exists f l
let memr l x = List.exists (fun y -> x = y) l
let choose f l = List.choose f l
let tryFind f l = List.tryFind f l
#if ideal
let find f l = List.find f l
// MK what is the right assoc function? 
let rec assoc f l =
    match l with
      | (f',l')::_ when f=f' -> Some (f)
      | _::l                   -> assoc f l
      | []                       -> None
let rec assoc2_1 (f1,f2) l =
    match l with
      | (f1',f2',v)::_ when f1=f1' && f2=f2' -> Some (v)
      | _::l                   -> assoc2_1 (f1,f2) l
      | []                       -> None
      
// MK what is the right mem function?
let mem x l = List.exists (fun y -> x = y) l
let map f l = List.map f l

#endif
let listLength (l:'a list) = l.Length
let listHead (l:'a list) = l.Head

let isSome (l:'a option) = 
  match l with
      Some(x) -> true
    | None -> false

let random (n:nat) = abytes (CoreRandom.random n)
