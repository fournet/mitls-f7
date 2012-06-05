(* Copyright (c) Microsoft Corporation.  All rights reserved.  *)
module Pi
open Printf
#indent "off"

type formula = bool
let pred (x:'a) = true
let forall (f:'a -> formula) = true
let exists (f:'a -> formula) = true

#if fs
open System.Threading
let sleep n = System.Threading.Thread.Sleep (n:int)

let fork (c:unit->unit) = 
  let t = new Thread(new ThreadStart(c)) in
  t.Start();
  ()
#else
let sleep n = Thread.sleep ()
let fork (c:unit->unit) = 
  let _ = Thread.create c () in
  ()
#endif

type name = Name of string * int


let counter = ref 0 
let name s = 
  incr counter;
  Name(s,!counter) 

let fpname o (Name(s,i)) = Printf.fprintf o "%s%i" s i
let spname (o:unit) (Name(s,i)) = Printf.sprintf "%s%i" s i

#if fs 
type 'a chan = Chan of name * 'a list ref
  
let fpchan o (Chan(n,l)) = fpname o n
let spchan (o:unit) (Chan(n,l)) = spname o n

let chan s = Chan (name s,ref [])

let send (Chan (n,c)) v = 
  Printf.printf "Sending on %a: %A\n" fpname n v;
  System.Threading.Monitor.Enter(c);
  c := !c @ [v];
  System.Threading.Monitor.Exit(c)
  
let recv (Chan (n,c)) =  
  let rec f() = 
    System.Threading.Monitor.Enter(c);
    match !c with 
      | msg::msgs -> 
        c:= msgs;
        System.Threading.Monitor.Exit(c);
//	    Printf.printf "Received on %a:" fpname n; print_any msg; print_string "\n";
        msg 
      | [] -> 
      System.Threading.Monitor.Exit(c);
      sleep 1; 
      f () in
    f()
      
#else
type 'a chan = Chan of name * 'a list ref * Mutex.t

let fpchan o (Chan(n,l,m)) = fpname o n
let spchan (o:unit) (Chan(n,l,m)) = spname o n

let chan s = Chan (name s,ref [],Mutex.create())

let send (Chan (n,c,m)) v = 
  Mutex.lock m;
  c := !c @ [v];
  Mutex.unlock m
  
let recv (Chan (n,c,m)) =  
  let rec f() = 
    Mutex.lock m;
    match !c with 
      | msg::msgs -> 
        c:= msgs;
        Mutex.unlock m;
        msg 
      | [] -> 
        Mutex.unlock m;
        sleep 1; 
        f () in
    f()
#endif
      
// events

type 'a trace = Trace of 'a list ref

let trace () = Trace (ref [])

let log (Trace s) e = s := e::(!s)

// 10-09-06 F#2.0
let rec mem x u = match u with
  | y::v -> if x = y then true else mem x v 
  | _ -> false

let query (Trace s) p = 
  let rec f h = match h with 
  | e::es -> 
      let now = 
        try
          let e' = p e in
          let earlier = mem e' es in 
            earlier
        with _ -> true in
      now && f es
  | _ -> true
  in f (!s)

let weaksecret (x:'a) = ()

//type 'a annot = unit
//let coerce (a:'a) = ()

type ('a,'b,'c) postpred = 
  | Post of 'a * 'b * 'c
  | Post2 of 'a * 'b * 'c
  | Pre of 'a * 'b
  | Pre2 of 'a * 'b
  | Call of 'a * 'b
  | Return of 'a * 'b * 'c
  | Deterministic of 'a
  | Determ of 'a

let assume x = ()
let expect x = ()
