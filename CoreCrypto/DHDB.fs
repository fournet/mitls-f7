module DHDB

open System.IO

open Bytes

type Key   = bytes * bytes
type IntKey = cbytes * cbytes
type Value = bytes * bool
type IntValue = cbytes * bool

type dhdb = {
    filename: string;
}

(* ------------------------------------------------------------------------------- *)
let intkey_to_key (a,b) = abytes(a),abytes(b)
let key_to_intkey (a,b) = cbytes(a),cbytes(b)

(* ------------------------------------------------------------------------------- *)
let intvalue_to_value (a,b) = abytes(a),b
let value_to_intvalue (a,b) = cbytes(a),b

(* ------------------------------------------------------------------------------- *)
let create (filename:string) =
    let self = {
        filename = filename;
    }
    DB.closedb (DB.opendb self.filename)
    self

(* ------------------------------------------------------------------------------- *)
let remove self key =
    let key = DB.serialize<IntKey> (key_to_intkey key) in
  
    let db  = DB.opendb self.filename in

    try
        DB.tx db (fun db -> ignore (DB.remove db key));
        self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let select self key =
    let key = DB.serialize<IntKey> (key_to_intkey key) in

    let select (db : DB.db) =
        DB.get db key
            |> Option.map (DB.deserialize<IntValue> >> intvalue_to_value)
          
    let db = DB.opendb self.filename in

    try
        DB.tx db select
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let insert self key v =
    let key = DB.serialize<IntKey> (key_to_intkey key) in
    let v   = DB.serialize<IntValue> (value_to_intvalue v) in
  
    let insert (db : DB.db) =
        match DB.get db key with
        | Some _ -> ()
        | None   -> DB.put db key v in

    let db = DB.opendb self.filename in

    try
        DB.tx db insert; self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let keys self =
    let aout =
        let db = DB.opendb self.filename in
    
        try
            DB.tx db (fun db -> DB.keys db)
        finally
            DB.closedb db
    in
        List.map (DB.deserialize<IntKey> >> intkey_to_key) aout
     
(* ------------------------------------------------------------------------------- *)
let merge self db1 =
    let db = DB.opendb self.filename in
    
    try
        let db = DB.attach db db1 "db" in
        DB.tx db (fun db -> DB.merge db "db"); self
    finally
        DB.closedb db
