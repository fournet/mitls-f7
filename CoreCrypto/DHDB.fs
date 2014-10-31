module DHDB

open System.IO
//open System.Runtime.Serialization.Formatters.Binary

open Bytes

open MsgPack.Serialization

type Key   = bytes * bytes
type Value = bytes * bool

type dhdb = {
    filename: string;
}

(* ------------------------------------------------------------------------------- *)
let bytes_of_key (k : Key) : byte[] =
    let bf = MessagePackSerializer.Get<byte[] * byte[]> () in
    let m  = new MemoryStream () in
    let p, g = k in    
        bf.Pack(m, (cbytes p, cbytes g)); m.ToArray ()

let key_of_bytes (k : byte[]) : Key =
    let bf = MessagePackSerializer.Get<byte[] * byte[]> () in
    let m  = new MemoryStream(k) in
    let p, g = bf.Unpack(m) in
        (abytes p, abytes g)
            
let bytes_of_value (v : Value) : byte[] =
    let bf = MessagePackSerializer.Get<byte[] * bool> () in
    let m  = new MemoryStream () in
    let (q,b) = v in
        bf.Pack(m, (cbytes q, b)); m.ToArray ()
      
let value_of_bytes (v : byte[]) : Value =
    let bf = MessagePackSerializer.Get<byte[] * bool> () in
    let m  = new MemoryStream(v) in
    let (q,b) = bf.Unpack(m) in
        (abytes q, b)

(* ------------------------------------------------------------------------------- *)
let create (filename:string) =
    let self = {
        filename = filename;
    }
    DB.closedb (DB.opendb self.filename)
    self

(* ------------------------------------------------------------------------------- *)
let remove self key =
    let key = bytes_of_key key in
  
    let db  = DB.opendb self.filename in

    try
        DB.tx db (fun db -> ignore (DB.remove db key));
        self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let select self key =
    let key = bytes_of_key key in

    let select (db : DB.db) =
        DB.get db key
            |> Option.map value_of_bytes
          
    let db = DB.opendb self.filename in

    try
        DB.tx db select
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let insert self key v =
    let key = bytes_of_key key in
  
    let insert (db : DB.db) =
        match DB.get db key with
        | Some _ -> ()
        | None   -> DB.put db key (bytes_of_value v) in

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
        List.map key_of_bytes aout

(* ------------------------------------------------------------------------------- *)
let merge self db1 =
    let db = DB.opendb self.filename in
    
    try
        let db = DB.attach db db1 "db" in
        DB.tx db (fun db -> DB.merge db "db"); self
    finally
        DB.closedb db
