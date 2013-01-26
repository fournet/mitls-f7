module SessionDB

open System.IO
open System.Runtime.Serialization.Formatters.Binary

open Bytes
open TLSInfo

(* ------------------------------------------------------------------------------- *)
type SessionDB = {
    filename: string;
      expiry: Bytes.TimeSpan;
}

type SessionIndex = sessionID * Role * Cert.hint
type StorableSession = SessionInfo * PRF.masterSecret

(* ------------------------------------------------------------------------------- *)
module Option =
    let filter (f : 'a -> bool) (x : 'a option) =
        match x with
        | None -> None
        | Some x when f x -> Some x
        | Some x -> None

(* ------------------------------------------------------------------------------- *)
let bytes_of_key (k : SessionIndex) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream () in
        bf.Serialize(m, k); m.ToArray ()

let key_of_bytes (k : bytes) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream(k) in
    
        bf.Deserialize(m) :?> SessionIndex

let bytes_of_value (k : StorableSession * DateTime) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream () in
        bf.Serialize(m, k); m.ToArray ()

let value_of_bytes (k : bytes) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream(k) in
    
        bf.Deserialize(m) :?> (StorableSession * DateTime)

(* ------------------------------------------------------------------------------- *)
let create poptions =
    let self = {
        filename = poptions.sessionDBFileName;
          expiry = poptions.sessionDBExpiry;
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
        let filter_record ((sinfo, ts) : StorableSession * _) =
            let expires = Bytes.addTimeSpan ts self.expiry in

            if Bytes.greaterDateTime expires (Bytes.now()) then
                Some sinfo
            else
                ignore (DB.remove db key);
                None
        in

        DB.get db key
            |> Option.map value_of_bytes
            |> Option.bind filter_record

    let db  = DB.opendb self.filename in

    try
        DB.tx db select
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let insert self key value =
    let key = bytes_of_key key in

    let insert (db : DB.db) =
        match DB.get db key with
        | Some _ -> ()
        | None   -> DB.put db key (bytes_of_value (value, Bytes.now ()))
    in
    
    let db = DB.opendb self.filename in
    
    try
        DB.tx db insert; self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let getAllStoredIDs self =
    let aout =
        let db   = DB.opendb self.filename in
    
        try
            DB.tx db (fun db -> DB.all db)
        finally
            DB.closedb db
    in
        List.map
          (fun (k, v) -> (key_of_bytes k, value_of_bytes v))
          aout
