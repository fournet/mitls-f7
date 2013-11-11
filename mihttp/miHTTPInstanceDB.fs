module miHTTPInstance

open Bytes
open System.IO
open System.Runtime.Serialization.Formatters.Binary

type instanceid = bytes

type instance = {
    instanceid : cbytes;
    hostname   : string;
}

let dbname = "http-instances.sqlite3"

let cbytes_of_instance (i : instance) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream () in

    bf.Serialize(m, i)
    (Array.copy i.instanceid, m.ToArray ())

let instance_of_cbytes (b : cbytes) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream(b) in
    bf.Deserialize(m) :?> instance    

let save (i : instance) =
    let key, value = cbytes_of_instance i in
    let insert (db : DB.db) =
        match DB.get db key with
        | Some _ -> ()
        | None   -> DB.put db key value in
    let db = DB.opendb dbname in
    try
        DB.tx db insert
    finally
        DB.closedb db

let create (h : string) =
    let instanceid = Nonce.random 16 in
    let instance = { hostname = h; instanceid = cbytes instanceid; } in
    save instance; instance

let find (id : instanceid) : instance option =
    let select (db : DB.db) =
        DB.get db (cbytes id)
            |> Option.map instance_of_cbytes

    let db = DB.opendb dbname in

    try
        DB.tx db select
    finally
        DB.closedb db
