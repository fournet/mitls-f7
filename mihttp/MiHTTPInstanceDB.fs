module MiHTTPInstanceDB

open Bytes
open MiHTTPChannel

open System.IO
open System.Runtime.Serialization.Formatters.Binary

let dbname = "http-instances.sqlite3"

let bytes_of_cstate (s : cstate) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream () in
    bf.Serialize(m, s); m.ToArray ()

let cstate_of_bytes (x : cbytes) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream(x) in
    bf.Deserialize(m) :?> cstate

let save (c : channel) =
    let state = save_channel c in

    let doit (db : DB.db) =
        ignore (DB.remove db state.c_channelid);
        DB.put db state.c_channelid (bytes_of_cstate state)
    in

    let db = DB.opendb dbname in
    try
        DB.tx db doit
    finally
        DB.closedb db

let restore (id : channelid) =
    let doit (db : DB.db) =
        DB.get db (cbytes id)
            |> Option.map (fun x -> cstate_of_bytes x)
            |> Option.map MiHTTPChannel.restore_channel    
    in

    let db = DB.opendb dbname in
    try
        DB.tx db doit
    finally
        DB.closedb db
