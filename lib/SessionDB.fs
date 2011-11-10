module SessionDB

open TLSInfo
open AppCommon
open Data
open System.IO
open System.Runtime.Serialization.Formatters.Binary

type StorableSession =
    {sinfo: SessionInfo
     ms: bytes
     dir: Direction}

let load filename =
    let bf = new BinaryFormatter() in
    let file = new FileStream(  filename,
                                FileMode.Open, (* Never overwrite, and fail if not exists *)
                                FileAccess.Read,
                                FileShare.ReadWrite) in
    let map = bf.Deserialize(file) :?> Map<sessionID,(StorableSession * System.DateTime)> in
    file.Close()
    map

let store filename (map:Map<sessionID,(StorableSession * System.DateTime)>) =
    let bf = new BinaryFormatter() in
    let file = new FileStream(  filename,
                                FileMode.Create, (* Overwrite file, or create if it does not exists *)
                                FileAccess.Write,
                                FileShare.ReadWrite) in
    bf.Serialize(file,map)
    file.Close()

let create poptions =
    let map = Map.empty<sessionID,(StorableSession * System.DateTime)> in
    store poptions.sessionDBFileName map

let remove poptions key = 
    let map = load poptions.sessionDBFileName in
    let map = Map.remove key map in
    store poptions.sessionDBFileName map

let select poptions key = 
    let map = load poptions.sessionDBFileName in
    match Map.tryFind key map with
    | None -> None
    | Some (sinfo,ts) ->
        (* Check timestamp validity *)
        let expires = ts + poptions.sessionDBExpiry in
        let now = System.DateTime.Now in
        if expires > now then
            Some (sinfo)
        else
            remove poptions key
            None

let insert poptions key value =
    let map = load poptions.sessionDBFileName in
    (* If the session is already in the store, don't do anything.
       However, do _not_ use select to check availavility, or an expired
       session will be removed by select, and then re-added by us.
       Make direct access to the map instead *)
    match Map.tryFind key map with
    | Some (sinfo,ts) -> ()
    | None ->
        let map = Map.add key (value,System.DateTime.Now) map in
        store poptions.sessionDBFileName map

let getAllStoredIDs poptions =
    let map = load poptions.sessionDBFileName in
    let mapList = Map.toList map in
    List.map (fun (x,y) -> x) mapList