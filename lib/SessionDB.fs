module SessionDB

open TLSInfo
open AppCommon
open System.IO
open System.Runtime.Serialization.Formatters.Binary
open System.Threading

(* Lock Policy:
   - Never acquire lock in basic load/store functions.
   - Upper level functions acquire read/upgradeable read/write lock as appropriate *)
let DBLock = new ReaderWriterLockSlim()

type StorableSession =
    {sinfo: SessionInfo
     ms: PRFs.masterSecret
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
    DBLock.EnterWriteLock()
    let map = Map.empty<sessionID,(StorableSession * System.DateTime)> in
    store poptions.sessionDBFileName map
    DBLock.ExitWriteLock()

let remove poptions key =
    DBLock.EnterWriteLock()
    let map = load poptions.sessionDBFileName in
    let map = Map.remove key map in
    store poptions.sessionDBFileName map
    DBLock.ExitWriteLock()

let select poptions key =
    DBLock.EnterUpgradeableReadLock()
    let map = load poptions.sessionDBFileName in
    match Map.tryFind key map with
    | None ->
        DBLock.ExitUpgradeableReadLock()
        None
    | Some (sinfo,ts) ->
        (* Check timestamp validity *) 
        let expires = ts + poptions.sessionDBExpiry in
        let now = System.DateTime.Now in
        if expires > now then
            DBLock.ExitUpgradeableReadLock()
            Some (sinfo)
        else
            (* Remove will upgrade to the Write Lock *)
            remove poptions key
            DBLock.ExitUpgradeableReadLock()
            None

let insert poptions key value =
    DBLock.EnterUpgradeableReadLock()
    let map = load poptions.sessionDBFileName in
    (* If the session is already in the store, don't do anything.
       However, do _not_ use select to check availavility, or an expired
       session will be removed by select, and then re-added by us.
       Make direct access to the map instead *)
    match Map.tryFind key map with
    | Some (sinfo,ts) ->
        DBLock.ExitUpgradeableReadLock()
        ()
    | None ->
        DBLock.EnterWriteLock()
        let map = Map.add key (value,System.DateTime.Now) map in
        store poptions.sessionDBFileName map
        DBLock.ExitWriteLock()
        DBLock.ExitUpgradeableReadLock()

let getAllStoredIDs poptions =
    DBLock.EnterReadLock()
    let map = load poptions.sessionDBFileName in
    let mapList = Map.toList map in
    let res = List.map (fun (x,y) -> x) mapList in
    DBLock.ExitReadLock()
    res