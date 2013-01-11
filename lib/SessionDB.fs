module SessionDB

open TLSInfo
open System.IO
open System.Runtime.Serialization.Formatters.Binary
open System.Threading

type SessionDB =
    { filename: string;
      expiry: Bytes.TimeSpan}
type SessionIndex = sessionID * Role * Cert.hint

(* Lock Policy:
   - Never acquire lock in basic load/store functions.
   - Upper level functions acquire read/upgradeable read/write lock as appropriate *)
let DBLock = new ReaderWriterLockSlim()

type StorableSession = SessionInfo * PRF.masterSecret

let load filename =
    let bf = new BinaryFormatter() in
    use file = new FileStream(  filename,
                                FileMode.Open, (* Never overwrite, and fail if not exists *)
                                FileAccess.Read,
                                FileShare.ReadWrite) in
    let map = bf.Deserialize(file) :?> Map<SessionIndex,(StorableSession * Bytes.DateTime)> in
    map

let store filename (map:Map<SessionIndex,(StorableSession * Bytes.DateTime)>) =
    let bf = new BinaryFormatter() in
    use file = new FileStream(  filename,
                                FileMode.Create, (* Overwrite file, or create if it does not exists *)
                                FileAccess.Write,
                                FileShare.ReadWrite) in
    bf.Serialize(file,map)

let create poptions =
    let self = {filename = poptions.sessionDBFileName;
                expiry = poptions.sessionDBExpiry} in
    if File.Exists (self.filename) then
        self
    else
        DBLock.EnterWriteLock()
        try
            let map = Map.empty<SessionIndex,(StorableSession * Bytes.DateTime)> in
            store self.filename map
            self
        finally
            DBLock.ExitWriteLock()

let remove self key =
    DBLock.EnterWriteLock()
    try
        let map = load self.filename in
        let map = Map.remove key map in
        store self.filename map
        self
    finally
        DBLock.ExitWriteLock()

let select self key =
    DBLock.EnterUpgradeableReadLock()
    try
        let map = load self.filename in
        match Map.tryFind key map with
        | None ->
            None
        | Some (sinfo,ts) ->
            (* Check timestamp validity *) 
            let expires = Bytes.addTimeSpan ts self.expiry in
            if Bytes.greaterDateTime expires (Bytes.now()) then
                Some (sinfo)
            else
                (* Remove will upgrade to the Write Lock *)
                let self = remove self key in
                None
    finally
        DBLock.ExitUpgradeableReadLock()

let insert self key value =
    DBLock.EnterUpgradeableReadLock()
    try
        let map = load self.filename in
        (* If the session is already in the store, don't do anything.
           However, do _not_ use select to check availavility, or an expired
           session will be removed by select, and then re-added by us.
           Make direct access to the map instead *)
        match Map.tryFind key map with
        | Some (sinfo,ts) ->
            self
        | None ->
            DBLock.EnterWriteLock()
            try 
                let map = Map.add key (value,Bytes.now()) map in
                store self.filename map
                self
            finally
                DBLock.ExitWriteLock()
    finally
        DBLock.ExitUpgradeableReadLock()

let getAllStoredIDs self =
    DBLock.EnterReadLock()
    try
        let map = load self.filename in
        let mapList = Map.toList map in
        let res = List.map (fun (x,y) -> x) mapList in
        res
    finally
        DBLock.ExitReadLock()