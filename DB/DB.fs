module DB

open System
open System.Data
open System.IO

#if __MonoSQL__
open Mono.Data.Sqlite
type SQLiteConnection = SqliteConnection
#else
open System.Data.SQLite
#endif

open Bytes

open Newtonsoft.Json
open Newtonsoft.Json.Serialization

exception DBError of string

type db = DB of SQLiteConnection

let _db_lock = new Object()

type BytesJsonConverter() =
    inherit JsonConverter()       

    override this.WriteJson(writer:JsonWriter, value:Object, serializer:JsonSerializer) =        
        if (value.GetType().Equals(typeof<bytes>)) then
            serializer.Serialize(writer, cbytes (value :?> bytes))
        else 
            raise (NotImplementedException(sprintf "Serializing wrong type: expected bytes, got %s" (value.GetType().ToString())))

    override this.ReadJson(reader:JsonReader, objectType:Type, existingValue:Object, serializer:JsonSerializer) =
        if (objectType.Equals(typeof<bytes>)) then
            let b = serializer.Deserialize(reader, typeof<byte[]>) in            
            b :?> byte[] |> abytes :> obj
        else
            raise (NotImplementedException(sprintf "Deserializing wrong type: expected bytes, got %s" (objectType.ToString())))    

    override this.CanConvert(t:Type) =
        t.Equals(typeof<bytes>)


type MyContractResolver() = 
    inherit DefaultContractResolver()
        
    override this.CreateObjectContract(objectType:Type) : JsonObjectContract =        
        let contract = base.CreateObjectContract(objectType) in
        if (objectType.Equals(typeof<Date.DateTime>)) then            
            contract.DefaultCreator <- (fun () -> Date.now() :> obj)        
        contract

let converters =
    [ BytesJsonConverter() :> JsonConverter ] 
    |> List.toArray :> Collections.Generic.IList<JsonConverter>

let settings =
    JsonSerializerSettings (
        ContractResolver = MyContractResolver(), //DefaultContractResolver (), 
        Converters = converters,
        Formatting = Formatting.Indented,
        NullValueHandling = NullValueHandling.Include
        )

(* Serialization/Deserialization functions *)
let serialize<'T> (o: 'T) : byte[] =
    let s = JsonConvert.SerializeObject(o, settings) in 
    //printfn "%s" s;   
    System.Text.Encoding.ASCII.GetBytes(s)

let deserialize<'T> (b:byte[]): 'T =
    let s = System.Text.Encoding.ASCII.GetString(b) in
    //printfn "%s" s;   
    JsonConvert.DeserializeObject<'T>(s, settings)

module Internal =
    let wrap (cb : unit -> 'a) =
        try  cb ()
        with exn ->
            fprintfn stderr "DBError: %s" exn.Message;
            raise (DBError (exn.ToString()))

    let opendb (filename : string) =
        ((new FileInfo(filename)).Directory).Create()
        let request = "CREATE TABLE IF NOT EXISTS map(key BLOB PRIMARY KEY, value BLOB NOT NULL)" in
        let urn     = String.Format("Data Source={0};Version=3", filename) in
        let db      = new SQLiteConnection(urn) in
            db.Open();
            db.DefaultTimeout <- 5;
            use command = db.CreateCommand() in
                command.CommandText <- request;
                ignore (command.ExecuteNonQuery() : int);
                DB db

    let closedb (DB db : db) =
        use db = db in ()

    let attach (DB db : db) (filename : string) (alias : string) =
        let request = sprintf "ATTACH :filename AS :alias" 
        use command = db.CreateCommand() in
            command.CommandText <- request;
            command.Parameters.Add("filename", DbType.String).Value <- filename;
            command.Parameters.Add("alias", DbType.String).Value <- alias;
            ignore (command.ExecuteNonQuery() : int);
            DB db

    let put (DB db : db) (k : byte[]) (v : byte[]) =
        let request = "INSERT OR REPLACE INTO map (key, value) VALUES (:k, :v)" in
        use command = db.CreateCommand() in
            command.CommandText <- request;
            command.Parameters.Add("k", DbType.Binary).Value <- k;
            command.Parameters.Add("v", DbType.Binary).Value <- v;
            ignore (command.ExecuteNonQuery())

    let get (DB db : db) (k : byte[]) =
        let request = "SELECT value FROM map WHERE key = :k LIMIT 1" in
        use command = db.CreateCommand() in

            command.CommandText <- request;
            command.Parameters.Add("k", DbType.Binary).Value <- k;

            let reader  = command.ExecuteReader() in
                try
                    if reader.Read() then
                        let len  = reader.GetBytes(0, 0L, null, 0, 0) in
                        let data = Array.create ((int) len) 0uy in
                            ignore (reader.GetBytes(0, 0L, data, 0, (int) len) : int64);
                            Some data
                    else
                        None
                finally
                    reader.Close()

    let remove (DB db : db) (k : byte[]) =
        let request = "DELETE FROM map WHERE key = :k" in
        use command = db.CreateCommand() in
            command.CommandText <- request;
            command.Parameters.Add("k", DbType.Binary).Value <- k;
            command.ExecuteNonQuery() <> 0

    let all (DB db : db) =
        let request = "SELECT key, value FROM map" in
        use command = db.CreateCommand() in

            command.CommandText <- request;

            let reader = command.ExecuteReader() in
            let aout   = ref [] in

                try
                    while reader.Read() do
                        let klen  = reader.GetBytes(0, 0L, null, 0, 0) in
                        let vlen  = reader.GetBytes(1, 0L, null, 0, 0) in
                        let kdata = Array.create ((int) klen) 0uy in
                        let vdata = Array.create ((int) vlen) 0uy in
                            ignore (reader.GetBytes(0, 0L, kdata, 0, (int) klen) : int64);
                            ignore (reader.GetBytes(0, 0L, vdata, 0, (int) vlen) : int64);
                            aout := (kdata, vdata) :: !aout
                    done;
                    !aout
                finally
                    reader.Close()

    let keys (DB db : db) =
        let request = "SELECT key FROM map" in
        use command = db.CreateCommand() in

            command.CommandText <- request;

            let reader = command.ExecuteReader() in
            let aout   = ref [] in

                try
                    while reader.Read() do
                        let klen  = reader.GetBytes(0, 0L, null, 0, 0) in
                        let kdata = Array.create ((int) klen) 0uy in
                            ignore (reader.GetBytes(0, 0L, kdata, 0, (int) klen) : int64);
                            aout := kdata :: !aout
                    done;
                    !aout
                finally
                    reader.Close()

    let merge (DB db : db) (alias : string) =
        // Only used internally, alias is trusted    
        let request = sprintf "INSERT OR IGNORE INTO map (key, value) SELECT key, value FROM %s.map" alias in
        use command = db.CreateCommand() in         
            command.Parameters.Add("alias", DbType.String).Value <- alias;
            command.CommandText <- request;
            ignore (command.ExecuteNonQuery() : int)

    let tx (DB db : db) (f : db -> 'a) : 'a =
        lock (_db_lock) (fun () ->
            use tx = db.BeginTransaction (IsolationLevel.ReadCommitted) in
            let aout = f (DB db) in
                tx.Commit (); aout)

let opendb (filename : string) =
    Internal.wrap (fun () -> Internal.opendb filename)

let closedb (db : db) =
    Internal.wrap (fun () -> Internal.closedb db)

let attach (db : db) (filename : string) (alias : string) =
    Internal.wrap (fun () -> Internal.attach db filename alias)

let put (db : db) (k : byte[]) (v : byte[]) =
    Internal.wrap (fun () -> Internal.put db k v)

let get (db : db) (k : byte[]) =
    Internal.wrap (fun () -> Internal.get db k)

let remove (db : db) (k : byte[]) =
    Internal.wrap (fun () -> Internal.remove db k)

let all (db : db) =
    Internal.wrap (fun () -> Internal.all db)

let keys (db : db) =
    Internal.wrap (fun () -> Internal.keys db)

let merge (db : db) (alias : string) =
    Internal.wrap (fun () -> Internal.merge db alias)

let tx (db : db) (f : db -> 'a) =
    Internal.wrap (fun () -> Internal.tx db f)
