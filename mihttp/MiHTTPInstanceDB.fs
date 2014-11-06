module MiHTTPInstanceDB

open Bytes
open MiHTTPChannel

open Newtonsoft.Json
open Newtonsoft.Json.Serialization


let dbname = "http-instances.sqlite3"

(* ------------------------------------------------------------------------------- *)
type BytesJsonConverter() =
    inherit JsonConverter()       

    override this.WriteJson(writer, value, serializer) =        
        serializer.Serialize(writer, cbytes (value :?> bytes))
       
    override this.ReadJson(reader, objectType, existingValue, serializer) =
        serializer.Deserialize(reader, typeof<byte[]>) :?> byte[] |> abytes :> obj

    override this.CanConvert(t) =
        t.Equals(typeof<bytes>)

(* ------------------------------------------------------------------------------- *)
let converters =
    [| BytesJsonConverter() :> JsonConverter |]

(* ------------------------------------------------------------------------------- *)
let settings =
    JsonSerializerSettings (
        ContractResolver = DefaultContractResolver (),
        Converters = converters,
        // Beware that Formatting.Indented will produce system-dependent line endings
        Formatting = Formatting.None,        
        NullValueHandling = NullValueHandling.Include
        )

(* ------------------------------------------------------------------------------- *)
let serialize<'T> (o: 'T) : string =
    JsonConvert.SerializeObject(o, settings)

let deserialize<'T> (s:string) : 'T =
    JsonConvert.DeserializeObject<'T>(s, settings)

let save (c : channel) =
    let state = save_channel c in
    let key   = serialize<cbytes> state.c_channelid in
    let value = serialize<cstate> state in

    let doit (db : DB.db) =
        ignore (DB.remove db key);
        DB.put db key value
    in

    let db = DB.opendb dbname in
    try
        DB.tx db doit
    finally
        DB.closedb db

let restore (id : channelid) =
    let key   = serialize<cbytes> (cbytes id) in

    let doit (db : DB.db) =
        DB.get db key
            |> Option.map deserialize<cstate>
            |> Option.map MiHTTPChannel.restore_channel    
    in

    let db = DB.opendb dbname in
    try
        DB.tx db doit
    finally
        DB.closedb db
