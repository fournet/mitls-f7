#light "off"

module SessionDB

open Bytes
open TLSInfo
open Date

(* ------------------------------------------------------------------------------- *)
type StorableSession = SessionInfo * PRF.masterSecret * epoch
type SessionIndex = sessionID * Role * Cert.hint

#if ideal
type entry = sessionID * Role * Cert.hint * StorableSession
type t = list<entry>  

let create (c:config) : t = []

let insert (db:t) sid r h sims : t = (sid,r,h,sims)::db 

let rec select (db:t) sid r h = 
  match db with 
  | (sid',r',h',sims)::db when sid=sid' && r=r' && h=h'  -> Some(sims)
  | _::db                                                -> select db sid r h  
  | []                                                   -> None

let rec remove (db:t) sid r h = 
  match db with 
  | (sid',r',h',sims)::db when sid=sid' && r=r' && h=h' -> remove db sid r h 
  | e::db                                               -> e::remove db sid r h 
  | []                                                  -> []

let rec getAllStoredIDs (db:t) = 
  match db with 
  | (sid,r,h,sims)::db -> (sid,r,h)::getAllStoredIDs db
  | []                 -> []
#else
open System.IO

open Newtonsoft.Json
open Newtonsoft.Json.Serialization

open System.Reflection
open System.Runtime.Serialization.Formatters.Binary

type t = {
    filename: string;
    expiry: TimeSpan;
}


(* ------------------------------------------------------------------------------- *)
type BytesJsonConverter() =
class
    inherit JsonConverter()       

    override this.WriteJson(writer, value, serializer) =        
        serializer.Serialize(writer, cbytes (value :?> bytes))
       
    override this.ReadJson(reader, objectType, existingValue, serializer) =
        serializer.Deserialize(reader, typeof<byte[]>) :?> byte[] |> abytes :> obj

    override this.CanConvert(t) =
        t.Equals(typeof<bytes>)
end

(* ------------------------------------------------------------------------------- *)
type BinaryJsonConverter(types:System.Type[]) =
class
    inherit JsonConverter()
    member this._types = types

    override this.WriteJson(writer, value, serializer) =
        let bf = new BinaryFormatter() in
        let ms = new MemoryStream() in
        bf.Serialize(ms, value);        
        serializer.Serialize(writer, ms.ToArray())
       
    override this.ReadJson(reader, objectType, existingValue, serializer) =       
        let x = serializer.Deserialize(reader, typeof<byte[]>) :?> byte[] in
        let ms = new MemoryStream(x) in
        let bf = new BinaryFormatter() in
        bf.Deserialize(ms)

    override this.CanWrite = true

    override this.CanConvert(objectType:System.Type) =
        let objectType = if objectType.IsSpecialName then objectType.BaseType else objectType in
        Array.exists (fun t -> t.Equals(objectType)) this._types
        
end

(* ------------------------------------------------------------------------------- *)
let converters =
    [| new BytesJsonConverter() :> JsonConverter;
//       new BinaryJsonConverter(
//            [| typeof<PRF.ms>; 
//               typeof<TLSConstants.cipherSuite>; 
//               typeof<TLSInfo.pmsId>; 
//               typeof<TLSInfo.preEpoch>;
//               //typeof<Date.DateTime>;
//            |]) :> JsonConverter;
    |]

type MyContractResolver() =
class
    inherit DefaultContractResolver()  

    member this.DefaultMemberSearchFlags = BindingFlags.Instance ||| BindingFlags.Public ||| BindingFlags.NonPublic 

//    override this.CreateProperty(p,memberSerialization) =
//        let x = base.CreateProperty(p,memberSerialization) in
//        x.Writable <- true;
//        x.Readable <- true;
//        x

    override this.CreateProperties(t:System.Type, memberSerialization:MemberSerialization) : System.Collections.Generic.IList<JsonProperty> =
        if (t.BaseType.Equals(typeof<Date.DateTime>)) then
            let props = t.GetProperties(BindingFlags.Public ||| BindingFlags.NonPublic ||| BindingFlags.Instance) in       
            let mutable x = List.empty<JsonProperty> in        
            for p in props do
               x <- x @ [base.CreateProperty(p, memberSerialization)]
            done;
            printfn "%A" x;
            
            let fields = t.GetFields(BindingFlags.Public ||| BindingFlags.NonPublic ||| BindingFlags.Instance) in
            for f in fields do
                x <- x @ [base.CreateProperty(f, memberSerialization)]
            done;
            printfn "%A" x;

            let x = Array.ofList(x) :> System.Collections.Generic.IList<JsonProperty> in
            for p in x do
                p.Writable <- true;
                p.Readable <- true
            done;
            x
        else
            base.CreateProperties(t, memberSerialization)
end

(* ------------------------------------------------------------------------------- *)
let settings =
    JsonSerializerSettings (
        ContractResolver = MyContractResolver (),
        Converters = converters,
        // Beware that Formatting.Indented will produce system-dependent line endings
        Formatting = Formatting.None,     
        NullValueHandling = NullValueHandling.Ignore
        )

(* ------------------------------------------------------------------------------- *)
let serialize<'T> (o: 'T) : string =
    JsonConvert.SerializeObject(o, settings)

let deserialize<'T> (s:string) : 'T =    
    JsonConvert.DeserializeObject<'T>(s, settings)

(* ------------------------------------------------------------------------------- *)
module Option =
    begin
    let filter (f : 'a -> bool) (x : option<'a>) =
        match x with
        | None -> None
        | Some x when f x -> Some x
        | Some x -> None
    end

(* ------------------------------------------------------------------------------- *)
let create poptions =
    let self = {
        filename = poptions.sessionDBFileName;
          expiry = poptions.sessionDBExpiry;
    } in

    DB.closedb (DB.opendb self.filename);
    self

(* ------------------------------------------------------------------------------- *)
let remove self sid role hint =
    let key = serialize<SessionIndex> (sid,role,hint) in
    let db  = DB.opendb self.filename in

    try
        DB.tx db (fun db -> ignore (DB.remove db key));
        self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let select self sid role hint =
    let key = serialize<SessionIndex> (sid,role,hint) in

    let select (db : DB.db) =
        let filter_record ((sinfo, ts) : StorableSession * DateTime) =
            let expires = addTimeSpan ts self.expiry in

            if greaterDateTime expires (now()) then
                Some sinfo
            else
                (ignore (DB.remove db key);
                None)
        in

        DB.get db key
            |> Option.map deserialize<StorableSession*DateTime> 
            |> Option.bind filter_record
    in

    let db = DB.opendb self.filename in

    try
        DB.tx db select
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let insert self sid role hint value =
    let key = serialize<SessionIndex> (sid,role,hint) in
    let insert (db : DB.db) =
        match DB.get db key with
        | Some _ -> ()
        | None   -> DB.put db key (serialize<StorableSession*DateTime> (value, now ())) in
    let db = DB.opendb self.filename in
    try
        DB.tx db insert; self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let getAllStoredIDs self =
    let aout =
        let db = DB.opendb self.filename in
    
        try
            DB.tx db (fun db -> DB.keys db)
        finally
            DB.closedb db
    in
        List.map deserialize<SessionIndex> aout

#endif
