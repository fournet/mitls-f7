open DHDB
open Bytes
open CoreRandom
open TLSInfo
open TLSConstants

open System.IO

open Org.BouncyCastle.Math
open Org.BouncyCastle.Security

//open MsgPack.Serialization
open System.Runtime.Serialization.Formatters.Binary
//open System.Runtime.Serialization

let n = 3

(* ------------------------------------------------------------------------------- *)
let insert_dh () =
    let dhdb = DHDB.create "dh.db" in
    let gen = new SecureRandom() in
    let all = 
     [for i in 1 .. n do
        let p = new BigInteger(1024, gen) in
        let q = new BigInteger(1024, gen) in
        let g = new BigInteger(1024, gen) in
        let b = (i%2).Equals(0) in
        yield (p,g,q,b) ]
    in
    let all = List.sortBy (function (p,g,q,b) -> p.ToString()) all in
    for p,g,q,b in all do 
        let pbytes = abytes (p.ToByteArrayUnsigned()) in
        let qbytes = abytes (q.ToByteArrayUnsigned()) in
        let gbytes = abytes (g.ToByteArrayUnsigned()) in
            printfn "p=%O\ng=%O\nq=%O\nb=%b" p g q b;
            ignore(DHDB.insert dhdb (pbytes, gbytes) (qbytes, b))
    done
    ()

(* ------------------------------------------------------------------------------- *)
let dump_dh () =
    let dhdb = DHDB.create "dh.db" in
    let keys = DHDB.keys dhdb in
    let keys = List.sortBy (function (p,g) -> let p = new BigInteger(1, cbytes p) in p.ToString()) keys in
    for (p,g) in keys do
        match DHDB.select dhdb (p,g) with
        | None -> failwith "unexpected"
        | Some(q,b) ->
          let p = new BigInteger(1, cbytes p) in
          let g = new BigInteger(1, cbytes g) in
          let q = new BigInteger(1, cbytes q) in
            printfn "p=%O\ng=%O\nq=%O\nb=%b" p g q b;
    done
    ()

(* ------------------------------------------------------------------------------- *)
let insert_session () =
    let db = SessionDB.create {TLSInfo.defaultConfig with sessionDBFileName="session.db"} in    
    let all = 
      [for i in 1 .. n do
        let id = CoreRandom.random(32) in
        let role = if (i%2).Equals(0) then TLSInfo.Client else TLSInfo.Server in
        let hint = sprintf "This is a hint %d" i in
        let si = {
            init_crand = CoreRandom.random(32);
            init_srand = CoreRandom.random(32);
            protocol_version = TLS_1p1;
            cipher_suite = cipherSuite_of_name TLS_DH_anon_WITH_AES_256_GCM_SHA384;
            compression = NullCompression;
            extensions = {ne_extended_ms = false; ne_extended_padding=false; ne_renegotiation_info = None};
            pmsId = noPmsId;
            session_hash = CoreRandom.random(128);
            client_auth = true;
            clientID = [];
            clientSigAlg = SA_DSA, NULL;
            serverID = [];
            serverSigAlg = SA_ECDSA, SHA384;
            sessionID = id;
            } in
        let ms = PRF.coerce (StandardMS (noPmsId, Nonce.random 64, PRF_SSL3_nested)) 
                        (CoreRandom.random(48)) in
        let epoch = TLSInfo.unAuthIdInv ({ 
                                            msId = StandardMS (noPmsId, Nonce.random 64, PRF_SSL3_nested); 
                                            kdfAlg=PRF_SSL3_nested; 
                                            pv=SSL_3p0; 
                                            aeAlg= MACOnly(MA_SSLKHASH(NULL)); 
                                            csrConn = Nonce.random 64;
                                            ext = {ne_extended_padding = false; ne_extended_ms = false; ne_renegotiation_info = None};
                                            writer=Client
            }) 
        in yield (id,role,hint,si,ms,epoch) ] in    
    let all = List.sortBy (function (id:bytes,role,hint,si,ms,epoch) -> hint) all in
    for id,role,hint,si,ms,epoch in all do
        let dummy = StandardMS (noPmsId, empty_bytes, TLSConstants.PRF_SSL3_nested) in
        printfn "%s\n%s\n%s\n%s\n%A" 
                    (hexString id) hint (sinfo_to_string si) (hexString (PRF.leak dummy ms)) epoch
        ignore(SessionDB.insert db id role hint (si, ms, epoch))
    done
    ()

(* ------------------------------------------------------------------------------- *)
let dump_session () =
    let db = SessionDB.create {TLSInfo.defaultConfig with sessionDBFileName="session.db"} in
    let keys = SessionDB.getAllStoredIDs db in
    let keys = List.sortBy (function (_,_,hint) -> hint) keys in
    for (id,role,hint) in keys do
        match SessionDB.select db id role hint with
        | None -> failwith "unexpected"
        | Some(si,ms,epoch) -> 
            let dummy = StandardMS (noPmsId, empty_bytes, TLSConstants.PRF_SSL3_nested) in
            printfn "%s\n%s\n%s\n%s\n%A" 
                    (hexString id) hint (sinfo_to_string si) (hexString (PRF.leak dummy ms)) epoch
    done
    ()

(* ------------------------------------------------------------------------------- *)
//type Info = { 
//    crand : bytes; 
//    srand : bytes; 
//    pv    : ProtocolVersion;    
//    cipher_suite: cipherSuite;
//}

(* ------------------------------------------------------------------------------- *)
//type InfoSerializer(context:SerializationContext) =
//    inherit MessagePackSerializer<Info>(context)
//    
//    override this.PackToCore(packer, x) =
//        let bs = context.GetSerializer<bytes>() in
//        let pvs = context.GetSerializer<string>() in
//        let _ = bs.PackTo(packer, x.crand) in
//        let _ = bs.PackTo(packer, x.srand) in  
//        let _ = bs.PackTo(packer, versionBytes x.pv) in
//        ()
//
//    override this.UnpackFromCore(unpacker) =
//        let bs = context.GetSerializer<bytes>() in
//        let pvs = context.GetSerializer<string>() in
//        { crand = bs.UnpackFrom(unpacker);         
//          srand = let _ = unpacker.Read() in bs.UnpackFrom(unpacker);
//          pv    = let _ = unpacker.Read() in
//                  let b = bs.UnpackFrom(unpacker) in                  
//                  match parseVersion b with
//                  | Error.Correct(v) -> v 
//                  | _ -> raise (SerializationException("protocol verison"))
//        }

//(* ------------------------------------------------------------------------------- *)
//type BytesSerializer(context:SerializationContext) =
//    inherit MessagePackSerializer<Bytes.bytes>(context)
//    
//    override this.PackToCore(packer, objectTree) =        
//        ignore(packer.PackBinary(cbytes objectTree))
//
//    override this.UnpackFromCore(unpacker) =
//        unpacker.LastReadData.AsBinary() |> abytes
//
//(* ------------------------------------------------------------------------------- *)
//type InfoBinarySerializer(context:SerializationContext) =
//    inherit MessagePackSerializer<SessionInfo>(context)
//    
//    override this.PackToCore(packer, x) =        
//        let bf = new BinaryFormatter() in
//        let ms = new MemoryStream() in
//        bf.Serialize(ms, x);
//        ignore(packer.PackBinary(ms.ToArray()))
//
//    override this.UnpackFromCore(unpacker) =
//        let bf = new BinaryFormatter() in
//        let ms = new MemoryStream(unpacker.LastReadData.AsBinary()) in        
//        bf.Deserialize(ms) :?> SessionInfo

type info = {
    crand: bytes;
    pv : ProtocolVersion;
    }

(* ------------------------------------------------------------------------------- *)

open Newtonsoft.Json
open Newtonsoft.Json.Serialization

open Microsoft.FSharp.Reflection
open System.Reflection

open Opaque

(* ------------------------------------------------------------------------------- *)
type MyJsonConverter() =
    inherit JsonConverter()       
    
    member this.CasePropertyName = "Case";
    member this.FieldsPropertyName = "Fields";

    override this.WriteJson(writer, value, serializer) =        
            let resolver : DefaultContractResolver = serializer.ContractResolver :?> DefaultContractResolver in

            let t = value.GetType() in

            let info, fields = FSharpValue.GetUnionFields(value, t, true) in
            printfn "%A\n%A" info fields;

            let caseName = info.Name in
            let fieldsAsArray = fields in         

            writer.WriteStartObject();
            writer.WritePropertyName(
                if (resolver <> null) then 
                    resolver.GetResolvedPropertyName(this.CasePropertyName) 
                else
                     this.CasePropertyName);
            writer.WriteValue((string) caseName);

            if (fieldsAsArray <> null && fieldsAsArray.Length > 0) then
                 writer.WritePropertyName(
                    if (resolver <> null) then
                        resolver.GetResolvedPropertyName(this.FieldsPropertyName)
                    else 
                        this.FieldsPropertyName);
                 serializer.Serialize(writer, fields);    
            writer.WriteEndObject();

    override this.ReadJson(reader, objectType, existingValue, serializer) =        
         base.ReadJson(reader, objectType, existingValue, serializer)     
 
    override this.CanConvert(t) =  
        printfn "%A %b" t (FSharpType.IsUnion(t,true));    
        FSharpType.IsUnion(t,true)

type MyContractResolver() =
    inherit DefaultContractResolver()

//    member this.DefaultMemberSearchFlags = BindingFlags.Instance ||| BindingFlags.Public ||| BindingFlags.NonPublic 
//    member this.IgnoreSerializableAttribute = true
//
//    override this.GetSerializableMembers(t:System.Type) =
//        let result = base.GetSerializableMembers(t) in    
//        printfn "%+A" result;
//        let memberInfo = t.GetMembers(BindingFlags.NonPublic ||| BindingFlags.Instance) in
//        result.AddRange(memberInfo);
//        printfn "%+A" result;
//        result.Clear();
//        result        

    override this.CreateProperties(t:System.Type, memberSerialization:MemberSerialization) : System.Collections.Generic.IList<JsonProperty> =
        let mutable x = List.empty<JsonProperty> in        

        let props = t.GetProperties(BindingFlags.Public ||| BindingFlags.NonPublic ||| BindingFlags.Instance)
        for p in props do            
           x <- base.CreateProperty(p, memberSerialization) :: x
        printfn "Props = %A" x;
            
//        let fields = t.GetFields(BindingFlags.Public ||| BindingFlags.NonPublic ||| BindingFlags.Instance)        
//        for f in fields do
//            x <- base.CreateProperty(f, memberSerialization) :: x
//        printfn "%A" x;
        
        for p in x do
            p.Writable <- true;
            p.Readable <- true;
        Array.ofList(x) :> System.Collections.Generic.IList<JsonProperty>                
                  


open System
open Microsoft.FSharp.Reflection

[<AutoOpen>]
module internal Reader =

    type Reader<'R,'T> = 'R -> 'T

    let bind k m = fun r -> (k (m r)) r

    let inline flip f a b = f b a
    
    type ReaderBuilder () =

        member this.Return (a) : Reader<'R,'T> = fun _ -> a

        member this.ReturnFrom (a: Reader<'R,'T>) = a

        member this.Bind (m: Reader<'R,'T>, k:'T -> Reader<'R,'U>) : Reader<'R,'U> = 
            bind k m

        member this.Zero () = 
            this.Return ()

        member this.Combine (r1, r2) = 
            this.Bind (r1, fun () -> r2)

        member this.TryWith (m: Reader<'R,'T>, h: exn -> Reader<'R,'T>) : Reader<'R,'T> =
            fun env -> try m env
                        with e -> (h e) env

        member this.TryFinally (m: Reader<'R,'T>, compensation) : Reader<'R,'T> =
            fun env -> try m env
                        finally compensation()

        member this.Using (res: #IDisposable, body) =
            this.TryFinally (body res, (fun () -> match res with null -> () | disp -> disp.Dispose ()))

        member this.Delay (f) = 
            this.Bind (this.Return (), f)

        member this.While (guard, m) =
            if not (guard ()) then 
                this.Zero () 
            else
                this.Bind (m, (fun () -> this.While (guard, m)))

        member this.For(sequence: seq<_>, body) =
            this.Using (sequence.GetEnumerator (),
                (fun enum -> this.While(enum.MoveNext, this.Delay(fun () -> body enum.Current))))


[<AutoOpen>]
module internal State =

    type JsonState =
        { Reader: JsonReader option
          Writer: JsonWriter option
          Serializer: JsonSerializer }
 
        static member read reader serializer =
            { Reader = Some reader
              Writer = None
              Serializer = serializer }
 
        static member write writer serializer =
            { Reader = None
              Writer = Some writer
              Serializer = serializer }

    let json = ReaderBuilder ()

    let read func =
        json {
            return! (fun x -> func x.Serializer x.Reader.Value) }

    let write func =
        json {
            return! (fun x -> func x.Serializer x.Writer.Value) }


[<AutoOpen>]
module internal Common =

    let property o name =
        o.GetType().GetProperty(name).GetValue(o, null)
 
    let objKey o =
        property o "Key"
 
    let objValue o =
        property o "Value"

    let tokenType () =
        json {
            return! read (fun _ r -> 
                r.TokenType) }
 
    let ignore () =
        json {
            do! read (fun _ r -> 
                r.Read () |> ignore) }

    let value () =
        json {
            return! read (fun _ r -> 
                r.Value) }

    let serialize (o: obj) =
        json {
            do! write (fun s w -> 
                s.Serialize (w, o)) }
 
    let deserialize (t: Type) =
        json {
            return! read (fun s r -> 
                s.Deserialize (r, t)) }

    let mapName (n: string) =
        json {
            return! write (fun s _ ->
                (s.ContractResolver :?> DefaultContractResolver).GetResolvedPropertyName (n)) }

    let readArray next =
        json {
            let! tokenType = flip tokenType
            let! ignore = flip ignore
            let! deserialize = flip deserialize
 
            let rec read index data =
                match tokenType () with
                | JsonToken.StartArray ->
                    ignore ()
                    read index data
                | JsonToken.EndArray ->
                    data
                | _ ->
                    let value = deserialize (next (index))
                    ignore ()
                    read (index + 1) (data @ [value])
 
            return read 0 List.empty |> Array.ofList }

    let readObject func keyType valueType =
        json {
            let! tokenType = flip tokenType
            let! ignore = flip ignore
            let! value = flip value
            let! deserialize = flip deserialize

            let key =
                match keyType with
                | t when t = typeof<string> -> fun o -> box (string o)
                | t when t = typeof<Guid> -> fun o -> box (Guid (string o))
                | t when t = typeof<int> -> fun o -> box (System.Int32.Parse o)
                | _ -> failwith "key type not allowed"
 
            let rec read data =
                match tokenType () with
                | JsonToken.StartObject ->
                    ignore ()
                    read data
                | JsonToken.EndObject ->
                    data
                | _ ->
                    let k = key (string (value ()))
                    ignore ()
                    let v = deserialize valueType
                    ignore ()
                    read (func k v :: data)
            
            return read List.empty }
 
    let writeObject (map: Map<string, obj>) =
        json {
            do! write (fun _ w -> w.WriteStartObject ())
        
            for pair in map do
                do! write (fun _ w -> w.WritePropertyName (pair.Key))
                do! write (fun s w -> s.Serialize (w, pair.Value))
 
            do! write (fun _ w -> w.WriteEndObject ()) }

[<AutoOpen>]
module internal Unions =

    let isUnion (t: Type) =
        FSharpType.IsUnion(t,true)
 
    let readUnion (t: Type) =
        json {
            do! ignore ()
            let! caseName = value ()
            do! ignore ()
            
            let case =  FSharpType.GetUnionCases (t, true) |> Array.find (fun x -> String.Equals (string caseName, x.Name, StringComparison.OrdinalIgnoreCase))
            let types = case.GetFields () |> Array.map (fun f -> f.PropertyType)
            let! array = readArray (fun i -> types.[i])
            let union = FSharpValue.MakeUnion (case, array, true)
            
            do! ignore ()
            
            return union }
 
    let writeUnion (o: obj) =
        json {
            let case, fields = FSharpValue.GetUnionFields (o, o.GetType (), true)
            let! caseName = mapName case.Name
            let properties = [caseName, box fields] |> Map.ofList

            do! writeObject (properties) }

(* ------------------------------------------------------------------------------- *)
type UnionConverter () =
    inherit JsonConverter ()
    override x.CanConvert (t) = isUnion t
    override x.ReadJson (r, t, _, s) = readUnion t (JsonState.read r s)
    override x.WriteJson (w, v, s) = writeUnion v (JsonState.write w s)

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
let traceWriter = new MemoryTraceWriter(LevelFilter = Diagnostics.TraceLevel.Verbose )

(* ------------------------------------------------------------------------------- *)
let converters = [| 
    BytesJsonConverter() :> JsonConverter;
    //UnionConverter() :> JsonConverter;
    |]

(* ------------------------------------------------------------------------------- *)
let settings =
    JsonSerializerSettings (
        ContractResolver = new MyContractResolver (), //DefaultContractResolver(),
        Converters = converters,       
        Formatting = Formatting.None,     
        NullValueHandling = NullValueHandling.Include,
        ConstructorHandling = ConstructorHandling.AllowNonPublicDefaultConstructor,
        //ObjectCreationHandling = ObjectCreationHandling.Reuse,
        TraceWriter = traceWriter
        )

(* ------------------------------------------------------------------------------- *)
let serialize<'T> (o: 'T) : string =
    JsonConvert.SerializeObject(o, settings)

(* ------------------------------------------------------------------------------- *)
let deserialize<'T> (s:string) : 'T =    
    JsonConvert.DeserializeObject<'T>(s, settings)

[<EntryPoint>]
let main argv = 
   try       
        let v = Opaque.v
        let s = serialize v in        
        let w = deserialize<opaque> s in

        let bf = new BinaryFormatter() in
        let ms1 = new MemoryStream() in
        let ms2 = new MemoryStream() in
        bf.Serialize(ms1, v);
        bf.Serialize(ms2, w);
        let x = ms1.ToArray() in
        let y = ms2.ToArray() in
        printfn "%A\n%A\n%b" (hexString (abytes x)) (hexString (abytes y)) (Bytes.equalBytes (abytes x) (abytes y))
        
        //printfn "%A\n%A\n%A" s (Opaque.show v) (Opaque.equal v w)
   finally 
        System.Console.WriteLine(traceWriter)
    ;

//   try       
//        let v = TLSConstants.cipherSuite_of_name TLS_DH_anon_WITH_AES_256_GCM_SHA384; //Opaque.v         
//        let s = serialize v in        
//        let w = deserialize<TLSConstants.cipherSuite> s in
//        ()
//        //printfn "%A\n%A\n%A" s (Opaque.show v) (Opaque.equal v w)
//   finally 
//        System.Console.WriteLine(traceWriter)
//    ;

//   let s = serialize (Date.now()) in
//   printfn "JSON: %s" s;
//   let v = deserialize<Date.DateTime> s in
//   printfn "Value: %A" v;


//    let x = cipherSuite_of_name TLS_DH_anon_WITH_AES_256_GCM_SHA384 in
//    let bf = new BinaryFormatter() in
//    let ms = new MemoryStream() in
//    bf.Serialize(ms, x);
//    printfn "%A" (ms.ToArray());
//    let ms = new MemoryStream(ms.ToArray()) in    
//    let y = bf.Deserialize(ms) :?> TLSConstants.cipherSuite in
//    printfn "%A" (match name_of_cipherSuite x with | Error.Correct(s) -> s | _ -> failwith "ER")

//    let x = Date.now () in
//    let bf = new BinaryFormatter() in
//    let ms = new MemoryStream() in
//    bf.Serialize(ms, x);
//    let ms = new MemoryStream(ms.ToArray()) in        
//    let y = bf.Deserialize(ms) :?> Date.DateTime in
//    printfn "%s" (Date.tostring y)

//    let x = { crand = random(32); pv = TLS_1p2; } in
//    let b = DB.serialize<info>(x) in
//    let y = DB.deserialize<info>(b) in
//    assert((cbytes (x.crand)).Equals(cbytes (y.crand)) && x.pv.Equals(y.pv));

//    let x = random(32) in
//    let b = DB.serialize<bytes>(x) in
//    let y = DB.deserialize<bytes>(b) in
//    assert((cbytes x).Equals(cbytes y));
//    printfn "%02x %02x" (cbytes x).[0] (cbytes x).[30];
//    printfn "%02x %02x" (cbytes y).[0] (cbytes y).[30];

//    if File.Exists "dh.db" then    
//        dump_dh ();
//    else
//        insert_dh ();

//    if File.Exists "session.db" then    
//        dump_session ();
//    else
//        insert_session (); 

//    let stream = new MemoryStream() in   
//    let context = new SerializationContext() in
//    let _ = context.Serializers.Register (new BytesSerializer(context)) in    
//    let _ = context.Serializers.Register (new InfoBinarySerializer(context)) in
//    let serializer = MessagePackSerializer.Get<SessionInfo> (context) in
//
//    let x = { crand = random(2); srand = random(4); pv = TLS_1p2; cipher_suite = nullCipherSuite } in
//    printfn "=====Serializing====";
//    printfn "%02x %02x" (cbytes (x.crand)).[0] (cbytes (x.srand)).[3];
//
//    let p = serializer.Pack(stream, x);    
//    stream.Position <- 0L;
//    let u = serializer.Unpack stream in
//
//    printfn "=====Deserializing====";
//    printfn "%02x %02x" (cbytes (x.crand)).[0] (cbytes (x.srand)).[3];

    0
