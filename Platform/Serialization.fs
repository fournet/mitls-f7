module Serialization

open Bytes

open System
open System.Reflection
open Microsoft.FSharp.Reflection

open Newtonsoft.Json
open Newtonsoft.Json.Serialization


let dontGoPastInterfaces = BindingFlags.Public
let goPastInterfaces = BindingFlags.NonPublic ||| BindingFlags.Public


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
                        finally compensation ()

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
            { Reader = Some reader;
              Writer = None;
              Serializer = serializer }
 
        static member write writer serializer =
            { Reader = None;
              Writer = Some writer;
              Serializer = serializer }

    let json = ReaderBuilder ()

    let read func =
        json { return! (fun x -> func x.Serializer x.Reader.Value) }

    let write func =
        json { return! (fun x -> func x.Serializer x.Writer.Value) }


[<AutoOpen>]
module internal Common =

    let property o name =
        o.GetType().GetProperty(name).GetValue(o, null)
 
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
        FSharpType.IsUnion(t, goPastInterfaces)
 
    let readUnion (t: Type) =
        json {
            do! ignore ()
            let! caseName = value ()
            do! ignore ()
            
            let case =  FSharpType.GetUnionCases (t, goPastInterfaces) 
                            |> Array.find (fun x -> String.Equals (string caseName, x.Name, StringComparison.OrdinalIgnoreCase))
            let types = case.GetFields () |> Array.map (fun f -> f.PropertyType)
            let! array = readArray (fun i -> types.[i])
            let union = FSharpValue.MakeUnion (case, array, goPastInterfaces)
            
            do! ignore ()
            
            return union }
 
    let writeUnion (o: obj) =
        json {
            let case, fields = FSharpValue.GetUnionFields (o, o.GetType (), goPastInterfaces)
            let! caseName = mapName case.Name
            let properties = [caseName, box fields] |> Map.ofList

            do! writeObject (properties) }


[<AutoOpen>]
module internal Records =

    let isRecord (t: Type) =
        FSharpType.IsRecord (t, goPastInterfaces)

    let readFields (fields: Map<string,Type>) =
        json {
            let! tokenType = flip tokenType
            let! ignore = flip ignore
            let! value = flip value
            let! deserialize = flip deserialize

            let rec read data : Map<string,obj> =
                match tokenType () with
                | JsonToken.StartObject ->
                    ignore ()
                    read data
                | JsonToken.EndObject -> 
                    data                
                | JsonToken.PropertyName ->
                    let name = string (value ())
                    ignore()                   
                    let result = fields.TryFind name in
                    match result with
                    | Some t ->
                        let value = deserialize t
                        ignore ()
                        read (data.Add (name, value))
                    | None -> 
                        raise (new JsonSerializationException (sprintf "\"%s\" is not a field in the deserialized record" name))
                | _ ->
                    failwith "Unreachable"

            return read Map.empty }

    let readRecord (t: Type) =
        json {
            let fields = FSharpType.GetRecordFields (t, goPastInterfaces)
                            |> Array.map (fun p -> p.Name, p.PropertyType)
            let! map   = Map.ofArray fields |> readFields 
            let array  = [| for f, _ in fields do yield map.Item f |]
            let record = FSharpValue.MakeRecord (t, array, goPastInterfaces)

            return record }

    let writeRecord (o: obj) =
        json {
            let fields = FSharpType.GetRecordFields (o.GetType (), goPastInterfaces)
            let names  = fields |> Array.map (fun f -> f.Name)
            let values = FSharpValue.GetRecordFields (o, goPastInterfaces)
            let properties = Array.zip names values |> Map.ofArray
            do! writeObject (properties) }


(* ------------------------------------------------------------------------------- *)
type UnionConverter () =
    inherit JsonConverter ()

    override x.CanConvert (objectType) = isUnion objectType

    override x.ReadJson (reader, objectType, _, serializer) =
        readUnion objectType (JsonState.read reader serializer)

    override x.WriteJson (writer, value, serializer) =
        writeUnion value (JsonState.write writer serializer)

(* ------------------------------------------------------------------------------- *)
type RecordConverter () =
    inherit JsonConverter ()

    override x.CanConvert (objectType) = isRecord objectType

    override x.ReadJson (reader, objectType, _, serializer) =
        readRecord objectType (JsonState.read reader serializer)

    override x.WriteJson (writer, value, serializer) =
        writeRecord value (JsonState.write writer serializer)

(* ------------------------------------------------------------------------------- *)
type BytesJsonConverter () =
    inherit JsonConverter ()

    override x.CanConvert (objectType) = objectType.Equals(typeof<bytes>)

    override x.ReadJson (reader, objectType, _, serializer) =
        serializer.Deserialize (reader, typeof<byte[]>) :?> byte[] |> abytes :> obj

    override x.WriteJson (writer, value, serializer) =
        serializer.Serialize (writer, cbytes (value :?> bytes))


(* ------------------------------------------------------------------------------- *)
let converters = [|
        UnionConverter() :> JsonConverter;
        RecordConverter() :> JsonConverter;
        BytesJsonConverter() :> JsonConverter;
        |]

(* ------------------------------------------------------------------------------- *)
let settings =
    JsonSerializerSettings (
        //TraceWriter = new MemoryTraceWriter(),
        Converters = converters,
        Formatting = Formatting.None, // Beware of line endings when using Formatting.Indented
        NullValueHandling = NullValueHandling.Include
        )

(* ------------------------------------------------------------------------------- *)
let serialize<'T> (o: 'T) : string = JsonConvert.SerializeObject(o, settings)

(* ------------------------------------------------------------------------------- *)
let deserialize<'T> (s: string) : 'T = JsonConvert.DeserializeObject<'T>(s, settings)
