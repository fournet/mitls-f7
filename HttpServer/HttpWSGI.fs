module HttpWSGI

open System
open System.IO
open Python.Runtime
open HttpData

// ------------------------------------------------------------------------
type WsgiEngine () =
    static let mutable tid = (nativeint) 0

    static member initialize () =
        lock typeof<Python.Runtime.Runtime> (fun () ->
            if tid <> (nativeint) 0 then
                failwith "WsgiHandler already initialized";
            if PythonEngine.IsInitialized then
                failwith "PythonEngine already initialized";
            PythonEngine.Initialize ();
            try
                tid <- PythonEngine.BeginAllowThreads ()
            with e ->
                PythonEngine.Shutdown ();
                raise e)

    static member finalize () =
        lock typeof<Python.Runtime.Runtime> (fun () ->
            try
                if tid <> (nativeint) 0 then
                    PythonEngine.EndAllowThreads tid;
                    PythonEngine.Shutdown ()
            finally
                tid <- (nativeint) 0)

// ------------------------------------------------------------------------
type WsgiHandler () =
    do
        WsgiEngine.initialize ()

    interface IDisposable with
        member self.Dispose () =
            WsgiEngine.finalize ()

// ------------------------------------------------------------------------
type PythonEngineLock () =
    let gil = PythonEngine.AcquireLock ()

    interface IDisposable with
        member this.Dispose () =
            PythonEngine.ReleaseLock gil

// ------------------------------------------------------------------------
let application () =
    use lock = new PythonEngineLock () in
    use app = PythonEngine.ImportModule ("wsgiapp") in
        app.GetAttr("application")

// ------------------------------------------------------------------------
let entry (config : HttpServerConfig) (request : HttpRequest) (stream : Stream) =
    assert PythonEngine.IsInitialized

    use lock   = new PythonEngineLock () in
    use bridge = PythonEngine.ImportModule ("wsgibridge") in
    let error  = System.Console.Error in
    let url    = sprintf "https://localhost:%d/%s" config.localaddr.Port request.path in (* FIXME *)

    let config =
        [ ("url"    , url     :> obj);
          ("request", request :> obj);
          ("error"  , error   :> obj);
          ("input"  , stream  :> obj);
          ("output" , stream  :> obj);
        ]
            |> Map.ofList
            |> PyObject.FromManagedObject
    in

    ignore (bridge.GetAttr("_entry").Invoke([|config; application ()|]))
