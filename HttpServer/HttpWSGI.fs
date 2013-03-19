module HttpWSGI

open System
open System.IO
open Python.Runtime
open HttpData

// ------------------------------------------------------------------------
type WsgiEngineLock () =
    let gil = PythonEngine.AcquireLock ()

    interface IDisposable with
        member this.Dispose () =
            PythonEngine.ReleaseLock gil

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
                // fprintfn stderr "WSGI: using python engine: %A" (PythonEngine.BuildInfo);
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
// We currently only support one WSGI application per server
type WsgiHandler () =
    static let mutable application = null

    do
        WsgiEngine.initialize ()
        use lock   = new WsgiEngineLock () in
        use appmod = PythonEngine.ImportModule ("wsgiapp") in
            application <- appmod.GetAttr("main").Invoke([||])

    interface IDisposable with
        member self.Dispose () =
            application <- null
            WsgiEngine.finalize ()

    static member entry (config : HttpServerConfig) (request : HttpRequest) (stream : Stream) =
        assert PythonEngine.IsInitialized

        use lock   = new WsgiEngineLock () in
        use bridge = PythonEngine.ImportModule ("wsgibridge") in
        let error  = System.Console.Error in
        let url    = sprintf "https://mitls.rocq.inria.fr/%s" request.path in (* FIXME *)

        let sinfo =
            try
                let sinfo = (stream :?> TLStream.TLStream) in
                let sinfo = sinfo.GetSessionInfo () in
                let sinfo =
                    [ ("cipher", sinfo.cipher_suite.ToString () :> obj) ]
                        |> Map.ofList
                        |> PyObject.FromManagedObject
                in
                    sinfo
            with :? InvalidCastException -> null
        in

        let config =
            [ ("url"    , url     :> obj);
              ("request", request :> obj);
              ("error"  , error   :> obj);
              ("input"  , stream  :> obj);
              ("output" , stream  :> obj);
              ("sinfo"  , sinfo   :> obj);
            ]
                |> Map.ofList
                |> PyObject.FromManagedObject
        in

        ignore (bridge.GetAttr("_entry").Invoke([|config; application|]))
