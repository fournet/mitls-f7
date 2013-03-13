module HttpWSGI

open System
open System.IO
open Python.Runtime
open HttpData

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
    PythonEngine.Initialize ()

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
