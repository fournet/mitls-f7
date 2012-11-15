module PwAppRun

open System
open System.Threading

let servname = "cert-01.needham.inria.fr"
let my       = "xxxxxxxxxxxxxxxx"
let token    = PwToken.mk (Array.create 16 0uy)

let server () =
    try
        printfn "S: %A" (PwApp.response servname)
    with e ->
        printfn "E: %A" e

let client () =
    let r = (PwApp.request servname my token) in
        printfn "C: %A" r

let program () =
    let tserver = new Thread(new ThreadStart(server))

    tserver.Name <- "Server"; tserver.Start ()
    Thread.Sleep 1000; client ();
    Thread.Sleep -1

let _ = program ()
