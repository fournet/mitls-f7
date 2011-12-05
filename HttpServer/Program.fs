module HttpEntryPoint

open System
open System.IO
open HttpServer

let _ =
    let mimetypes =
        try
            Mime.of_file "C:\htdocs\mime.types"
        with :? IOException as e ->
            Console.WriteLine("cannot read mime-types: " + e.Message)
            Mime.MimeMap ()
    in
        HttpServer.run { root = "C:\htdocs"; mimes = mimetypes } 
