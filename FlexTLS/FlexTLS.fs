module FlexTLS

open Bytes
open Error
open System
open System.IO
open TLS
open TLSInfo
open TLSConstants




let cfg = {
    defaultConfig with 
        minVer = TLS_1p0;
}




let run (address:string) (port:int) : Connection =

    let cfg = {
        cfg with
            server_name = address;
    }

    let ns   = Tcp.connect address port in

    let conn = TLS.connect ns cfg in

    let rec doHS conn =
        match TLS.read conn with
        | ReadError(ad,err)         ->  failwith (sprintf "HS ReadError = %A" err)
        | Close(_)                  ->  failwith "HS Close"
        | Fatal(ad)                 ->  failwith (sprintf "HS Fatal = %A" ad)
        | Warning(_,ad)             ->  failwith (sprintf "HS Warning = %A" ad)
        | CertQuery(conn,q,advice)  ->
            if advice then 
                match TLS.authorize conn q with
                | ReadError(ad,err)    ->  failwith (sprintf "HS CertQuery ReadError = %A" err)
                | Close(_)             ->  failwith "HS CertQuery Close"
                | Fatal(ad)            ->  failwith (sprintf "HS CertQuery Fatal = %A" ad)
                | Warning(_,ad)        ->  failwith (sprintf "HS CertQuery Warning = %A" ad)
                | CertQuery(conn,q,advice) -> failwith "HS CertQuery =  There should be only one CertQuery in one HS"
                | CompletedFirst(conn) ->  conn
                | CompletedSecond(conn)->  conn
                | Read(_)              ->  failwith "HS CertQuery Read"
                | DontWrite(conn)      ->  doHS conn
            else 
                TLS.refuse conn q
                failwith "HS CertQuery : Advice is false"
        | CompletedFirst(conn) ->  conn
        | CompletedSecond(conn)->  conn
        | Read(_)              ->  failwith "HS Read"
        | DontWrite(conn)      ->  doHS conn

    in
    doHS conn