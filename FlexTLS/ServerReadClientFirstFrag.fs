#light "off"

module ServerReadClientFirstFrag

open Bytes
open Error
open System
open System.IO
open TLS
open TLSInfo
open TLSConstants




type channel = {
    mutable record: Record.ConnectionState;
    epoch:  TLSInfo.epoch;
}

type state = {
    read_s: channel;
    write_s: channel;
}


let cfg = {
    defaultConfig with 
        minVer = TLS_1p0;
}


let run (address:string) (port:int) : string =

    let cfg = {
        cfg with
            server_name = address
    } in

    let l    = Tcp.listen address port in
    let ns   = Tcp.accept l in
   
    (* Record initial connection state pair for both read and write side *)
    let irconn = 
        let (ci,hs)      = Handshake.init Server cfg in
        let record_s_in  = Record.nullConnState ci.id_in Reader in
        let record_s_out = Record.nullConnState ci.id_out Writer in
        { read_s  = { record = record_s_in ; epoch = ci.id_in;};
          write_s = { record = record_s_out; epoch = ci.id_out;}} in
    
    let header =
        match Tcp.read ns 5 with
        | Error x        -> failwith "Tcp.read header 5 bytes failed"
        | Correct header ->
            match Record.parseHeader header with
            | Error x      -> failwith (sprintf "%A" x)
            | Correct(res) -> res
    in
    
    
    let ct,pv,len = header in
    
    let plaindata = 
        match Tcp.read ns len with
        | Error x         -> failwith "Tcp.read len bytes failed"
        | Correct payload ->
            Record.recordPacketIn irconn.read_s.epoch irconn.read_s.record ct payload
    in
    
    let data = 
        match plaindata with
        | Error x      -> failwith "Unable to parse plain data"
        | Correct recf ->
            let (rec_in,rg,frag) = recf in
            let read_s = {irconn.read_s with record = rec_in} in
            let irconn = {irconn with read_s = read_s} in
            let id = TLSInfo.id irconn.read_s.epoch in
            TLSFragment.reprFragment id ct rg frag
 
    in
    (sprintf "Result : %A" data)

