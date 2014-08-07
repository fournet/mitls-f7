#light "off"

module HandleCH

open Bytes
open Error
open System
open System.IO
open TLS
open TLSInfo
open TLSConstants
open TLSExtensions


type FClientHello = {
    pv: ProtocolVersion;
    rand: Random;
    sid: sessionID;
    suites: list<cipherSuite>;
    comp: list<Compression>;
    ext: bytes;
    payload: bytes;
}


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


let init cfg =
    let (ci,hs)      = Handshake.init Server cfg in
    let record_s_in  = Record.nullConnState ci.id_in Reader in
    let record_s_out = Record.nullConnState ci.id_out Writer in
    { read_s  = { record = record_s_in ; epoch = ci.id_in;};
        write_s = { record = record_s_out; epoch = ci.id_out;}}
    
let getHeader ns =
    match Tcp.read ns 5 with
    | Error x        -> failwith "Tcp.read header 5 bytes failed"
    | Correct header ->
        match Record.parseHeader header with
        | Error x      -> failwith (sprintf "%A" x)
        | Correct(res) -> res

let write conn pv rg ct frag_out =
    let (write_state, b) = Record.recordPacketOut conn.write_s.epoch conn.write_s.record pv rg ct frag_out in
    conn.write_s.record <- write_state;
    b

let run (address:string) (port:int) : unit =

    let cfg = {
        cfg with
            server_name = address
    } in


    let l    = Tcp.listen address port in
    let ns   = Tcp.accept l in
    let irconn = init cfg in
    
    let ct,pv,len = getHeader ns in
    
    let data_in = 
        let plaindata = 
            match Tcp.read ns len with
            | Error x         -> failwith "Tcp.read len bytes failed"
            | Correct payload ->
                Record.recordPacketIn irconn.read_s.epoch irconn.read_s.record ct payload
        in
        match plaindata with
        | Error x      -> failwith "Unable to parse plain data"
        | Correct recf ->
            let (rec_in,rg,frag) = recf in
            let read_s = {irconn.read_s with record = rec_in} in
            let irconn = {irconn with read_s = read_s} in
            let id = TLSInfo.id irconn.read_s.epoch in
            TLSFragment.reprFragment id ct rg frag
    in

    let data_out =
        let data =
            let b = Bytes.utf8 "Hello World !" in
            let len = length b in
            let rg : Range.range = (len,len) in
            let id = TLSInfo.id irconn.write_s.epoch in
            let frag_out = TLSFragment.fragment id Handshake rg b in
            write irconn pv rg ct frag_out
        in
        match Tcp.write ns data with
        | Error x -> failwith x
        | Correct () -> data
    in
    printf "Input : %A\n" data_in;
    printf "Output : %A\n" data_out

