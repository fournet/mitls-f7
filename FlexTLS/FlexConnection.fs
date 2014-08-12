#light "off"

module FlexConnection

open Tcp
open TLS
open TLSInfo
open TLSConstants

open FlexTypes



(* Set default connection configuration *)
let cfg = defaultConfig


(* Initiate a connection either from Client or Server *)
let init (ns:NetworkStream) (cfg:config) (role:Role) =
    let (ci,_)      = Handshake.init role cfg in
    let record_s_in  = Record.nullConnState ci.id_in Reader in
    let record_s_out = Record.nullConnState ci.id_out Writer in
    { read_s  = { record = record_s_in ; epoch = ci.id_in;};
      write_s = { record = record_s_out; epoch = ci.id_out;};
      ns = ns }


(* Open a connection as a Server *)
let serverOpenTcpConnection (address:string) (port:int) : NetworkStream * config * state =
    
    let cfg = {
        cfg with
            server_name = address
    } in

    let l    = Tcp.listen address port in
    let ns   = Tcp.accept l in
    let st = init ns cfg Server in
    (ns,cfg,st)

 
 (* Open a connection as a Client *)
 let clientOpenTcpConnection (address:string) (port:int) :  NetworkStream * config * state =
    
    let cfg = {
        cfg with
            server_name = address
    } in

    let ns = Tcp.connect address port in
    let st = init ns cfg Client in
    (ns,cfg,st)
