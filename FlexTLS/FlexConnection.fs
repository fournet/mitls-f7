#light "off"

module FlexConnection

open Bytes
open Tcp
open TLS
open TLSInfo
open TLSConstants

open FlexTypes



(* Set default connection configuration *)
let cfg = defaultConfig


type FlexConnection =
    class

    (* Initiate a connection either from Client or Server *)
    static member init (role:Role) (ns:NetworkStream) (cfg:config) : state =
        let rand = Nonce.mkHelloRandom() in
        let ci = TLSInfo.initConnection role rand in
        let record_s_in  = Record.nullConnState ci.id_in Reader in
        let record_s_out = Record.nullConnState ci.id_out Writer in
        { read_s  = { record = record_s_in ; epoch = ci.id_in; buffer = empty_bytes; alert_buffer = empty_bytes};
          write_s = { record = record_s_out; epoch = ci.id_out; buffer = empty_bytes; alert_buffer = empty_bytes};
          ns = ns }


    (* Open a connection as a Server *)
    static member serverOpenTcpConnection (address:string) (port:int) : state * config =
    
        let cfg = {
            cfg with
                server_name = address
        } in

        let l    = Tcp.listen address port in
        let ns   = Tcp.accept l in
        let st = FlexConnection.init Server ns cfg in
        (st,cfg)

 
     (* Open a connection as a Client *)
     static member clientOpenTcpConnection (address:string) (port:int) :  state * config =
    
        let cfg = {
            cfg with
                server_name = address
        } in

        let ns = Tcp.connect address port in
        let st = FlexConnection.init Client ns cfg in
        (st,cfg)

    end
