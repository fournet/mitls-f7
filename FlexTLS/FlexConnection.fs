#light "off"

module FlexConnection

open Bytes
open Tcp
open TLS
open TLSInfo
open TLSConstants

open FlexTypes



type FlexConnection =
    class

    (* Initiate a connection either from Client or Server *)
    static member init (role:Role, ns:NetworkStream) : state =
        let rand = Nonce.mkHelloRandom() in
        let ci = TLSInfo.initConnection role rand in
        let record_s_in  = Record.nullConnState ci.id_in Reader in
        let record_s_out = Record.nullConnState ci.id_out Writer in
        { read  = { record = record_s_in ; epoch = ci.id_in; epoch_init_pv = defaultConfig.maxVer; hs_buffer = empty_bytes; alert_buffer = empty_bytes};
          write = { record = record_s_out; epoch = ci.id_out; epoch_init_pv = defaultConfig.maxVer; hs_buffer = empty_bytes; alert_buffer = empty_bytes};
          ns = ns }


    (* Open a connection as a Server *)
    static member serverOpenTcpConnection (address:string, ?cn:string, ?port:int) : state * config =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let cn = defaultArg cn address in
        let cfg = {
            defaultConfig with
                server_name = cn
        } in

        let l    = Tcp.listen address port in
        let ns   = Tcp.accept l in
        let st = FlexConnection.init (Server, ns) in
        (st,cfg)

 
     (* Open a connection as a Client *)
     static member clientOpenTcpConnection (address:string, ?cn:string, ?port:int) :  state * config =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let cn = defaultArg cn address in
        let cfg = {
            defaultConfig with
                server_name = cn
        } in

        let ns = Tcp.connect address port in
        let st = FlexConnection.init (Client, ns) in
        (st,cfg)

    end
