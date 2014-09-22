#light "off"

module FlexConnection

open Bytes
open Tcp
open TLSInfo

open FlexTypes
open FlexConstants




type FlexConnection =
    class

    /// <summary>
    /// Initiate a connection either from Client or Server and create a global state
    /// </summary>
    /// <param name="role"> Behaviour set as Client or Server </param>
    /// <param name="ns"> Network stream </param>
    /// <returns> Global state of the handshake </returns>
    static member init (role:Role, ns:NetworkStream) : state =
        let rand = Nonce.mkHelloRandom() in
        let ci = TLSInfo.initConnection role rand in
        let record_s_in  = Record.nullConnState ci.id_in Reader in
        let record_s_out = Record.nullConnState ci.id_out Writer in
        { read  = { record = record_s_in;
                    epoch = ci.id_in;
                    keys = FlexConstants.nullKeys;
                    epoch_init_pv = defaultConfig.maxVer;
                    hs_buffer = empty_bytes;
                    alert_buffer = empty_bytes;
                    appdata_buffer = empty_bytes};
          write = { record = record_s_out;
                    epoch = ci.id_out;
                    keys = FlexConstants.nullKeys;
                    epoch_init_pv = defaultConfig.maxVer;
                    hs_buffer = empty_bytes;
                    alert_buffer = empty_bytes;
                    appdata_buffer = empty_bytes};
          ns = ns }


    /// <summary>
    /// Server role, open a port and wait for a tcp connection from a client
    /// </summary>
    /// <param name="address"> Binding address or domain name </param>
    /// <param name="cn"> Optional common name </param>
    /// <param name="port"> Optional port number </param>
    /// <returns> Updated state * Updated config </returns>
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

 
    /// <summary>
    /// Client role, open a tcp connection to a server
    /// </summary>
    /// <param name="address"> Binding address or domain name </param>
    /// <param name="cn"> Optional common name </param>
    /// <param name="port"> Optional port number </param>
    /// <returns> Updated state * Updated config </returns> 
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
