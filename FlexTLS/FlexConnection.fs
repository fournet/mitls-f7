#light "off"

module FlexTLS.FlexConnection

open NLog

open Bytes
open Tcp
open TLSInfo
open TLSConstants

open FlexTypes
open FlexConstants




/// <summary>
/// Module handling of opening TCP connections and prepare for TLS connections
/// </summary>
type FlexConnection =
    class

    /// <summary>
    /// Initiate a connection either from Client or Server and create a global state
    /// </summary>
    /// <param name="role"> Behaviour set as Client or Server </param>
    /// <param name="ns"> Network stream </param>
    /// <param name="pv"> Optional protocol version required to generate randomness </param>
    /// <returns> Global state of the handshake </returns>
    static member init (role:Role, ns:NetworkStream, ?pv:ProtocolVersion) : state =
        let pv = defaultArg pv defaultConfig.maxVer in
        let rand = Nonce.mkHelloRandom pv in
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
    /// <param name="pv"> Optional protocol version required to generate randomness </param>
    /// <returns> Updated state * Updated config </returns>
    static member serverOpenTcpConnection (address:string, ?cn:string, ?port:int, ?pv:ProtocolVersion) : state * config =
        let pv = defaultArg pv defaultConfig.maxVer in
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let cn = defaultArg cn address in
        let cfg = {
            defaultConfig with
                server_name = cn
        } in

        LogManager.GetLogger("file").Info("TCP : Listening on {0}:{2} as {1}", address, cn, port);
        let l    = Tcp.listen address port in
        let ns   = Tcp.accept l in
        LogManager.GetLogger("file").Debug("--- Client accepted");
        let st = FlexConnection.init (Server,ns,pv) in
        (st,cfg)

 
    /// <summary>
    /// Client role, open a tcp connection to a server
    /// </summary>
    /// <param name="address"> Binding address or domain name </param>
    /// <param name="cn"> Optional common name </param>
    /// <param name="port"> Optional port number </param>
    /// <param name="pv"> Optional protocol version required to generate randomness </param>
    /// <returns> Updated state * Updated config </returns> 
    static member clientOpenTcpConnection (address:string, ?cn:string, ?port:int, ?pv:ProtocolVersion) :  state * config =
        let pv = defaultArg pv defaultConfig.maxVer in
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let cn = defaultArg cn address in
        let cfg = {
            defaultConfig with
                server_name = cn
        } in

        LogManager.GetLogger("file").Info("TCP : Connecting to {0}:{1}",address,port);
        let ns = Tcp.connect address port in
        let st = FlexConnection.init (Client, ns) in
        LogManager.GetLogger("file").Debug("--- Done");
        (st,cfg)

    /// <summary>
    /// Open two TCP connection to do MITM : Listen for a client and Connect to a server
    /// </summary>
    /// <param name="listener_address"> Listening address (Should be 0.0.0.0 locally) </param>
    /// <param name="server_address"> Remote address </param>
    /// <param name="listener_cn"> Optional common name of the attacker </param>
    /// <param name="listener_port"> Optional port awaiting for connection </param>
    /// <param name="listener_pv"> Optional protocol version required to generate randomness </param>
    /// <param name="server_cn"> Optional common name of the server </param>
    /// <param name="server_port"> Optional port number on which to connect to the server </param>
    /// <param name="server_pv"> Optional protocol version required to generate randomness </param>
    static member MitmOpenTcpConnections (listener_address:string, server_address:string, ?listener_cn:string, ?listener_port:int, ?listener_pv:ProtocolVersion, ?server_cn:string, ?server_port:int, ?server_pv:ProtocolVersion) :  state * config * state * config =
        let listener_pv = defaultArg listener_pv defaultConfig.maxVer in
        let listener_port = defaultArg listener_port FlexConstants.defaultTCPPort in
        let listener_cn = defaultArg listener_cn listener_address in
        let server_pv = defaultArg server_pv defaultConfig.maxVer in
        let server_port = defaultArg server_port FlexConstants.defaultTCPPort in
        let server_cn = defaultArg server_cn server_address in
        let scfg = {
            defaultConfig with
                server_name = listener_cn
        } in
        let ccfg = {
            defaultConfig with
                server_name = server_cn
        } in

        LogManager.GetLogger("file").Info("TCP : Listening on {0}:{2} as {1}", listener_address, listener_cn, listener_port);
        let l    = Tcp.listen listener_address listener_port in
        let sns   = Tcp.accept l in
        let sst = FlexConnection.init (Server,sns,listener_pv) in
        LogManager.GetLogger("file").Debug("--- Client accepted");
        LogManager.GetLogger("file").Info("TCP : Connecting to {0}:{1}",server_address,server_port);
        let cns = Tcp.connect server_address server_port in
        let cst = FlexConnection.init (Client, cns) in
        LogManager.GetLogger("file").Debug("--- Done");
        (sst,scfg,cst,ccfg)

    /// <summary>
    /// Asynchronous forwarding of data from one string to another
    /// </summary>
    /// <param name="src"> Source network stream </param>
    /// <param name="dst"> Destination network stream </param>
    static member asyncForward(src:System.IO.Stream,dst:System.IO.Stream) : Async<unit> =
        async {
            let  b = Array.zeroCreate 2048 in
            let! n = src.AsyncRead(b) in
            if n > 0 then
                let b = Array.sub b 0 n in
                LogManager.GetLogger("file").Debug("--- Passing-through. Payload: {0}", Bytes.hexString (abytes b));
                dst.Write(b,0,n);
                return! FlexConnection.asyncForward(src,dst)
        }

    /// <summary>
    /// Passthrough function at the network stream level
    /// </summary>
    /// <param name="a"> Network stream A </param>
    /// <param name="b"> Network stream B </param>
    static member passthrough(a:NetworkStream, b:NetworkStream): unit =
        let a = Tcp.getStream a in
        let b = Tcp.getStream b in
        let d1 = FlexConnection.asyncForward(a,b) in
        let d2 = FlexConnection.asyncForward(b,a) in
        let p = Async.Parallel([d1;d2]) in
        ignore (Async.RunSynchronously(p))

    end
