module EchoImpl

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Threading

(* ------------------------------------------------------------------------ *)
type options = {
    ciphersuite : TLSConstants.cipherSuiteName list;
    tlsversion  : TLSConstants.ProtocolVersion;
    servername  : string;
    clientname  : string option;
    localaddr   : IPEndPoint;
    sessiondir  : string;
}

(* ------------------------------------------------------------------------ *)
let noexn = fun cb ->
    try cb () with _ -> ()

(* ------------------------------------------------------------------------ *)
let tlsoptions (options : options) = {
    TLSInfo.minVer = options.tlsversion
    TLSInfo.maxVer = options.tlsversion

    TLSInfo.ciphersuites = TLSConstants.cipherSuites_of_nameList options.ciphersuite

    TLSInfo.compressions = [ TLSConstants.NullCompression ]

    TLSInfo.honourHelloReq = TLSInfo.HRPResume
    TLSInfo.allowAnonCipherSuite = false
    TLSInfo.check_client_version_in_pms_for_old_tls = true
    TLSInfo.request_client_certificate = options.clientname.IsSome
    
    TLSInfo.safe_renegotiation = true

    TLSInfo.server_name = options.servername
    TLSInfo.client_name = match options.clientname with None -> "" | Some x -> x

    TLSInfo.sessionDBFileName = Path.Combine(options.sessiondir, "sessionDBFile.bin")
    TLSInfo.sessionDBExpiry   = Bytes.newTimeSpan 1 0 0 0 (* one day *)
}

(* ------------------------------------------------------------------------ *)
let client_handler ctxt (peer : Socket) = fun () ->
    let endpoint = peer.RemoteEndPoint

    fprintfn stderr "Connect: %s" (endpoint.ToString ());
    try
        try
            let netstream = new NetworkStream (peer) in
            let tlsstream = new TLStream.TLStream (netstream, ctxt, TLStream.TLSServer) in
            let reader    = new StreamReader (tlsstream) in
            let writer    = new StreamWriter (tlsstream) in

                let rec doit () =
                    let line = reader.ReadLine () in
                        if line <> null then
                            fprintfn stderr "Line[%s]: %s" (peer.RemoteEndPoint.ToString ()) line
                            writer.WriteLine (line)
                            writer.Flush ()
                            doit ()
                in
                    doit ()
        with e ->
            fprintfn stderr "%s" (e.ToString ())
    finally
        fprintfn stderr "Disconnect: %s" (endpoint.ToString ());
        noexn (fun () -> peer.Close ())

(* ------------------------------------------------------------------------ *)
let server (options : options) =
    let ctxt     = tlsoptions options in
    let listener = new TcpListener(options.localaddr) in

        listener.Start ();
        listener.Server.SetSocketOption(SocketOptionLevel.Socket,
                                        SocketOptionName.ReuseAddress,
                                        true);
        while true do
            let peer = listener.AcceptSocket () in
                try
                    let thread = new Thread(new ThreadStart(client_handler ctxt peer)) in
                        thread.IsBackground <- true;
                        thread.Start()
                with
                | :? IOException as e ->
                    noexn (fun () -> peer.Close())                    
                    Console.WriteLine(e.Message)
                | e ->
                    noexn (fun () -> peer.Close())                    
                    raise e
        done

(* ------------------------------------------------------------------------ *)
let client (options : options) =
    let ctxt      = tlsoptions options in
    let socket    = new TcpClient() in

    socket.Connect(options.localaddr)

    let tlsstream = new TLStream.TLStream(socket.GetStream(), ctxt, TLStream.TLSClient) in
    let reader    = new StreamReader (tlsstream) in
    let writer    = new StreamWriter (tlsstream) in

    let rec doit () =
        let line = System.Console.ReadLine () in
            if line <> null then
                writer.WriteLine(line); writer.Flush ()
                Console.WriteLine(reader.ReadLine ())
                doit ()
    in
        doit ()
