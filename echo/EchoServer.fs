module EchoServer

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Threading

type options = {
    ciphersuite : TLSConstants.cipherSuiteName list;
    tlsversion  : TLSConstants.ProtocolVersion;
    servername  : string;
    clientname  : string option;
}

let noexn = fun cb ->
    try cb () with _ -> ()

let tlsoptions (options : options) sessionDBDir = {
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

    TLSInfo.sessionDBFileName = Path.Combine(sessionDBDir, "sessionDBFile.bin")
    TLSInfo.sessionDBExpiry   = Bytes.newTimeSpan 2 0 0 0 (* two days *)
}

let client_handler ctxt (peer : Socket) = fun () ->
    let endpoint = peer.RemoteEndPoint

    printfn "Connect: %s" (endpoint.ToString ());
    try
        try
            let netstream = new NetworkStream (peer) in
            let tlsstream = new TLStream.TLStream (netstream, ctxt, TLStream.TLSServer) in
            let reader    = new StreamReader (tlsstream) in
            let writer    = new StreamWriter (tlsstream) in

                let rec doit () =
                    let line = reader.ReadLine () in
                        if line <> null then
                            printfn "Line[%s]: %s" (peer.RemoteEndPoint.ToString ()) line
                            writer.WriteLine (line)
                            writer.Flush ()
                            doit ()
                in
                    doit ()
        with e ->
            printfn "%s" (e.ToString ())
    finally
        printfn "Disconnect: %s" (endpoint.ToString ());
        noexn (fun () -> peer.Close ())

let entry (options : options) =
    let assembly     = System.Reflection.Assembly.GetExecutingAssembly() in
    let mypath       = Path.GetDirectoryName(assembly.Location) in
    let sessiondbdir = Path.Combine(mypath, "sessionDB") in
    let ctxt         = tlsoptions options sessiondbdir in
    let localaddr    = new IPEndPoint(IPAddress.Any, 6000) in
    let listener     = new TcpListener(localaddr) in

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
