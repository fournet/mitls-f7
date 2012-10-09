module EchoServer

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Threading

let noexn = fun cb ->
    try cb () with _ -> ()

let tlsoptions sessionDBDir = {
    TLSInfo.minVer = CipherSuites.ProtocolVersion.SSL_3p0
    TLSInfo.maxVer = CipherSuites.ProtocolVersion.TLS_1p2

    TLSInfo.ciphersuites =
        CipherSuites.cipherSuites_of_nameList [
            CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA;
            CipherSuites.TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        ]

    TLSInfo.compressions = [ CipherSuites.NullCompression ]

    TLSInfo.honourHelloReq = TLSInfo.HRPResume
    TLSInfo.allowAnonCipherSuite = false
    TLSInfo.check_client_version_in_pms_for_old_tls = true
    TLSInfo.request_client_certificate = false (* FIX *)
    
    TLSInfo.safe_renegotiation = true

    TLSInfo.server_name = "cert-01.needham.inria.fr"
    TLSInfo.client_name = "cert-02.needham.inria.fr"

    TLSInfo.sessionDBFileName = Path.Combine(sessionDBDir, "sessionDBFile.bin")
    TLSInfo.sessionDBExpiry   = Bytes.newTimeSpan 2 0 0 0 (* two days *)
}

let client_handler ctxt (peer : Socket) = fun () ->
    try
        let netstream = new NetworkStream (peer) in
        let tlsstream = new TLStream.TLStream (netstream, ctxt, TLStream.TLSServer) in
        let reader    = new StreamReader (tlsstream) in
        let writer    = new StreamWriter (tlsstream) in

            let rec doit () =
                let line = reader.ReadLine () in
                    if line <> null then
                        writer.WriteLine (line)
                        writer.Flush ()
                        doit ()
            in
                doit ()
    finally
        noexn (fun () -> peer.Close ())

let entry () =
    let assembly     = System.Reflection.Assembly.GetExecutingAssembly() in
    let mypath       = Path.GetDirectoryName(assembly.Location) in
    let sessiondbdir = Path.Combine(mypath, "sessionDB") in
    let ctxt         = tlsoptions sessiondbdir in
    let localaddr    = new IPEndPoint(IPAddress.Loopback, 6000) in
    let listener     = new TcpListener (localaddr) in

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
