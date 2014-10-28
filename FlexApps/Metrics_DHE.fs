#light "off"

module Metrics_DHE

open NLog

open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexHandshake
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerKeyExchange

open FlexApps
open Handshake_full_DHE




type Metrics_DHE = 
    class

    (* Run a full Handshake DHE with server side authentication only *)
    static member client (server_name:string, ?port:int) : (bytes * bytes) * bytes =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in

        // Typical DHE key exchange messages

        // Ensure we use DHE
        let fch = {FlexConstants.nullFClientHello with
            ciphersuites = FlexConstants.defaultDHECiphersuites } in

        let st,nsc,fch   = FlexClientHello.send(st,fch) in
        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
        Tcp.close st.ns;

        let kexdh = 
            match nsc.keys.kex with
            | DH(kexdh) -> kexdh
            | _ -> failwith "This metric has only been implemented for DHE"
        in
        kexdh.pg,kexdh.gy

    static member run_multi (filePath:string) : unit =
        System.IO.File.ReadLines(filePath) |>
        Seq.iter(fun domain -> 
            printfn  "%s" domain;
            try
                let domain = "www." + domain in 
                let (p,g),gx = Metrics_DHE.client(domain) in
                let outFile = new System.IO.StreamWriter("data/dhparams/" + domain) in
                outFile.WriteLine(sprintf "Website : %s" domain);
                outFile.WriteLine(sprintf "DH p : %s" (Bytes.hexString(p)));
                outFile.WriteLine(sprintf "DH g : %s" (Bytes.hexString(g)));
                outFile.WriteLine(sprintf "DH gx : %s" (Bytes.hexString(gx)));
                outFile.Close()
            with
                | Failure(msg) -> ()
        )
    end
