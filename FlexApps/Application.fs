#light "off"

module FlexApps.Application

open NLog

open TLSConstants

open FlexTLS
open FlexTypes

open FlexApps
open Parsing
open Attack_Alert
open Attack_FragmentClientHello
open Attack_EarlyCCS
open Attack_EarlyResume
open Attack_JavaLateCCS
open Attack_TripleHandshake
open Attack_SmallSubgroup_DHE
open Handshake_full_RSA
open Handshake_full_alert_RSA
open Handshake_full_DHE
open Handshake_resumption
open Handshake_tls13
open Metrics_DHE
open TraceInterpreter




[<EntryPoint>]
let main argv = 

    // Transform arguments array into a list
    let args = argv |> List.ofSeq in 
    
    // Parse command line arguments
    let opts = Parsing.innerParseCommandLineOpts nullOpts args in

    // Execute the correct scenario according to user input
    let res = 

        // Address and port when Client
        let connect_addr = 
            (match opts.connect_addr with
            | Some(addr) -> addr
            | None -> "localhost"
            )
        in
        let connect_port = 
            (match opts.connect_port with
            | Some(port) -> port
            | None -> 443
            )
        in
        let connect_cert = 
            (match opts.connect_cert with
            | Some(cn) -> cn
            | None -> "rsa.cert-02.mitls.org"
            )
        in
        // Address and port when Server
        let listen_addr = 
            (match opts.listen_addr with
            | Some(addr) -> addr
            | None -> "localhost"
            )
        in
        let listen_port = 
            (match opts.listen_port with
            | Some(port) -> port
            | None -> 4433
            )
        in
        let listen_cert = 
            (match opts.listen_cert with
            | Some(cn) -> cn
            | None -> "rsa.cert-01.mitls.org"
            )
        in
        // Client authentication
        let cert_req = 
            (match opts.cert_req with
            | Some(cert_req) -> cert_req
            | None -> false
            )
        in
        // TCP timeout
        let timeout = 
            (match opts.timeout with
            | Some(timeout) -> timeout
            | None -> 0
            )
        in
        (match opts.scenario with
        
        // Type of scenario
        | Some(FullHandshake) | None ->
            (match opts.role with
            
            // Role
            | Some(RoleClient) ->
                (match opts.kex with
                
                // Key Exchange
                | Some(KeyExchangeRSA) -> 

                    (* Standard RSA full handshake as Client *)
                    if cert_req then
                        let st = Handshake_full_RSA.client_with_auth(connect_addr,connect_cert,connect_port) in ()
                    else
                        let st = Handshake_full_RSA.client(connect_addr,connect_port,timeout=timeout) in ()
                
                | Some(KeyExchangeDHE) ->

                    (* Standard DHE full handshake as Client *)
                    if cert_req then
                        let st = Handshake_full_DHE.client_with_auth(connect_addr,connect_cert,connect_port) in ()
                    else
                        let st = Handshake_full_DHE.client(connect_addr,connect_port) in ()

                | Some(KeyExchangeECDHE) -> eprintf "ECDHE\n")
            
            | Some(RoleServer) ->
                (match opts.kex with
                
                // Key Exchange
                | Some(KeyExchangeRSA) -> 

                    (* Standard DHE full handshake as Client *)
                    if cert_req then
                        let st = Handshake_full_RSA.server_with_client_auth(listen_addr,listen_cert,listen_port) in ()
                    else
                        let st = Handshake_full_RSA.server(listen_addr,listen_cert,listen_port) in ()
                
                | Some(KeyExchangeDHE) ->

                    (* Standard DHE full handshake as Server *)
                    if cert_req then
                        let st = Handshake_full_DHE.server_with_client_auth(listen_addr,listen_cert,listen_port) in ()
                    else
                        let st = Handshake_full_DHE.server(listen_addr,listen_cert,listen_port) in ()

                | Some(KeyExchangeECDHE) -> eprintf "ECDHE\n")
            | Some(RoleMITM) -> eprintf "ROLE MITM\n")

        | Some(TraceInterpreter) ->
            (match opts.role with
            | Some(RoleClient) -> let _ = TraceInterpreter.runClients connect_addr connect_port connect_cert cert_req in ()
            | Some(RoleServer) -> let _ = TraceInterpreter.runServers listen_port listen_cert cert_req in () )
        )
    in
    printf "Scenario Finished\n";
    0



////////////////////////////////////////////////////////////////////////////////////////////////

    (* Standard RSA handshake with resumption as Client*)
//    let st = Handshake_full_RSA.client("www.inria.fr") in
//    let _  = Tcp.close st.ns in 
//    let st = Handshake_resumption.client(st,"www.inria.fr") in
//    printf "RSA client resumption finished\n";

    (* Standard RSA handshake with renegotiation as Client *)
//   let st = Handshake_full_RSA.client("127.0.0.1",4433) in
//    let st = Handshake_full_RSA.client("127.0.0.1",4433,st) in
//    printf "RSA client renegotiation finished\n";

    (* Standard RSA full handshake as Client, with an alert in between *)
//    let st = Handshake_full_alert_RSA.client("localhost",6443) in
//    printf "RSA client finished\n";

////////////////////////////////////////////////////////////////////////////////////////////////

    (* Alert attack *)
//    let st = Attack_Alert.run "www.google.com" in

    (* Alert attack MITM *)
//    let sst,cst = Attack_Alert.runMITM("0.0.0.0","127.0.0.1",4433) in

    (* Protocol downgrade attack (Fragmented ClientHello) *)
//    let st = Attack_FragmentClientHello.run("www.inria.fr",fp=All(5)) in
//    printf "Protocol version downgrade attack finished\n";

    (* Protocol downgrade attack MITM (Fragmented ClientHello) *)
//    let sst,cst = Attack_FragmentClientHello.runMITM("0.0.0.0","127.0.0.1",4433) in
//    printf "Protocol version downgrade attack finished\n";

    (* Early CCS attack MITM *)
//    let sst,cst = Attack_EarlyCCS.runMITM("0.0.0.0","127.0.0.1",4433) in
//    printf "Early CCS attack finished\n";

    (* Early Resume attack *)
//    let st = Attack_EarlyResume.run("test_CN",6443) in

    (* Java Late CCS attack as Server *)
//    let sst,cst = LateCCS.server("0.0.0.0") in
//    printf "Java Late CCS attack finished\n";

    (* Java Late CCS attack MITM *)
//    let sst,cst = LateCCS.runMITM("www.inria.fr") in
//    printf "Java Late CCS attack finished\n";

    (* Triple handshake attack MITM *)
//    let sst,cst = Attack_TripleHandshake.runMITM("0.0.0.0","rsa.cert-01.mitls.org",6666,"127.0.0.1",4433) in
//    printf "Triple handshake attack finished\n";

    (* Small subgroup attack for DHE *)
//    ignore(LogManager.DisableLogging());
//    // Test with local OpenSSL server using MODP 1024-bit group:
//    // $ openssl s_server -accept 443 -dhparam modp1024.pem
//    //
//    // -----BEGIN DH PARAMETERS-----
//    // MIIBCAKBgQCxC4+WoIDgHd6S3l6uXVTsUsmfvPsGo8aaap3KUtI7YWBz4oZ1oj0Y
//    // mDjvHi7mUsAT7LSuqQYRIySXXDzUm4O/rMvdfZDEvXCYSI6cIZpzck7/1vrlZEc4
//    // +qMaT/VbzMChUa9fDci0vUW/N982XBpl5oz9p21NpwjfH7K8LkpDcQKBgQCk0cvV
//    // w/00EmdlpELvuZkF+BBN0lisUH/WQGz/FCZtMSZv6h5cQVZLd35pD1UE8hMWAhe0
//    // sBuIal6RVH+eJ0n01/vX07mpLuGQnQ0iY/gKdqaiTAh6CR9THb8KAWm2oorWYqTR
//    // jnOvoy13nVkY0IvIhY9Nzvl8KiSFXm7rIrOy5Q==
//    // -----END DH PARAMETERS-----
//    //
//    Attack_SmallSubgroup_DHE.run(true, 223,
//           "124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084041279837566626881119772675984258163062926954046545485368458404445166682380071370274810671501916789361956272226105723317679562001235501455748016154805420913",
//           "223",
//           "localhost");
//    ignore(LogManager.EnableLogging());

////////////////////////////////////////////////////////////////////////////////////////////////

    (* Experimental TLS 1.3 full handshake as Client *)
//    printf "Starting TLS 1.3 client\n";
//    let st = Handshake_tls13.client("127.0.0.1","rsa.cert-01.mitls.org",4433) in
//    printf "TLS 1.3 client finished\n";

    (* Experimental TLS 1.3 full handshake as Server *)
//    printf "Starting TLS 1.3 server\n";
//    let st = Handshake_tls13.server("0.0.0.0","rsa.cert-01.mitls.org",4433) in
//    printf "TLS 1.3 server finished\n";

////////////////////////////////////////////////////////////////////////////////////////////////

    (* Metrics for DH parameters of ServerKeyExchange *)
//    printf "Running Metrics for DH parameters\n";
//    Metrics_DHE.run_multi("list.data");

////////////////////////////////////////////////////////////////////////////////////////////////

    (* OpenSSL tests *)
//    OpenSSL_tests.opensslTest 2443 "127.0.0.1" 2444;

////////////////////////////////////////////////////////////////////////////////////////////////
