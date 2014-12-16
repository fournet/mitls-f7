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
open Attack_JavaEarlyFinished
open Attack_TripleHandshake
open Attack_SmallSubgroup_DHE
open Handshake_full_RSA
open Handshake_full_alert_RSA
open Handshake_full_DHE
open Handshake_resumption
open Handshake_tls13
open Metrics_DHE
open SmackTLS
open Script




// This script will run in Debug mode
let runScript () =
    let _ = Script.run() in true



// This will run the CLI in Release mode
let runRelease argv =

    // Transform arguments array into a list
    let args = argv |> List.ofSeq in 
    
    // Parse command line arguments
    match Parsing.innerParseCommandLineOpts defaultOpts args with
    | None -> false
    | Some(opts) ->
    
    // Execute the correct scenario according to user input
    (match opts.scenario with
        
    // Type of scenario
    | Some(FullHandshake) ->
        (match opts.role,opts.kex with
            
        // Role * KeyExchange * Client Auth
        | None, None
        | None, Some(KeyExchangeRSA)
        | Some(RoleClient),None
        | Some(RoleClient),Some(KeyExchangeRSA) ->
            (match opts.connect_cert with
            | Some(client_cn) ->
                let st = Handshake_full_RSA.client_with_auth(opts.connect_addr,client_cn,opts.connect_port) in true
            | None ->
                let st = Handshake_full_RSA.client(opts.connect_addr,opts.connect_port) in true)
         
        | None,Some(KeyExchangeDHE)
        | Some(RoleClient),Some(KeyExchangeDHE) ->
            (match opts.connect_cert with
            | Some(client_cn) ->
                let st = Handshake_full_DHE.client_with_auth(opts.connect_addr,client_cn,opts.connect_port) in true
            | None ->
                let st = Handshake_full_DHE.client(opts.connect_addr,opts.connect_port) in true)

        | Some(RoleServer),None
        | Some(RoleServer),Some(KeyExchangeRSA) ->
            (match opts.connect_cert with
            | Some(client_cn) ->
                let st = Handshake_full_RSA.server_with_client_auth(opts.listen_addr,opts.listen_cert,opts.listen_port) in true
            | None ->
                let st = Handshake_full_RSA.server(opts.listen_addr,opts.listen_cert,opts.listen_port) in true)

        | None,Some(KeyExchangeDHE)
        | Some(RoleServer),Some(KeyExchangeDHE) ->
            (match opts.connect_cert with
            | Some(client_cn) ->
                let st = Handshake_full_DHE.server_with_client_auth(opts.listen_addr,opts.listen_cert,opts.listen_port) in true
            | None ->
                let st = Handshake_full_DHE.server(opts.listen_addr,opts.listen_cert,opts.listen_port) in true)

        | _,Some(KeyExchangeECDHE) -> eprintf "\nERROR: ECDHE not supported yet\n"; false
        | Some(RoleMITM),_ -> eprintf "\nERROR: No Full Handshake scenario as MITM\n"; false
        )

//                if resume then
//                    let st = Handshake_full_RSA.client(connect_addr,connect_port,timeout=timeout) in
//                    let _  = Tcp.close st.ns in 
//                    let st = Handshake_resumption.client(st,connect_addr,connect_port) in true
//                else
//                if renego then
//                    let st = Handshake_full_RSA.client(connect_addr,connect_port) in
//                    let st = Handshake_full_RSA.client(connect_addr,connect_port,st) in true
//                else

    // Trace Interpreter
    | Some(SmackTLS) ->
        (match opts.role with
        | Some(RoleClient) | None -> let _ = SmackTLS.runClients opts.connect_addr opts.connect_port opts.connect_cert in true
        | Some(RoleServer) -> let _ = SmackTLS.runServers opts.listen_port opts.listen_cert (match opts.connect_cert with |None->false |Some(_)->true) in true
        | Some(RoleMITM) -> eprintf "\nERROR: MITM role not implemented for SmackTLS\n"; false )

    // Attacks
    | Some (FragmentedClientHello) -> 
        let st = Attack_FragmentClientHello.run(opts.connect_addr,fp=All(5)) in true

    | Some (FragmentedAlert) -> 
        let _ = Attack_Alert.run(opts.connect_addr, opts.connect_port) in true
            
    | Some (MalformedAlert) -> 
        let _ = Handshake_full_alert_RSA.client(opts.connect_addr,opts.connect_port) in true

    | Some (EarlyCCS) ->
        let _ = Attack_EarlyCCS.runMITM(opts.listen_addr,opts.connect_addr,opts.listen_port,opts.connect_port) in true

    | Some (EarlyFinished) ->
        let _ = JavaEarlyFinished.server(opts.listen_addr,opts.listen_port) in true
                
    | Some (TripleHandshake) ->
        let _ = Attack_TripleHandshake.runMITM(opts.listen_addr,opts.listen_cert,opts.listen_port,opts.connect_addr,opts.connect_port) in true

    | Some (SmallSubgroup) ->
            // Test with local OpenSSL server using MODP 1024-bit group:
            // $ openssl s_server -accept 443 -dhparam modp1024.pem
            //
            // -----BEGIN DH PARAMETERS-----
            // MIIBCAKBgQCxC4+WoIDgHd6S3l6uXVTsUsmfvPsGo8aaap3KUtI7YWBz4oZ1oj0Y
            // mDjvHi7mUsAT7LSuqQYRIySXXDzUm4O/rMvdfZDEvXCYSI6cIZpzck7/1vrlZEc4
            // +qMaT/VbzMChUa9fDci0vUW/N982XBpl5oz9p21NpwjfH7K8LkpDcQKBgQCk0cvV
            // w/00EmdlpELvuZkF+BBN0lisUH/WQGz/FCZtMSZv6h5cQVZLd35pD1UE8hMWAhe0
            // sBuIal6RVH+eJ0n01/vX07mpLuGQnQ0iY/gKdqaiTAh6CR9THb8KAWm2oorWYqTR
            // jnOvoy13nVkY0IvIhY9Nzvl8KiSFXm7rIrOy5Q==
            // -----END DH PARAMETERS-----
            //
            let _ = Attack_SmallSubgroup_DHE.run(true, 223,
                    "124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084041279837566626881119772675984258163062926954046545485368458404445166682380071370274810671501916789361956272226105723317679562001235501455748016154805420913",
                    "223",opts.connect_addr) in true
            
    | Some (EarlyResume) ->
        let _ = Attack_EarlyResume.run(opts.listen_addr,opts.listen_cert,opts.listen_port) in true
       
    // Metrics
    | Some(DHParams) ->
        let _ = Metrics_DHE.run_multi("list.data") in true 
        
//        // Unit tests
//        | Some(UnitTests) -> 
//            let _ = UnitTests.runAll() in true

    // Nothing has been provided
    | None -> flexhelp Parsing.stderr; false)




[<EntryPoint>]
let main argv = 
#if DEBUG
    let success = runScript() in
#else
    let success = runRelease(argv) in
#endif
    if success then 
        let _ = printf "Scenario Finished\n" in 0
    else 
        let _ = printf "\n" in 0


////////////////////////////////////////////////////////////////////////////////////////////////

    (* Alert attack MITM *)
//    let sst,cst = Attack_Alert.runMITM("0.0.0.0","127.0.0.1",4433) in

    (* Protocol downgrade attack MITM (Fragmented ClientHello) *)
//    let sst,cst = Attack_FragmentClientHello.runMITM("0.0.0.0","127.0.0.1",4433) in
//    printf "Protocol version downgrade attack finished\n";

    (* Early CCS attack MITM *)
//    let sst,cst = Attack_EarlyCCS.runMITM("0.0.0.0","127.0.0.1",4433) in
//    printf "Early CCS attack finished\n";

    (* Java Late CCS attack MITM *)
//    let sst,cst = LateCCS.runMITM("www.inria.fr") in
//    printf "Java Late CCS attack finished\n";

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

    (* OpenSSL tests *)
//    OpenSSL_tests.opensslTest 2443 "127.0.0.1" 2444;

////////////////////////////////////////////////////////////////////////////////////////////////
