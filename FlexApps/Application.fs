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
open Attack_maxoutPV
open Attack_TripleHandshake
open Handshake_full_RSA
open Handshake_full_DHE
open Handshake_resumption
open Handshake_tls13




// This script will run in Debug mode
let runScript () =
    let _ = Handshake_full_DHE.client("www.inria.fr") in true


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

    // Attacks
    | Some (FragmentedClientHello) -> 
        let st = Attack_FragmentClientHello.run(opts.connect_addr,fp=All(5)) in true

    | Some (FragmentedAlert) -> 
        let _ = Attack_Alert.run(opts.connect_addr, opts.connect_port) in true
            
    | Some (EarlyCCS) ->
        let _ = Attack_EarlyCCS.runMITM(opts.listen_addr,opts.connect_addr,opts.listen_port,opts.connect_port) in true
                
    | Some (TripleHandshake) ->
        let _ = Attack_TripleHandshake.runMITM(opts.listen_addr,opts.listen_cert,opts.listen_port,opts.connect_addr,opts.connect_port) in true
    
    // TLS 1.3 Experimental 1RTT
    | Some (TLS13) ->
        (match opts.role with
        | Some(RoleClient) | None ->
            let _ = Handshake_tls13.client(opts.connect_addr,opts.connect_addr,opts.connect_port) in true
            
        | Some(RoleServer) ->
            let _ = Handshake_tls13.server(opts.listen_addr,opts.listen_cert,opts.listen_port) in true
        )
    
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
