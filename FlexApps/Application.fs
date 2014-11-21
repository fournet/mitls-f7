#light "off"

module FlexApps.Application

open NLog

open TLSConstants

open FlexTLS
open FlexTypes

open FlexApps
open Parsing
open Attack_EarlyCCS
open Attack_JavaEarlyFinished
open Handshake_full_RSA
open Handshake_full_DHE
open SmackTLS

let runRelease argv =

    // Transform arguments array into a list
    let args = argv |> List.ofSeq in 
    
    // Parse command line arguments
    match Parsing.innerParseCommandLineOpts defaultOpts args with
    | None -> false
    | Some(opts) ->
    
    // Execute the correct scenario according to user input
    (match opts.scenario with
        
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
        )

    | Some(SmackTLS) ->
        (match opts.role with
        | Some(RoleClient) | None -> let _ = SmackTLS.runClients opts.connect_addr opts.connect_port opts.connect_cert in true
        | Some(RoleServer) -> let _ = SmackTLS.runServers opts.listen_port opts.listen_cert (match opts.connect_cert with |None->false |Some(_)->true) in true)

    // Attacks
    | Some (EarlyCCS) ->
        let _ = Attack_EarlyCCS.runMITM(opts.listen_addr,opts.connect_addr,opts.listen_port,opts.connect_port) in true

    | Some (EarlyFinished) ->
        let _ = JavaEarlyFinished.server(opts.listen_addr,opts.listen_port) in true

    // Nothing has been provided
    | None -> flexhelp Parsing.stderr; false)

[<EntryPoint>]
let main argv = 
    let success = runRelease(argv) in
    if success then 
        let _ = printf "Scenario Finished\n" in 0
    else 
        let _ = printf "\n" in 0
