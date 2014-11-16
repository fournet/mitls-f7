#light "off"

module FlexApps.Application

open NLog

open TLSConstants
open FlexTLS
open FlexTypes

open FlexApps
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



type ScenarioOpt = FullHandshake | FullHanshakeANDResumption | Tests
type RoleOpt = RoleClient | RoleServer | RoleMITM
type LogLevelOpt = LogLevelTrace | LogLevelDebug | LogLevelInfo | LogLevelNone
type KeyExchangeOpt = KeyExchangeRSA | KeyExchangeDHE

type CommandLineOpts = {
    scenario: option<ScenarioOpt>;
    role: option<RoleOpt>;
    kex: option<KeyExchangeOpt>;
    connect_addr: option<string>;
    connect_port: option<int>;
    listen_addr: option<string>;
    listen_port: option<int>;
    min_pv: option<ProtocolVersion>;
    verbosity: option<LogLevelOpt>;
}




let rec innerParseCommandLineOpts parsedArgs args =
    let banner () =
        printf "FlexTLS Command Line Interface\n"
    in
    let info () = 
        banner ();
        printf "\n";
        printf "  - Version : FlexTLS 0.0.1\n";
        printf "              November 20, 2014\n";
        printf "\n";
        printf "  - Authors : Benjamin Beurdouche & Alfredo Pironti\n";
        printf "              INRIA Paris-Rocquencourt\n";
        printf "              Team Prosecco\n";
        printf "\n";
        printf "  - Website : http://www.mitls.org\n"
    in
    let help () = 
        banner ();
        printf "  -i    : Infos about this software\n";
        printf "\n";
        printf "  -s     :    Scenario to execute                  (default : FullHandshake)\n";
        printf "  -r     : *  Role                                 (required)\n";
        printf "               - Client : {c,C,Client}\n";
        printf "               - Server : {s,S,Server}\n";
        printf "               - Both   : {m,M,MITM}\n";
        printf "  -k     : *  Key exchange                         (required)\n";
        printf "               - RSA    : {r,rsa,RSA}\n";
        printf "               - DHE    : {dhe,DHE}\n";
        printf "               - ECDHE  : {ec,ecdhe,ECDHE}\n";
        printf "  -pv    : [] Protocol version minimum             (default : TLS1p2)\n";
        printf "               - SSL 3.0 : {30,ssl3,SSL3}\n";
        printf "               - TLS 1.0 : {10,tls10,TLS10}\n";
        printf "               - TLS 1.1 : {11,tls11,TLS11}\n";
        printf "               - TLS 1.2 : {12,tls12,TLS12}\n";
        printf "               - TLS 1.3 : {13,tls13,TLS13}\n";
        printf "  -ca    : [] Connect to address or domain _       (default : localhost)\n";
        printf "  -cp    : [] Connect to port number _             (default : 443)\n";
        printf "  -ccert : [] Certificate CN to use if Client _    (default : rsa.mitls.org)\n";
        printf "  -la    : [] Listening to address or domain _     (default : localhost)\n";
        printf "  -lp    : [] Listening to port number _           (default : 4433)\n";
        printf "  -lcert : [] Certificate CN to use if Server      (default : rsa.mitls.org)\n";
        printf "  -lauth :    Request client authentication\n";
        printf "  -v     : [] Verbosity                            (default : Info)\n";
        printf "               - Trace : {3,trace,Trace}\n";
        printf "               - Debug : {2,debug,Debug}\n";
        printf "               - Info  : {1,info,Info}\n";
        printf "               - None  : {0,none,None}\n";
        printf "\n";
        printf " *  =>  Require an argument\n";
        printf " [] =>  Default will be used if not provided\n";
    in

    // Process options
    match args with
    // Infos and Help
    | []        -> ()
    | "-h"::t   -> help ()

    // Match valid options
    | "-s"::t ->
        (match t with
        | "FullHandshake"::tt | "fullhandshake"::tt | "fh"::tt | "FH"::tt ->
            innerParseCommandLineOpts {parsedArgs with scenario = Some(FullHandshake)} tt
        | "Tests"::tt | "tests"::tt ->
            innerParseCommandLineOpts {parsedArgs with scenario = Some(Tests)} tt
        | _ -> help(); eprintf "ERROR : -s argument is not a valid scenario"
        )

    | "-r"::t ->
        (match t with
        | "Client"::tt | "C"::tt | "c"::tt -> innerParseCommandLineOpts {parsedArgs with role = Some(RoleClient)} tt
        | "Server"::tt | "S"::tt | "s"::tt -> innerParseCommandLineOpts {parsedArgs with role = Some(RoleServer)} tt
        | "MITM"::tt | "M"::tt | "m"::tt -> innerParseCommandLineOpts {parsedArgs with role = Some(RoleMITM)} tt
        | _ -> help(); eprintf "ERROR : -r argument is not a valid role"
        )

    | "-ca"::t ->
        (match t with
        | addr::tt -> innerParseCommandLineOpts {parsedArgs with connect_addr = Some(addr)} tt
        | [] -> help(); eprintf "ERROR : -ca has to be provided either a domain name or an ip address"
        )

    | "-cp"::t ->
        (match t with
        | sport::tt ->
            let success,port = System.Int32.TryParse sport in
            if success then
                innerParseCommandLineOpts {parsedArgs with connect_port = Some(port)} tt
            else help(); eprintf "ERROR : -cp argument not a correct integer"
        | [] -> help(); eprintf "ERROR : -cp has to be provided a port number"
        )

    | "-la"::t ->
        (match t with
        | addr::tt -> innerParseCommandLineOpts {parsedArgs with listen_addr = Some(addr)} tt
        | [] -> help(); eprintf "ERROR : -la has to be provided either a domain name or an ip address"
        )

    | "-lp"::t ->
        (match t with
        | sport::tt ->
            let success,port = System.Int32.TryParse sport in
            if success then
                innerParseCommandLineOpts {parsedArgs with connect_port = Some(port)} tt
            else help(); eprintf "ERROR : -lp argument is not a correct integer"
        | [] -> help(); eprintf "ERROR : -lp has to be provided a port number"
        )

    | "-k"::t ->
        (match t with
        | "RSA"::t -> innerParseCommandLineOpts {parsedArgs with kex = Some(KeyExchangeRSA)} t
        | "DHE"::t -> innerParseCommandLineOpts {parsedArgs with kex = Some(KeyExchangeDHE)} t
        | "ECDHE"::t -> eprintf "ERROR : -k ECDHE support is in progress ! Be back soon =)"
        | h::t -> help(); eprintf "ERROR : -k argument is not a valid key exchange mechanism"
        )

    | "-i"::t -> info ()
    
    // Invalid command
    | h::t      -> help(); eprintf "Error : %A is not a valid option !\n" h



let handleCommandLineOpts args =
    let defaultOpts : CommandLineOpts = {
        scenario = None;
        role = None;
        kex = None;
        connect_addr = None;
        connect_port = None;
        listen_addr = None;
        listen_port = None;
        min_pv = None;
        verbosity = None;
    } in 
    innerParseCommandLineOpts defaultOpts args




[<EntryPoint>]
let main argv = 
    let args = argv |> List.ofSeq in 
    
    handleCommandLineOpts args;
//    ignore (System.Console.ReadLine());
    0



////////////////////////////////////////////////////////////////////////////////////////////////

    (* Standard RSA full handshake as Client *)
//    let st = Handshake_full_RSA.client("localhost",6443) in
//    printf "RSA client finished\n";

    (* Standard RSA full handshake as stateful Client *)
//    let st = Handshake_full_RSA.stateful_client("www.inria.fr") in
//    printf "RSA client stateful finished\n";

    (* Standard RSA handshake with resumption as Client*)
//    let st = Handshake_full_RSA.client("www.inria.fr") in
//    let _  = Tcp.close st.ns in 
//    let st = Handshake_resumption.client(st,"www.inria.fr") in
//    printf "RSA client resumption finished\n";

    (* Standard RSA handshake with renegotiation as Client *)
//   let st = Handshake_full_RSA.client("127.0.0.1",4433) in
//    let st = Handshake_full_RSA.client("127.0.0.1",4433,st) in
//    printf "RSA client renegotiation finished\n";

    (* Standard RSA full handshake with client authentication as Client *)
 //   let st = Handshake_full_RSA.client_with_auth("localhost","rsa.cert-02.mitls.org",port=6443) in
 //   printf "RSA client_auth finished\n";
    
    (* Standard DHE full handshake as Client *)
//    let st = Handshake_full_DHE.client("www.inria.fr") in
//    printf "DHE client finished\n";

    (* Standard DHE full handshake with client authentication as Client *)
//    let st = Handshake_full_DHE.client_with_auth("127.0.0.1","rsa.cert-01.mitls.org",44102) in
//    printf "DHE client_auth finished\n";

    (* Standard RSA full handshake as Server *)
//    printf "Running RSA server. Please connect to port 6443\n";
//    let st = Handshake_full_RSA.server("0.0.0.0","rsa.cert-02.mitls.org",6443) in
//    printf "RSA server finished\n";

    (* Standard RSA full handshake with client authentication as Server *)
//    printf "Running RSA server. Please connect to port 44202\n";
//    let st = Handshake_full_RSA.server_with_client_auth("0.0.0.0","rsa.cert-01.mitls.org",44202) in
//    printf "RSA server_with_client_auth finished\n";

    (* Standard DHE full handshake as Server *)
//    printf "Running RSA server. Please connect to port 44203\n";
//    let st = Handshake_full_DHE.server("127.0.0.1","rsa.cert-01.mitls.org",44203) in
//    printf "DHE server finished\n";

    (* Standard DHE full handshake with client authentication as Server *)
//    printf "Running RSA server. Please connect to port 44204\n";
//    let st = Handshake_full_DHE.server_with_client_auth("127.0.0.1","rsa.cert-01.mitls.org",44204) in
//    printf "DHE server_with_client_auth finished\n";

    (* Standard RSA full handshake as Client, with an alert in between *)
//    let st = Handshake_full_alert_RSA.client("localhost",6443) in
//    printf "RSA client finished\n";

////////////////////////////////////////////////////////////////////////////////////////////////

    (* Trace Interpreter *)
//    let st = TraceInterpreter.runClients "localhost" 6443 "rsa.cert-02.mitls.org" false in
//    printf "Client no-cert trace interpreter finished\n";

//    let st = TraceInterpreter.runClients "localhost" 6443 "rsa.cert-02.mitls.org" true in
//    printf "Client cert trace interpreter finished\n";

//    let st = TraceInterpreter.runServers 6443 "rsa.cert-01.mitls.org" false in
//    printf "Server no-cert trace interpreter finished\n";

//    let st = TraceInterpreter.runServers 6443 "rsa.cert-01.mitls.org" true in
//    printf "Server cert trace interpreter finished\n";

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
