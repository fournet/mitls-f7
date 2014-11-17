#light "off"

module FlexApps.Parsing

open TLSConstants




type ScenarioOpt    = FullHandshake | TraceInterpreter
type RoleOpt        = RoleClient | RoleServer | RoleMITM
type LogLevelOpt    = LogLevelTrace | LogLevelDebug | LogLevelInfo | LogLevelNone
type KeyExchangeOpt = KeyExchangeRSA | KeyExchangeDHE | KeyExchangeECDHE


type CommandLineOpts = {
    scenario      : option<ScenarioOpt>;
    role          : option<RoleOpt>;
    kex           : option<KeyExchangeOpt>;
    connect_addr  : option<string>;
    connect_port  : option<int>;
    connect_cert  : option<string>;
    listen_addr   : option<string>;
    listen_port   : option<int>;
    listen_cert   : option<string>;
    cert_req      : option<bool>;
    min_pv        : option<ProtocolVersion>;
    timeout       : option<int>;
    verbosity     : option<LogLevelOpt>;
}

let nullOpts = {
    scenario = None;
    role = None;
    kex = None;
    connect_addr = None;
    connect_port = None;
    connect_cert = None;
    listen_addr = None;
    listen_port = None;
    listen_cert = None;
    cert_req = None;
    min_pv = None;
    timeout = None;
    verbosity = None;
}


type Parsing =
    class

    static member innerParseCommandLineOpts parsedArgs args : CommandLineOpts =

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
            printf "  -ccert : [] Certificate CN to use if Client _    (default : rsa.cert-02.mitls.org)\n";
            printf "  -la    : [] Listening to address or domain _     (default : localhost)\n";
            printf "  -lp    : [] Listening to port number _           (default : 4433)\n";
            printf "  -lcert : [] Certificate CN to use if Server      (default : rsa.cert-01.mitls.org)\n";
            printf "  -lauth :    Request client authentication\n";
            printf "  -t     : [] Timeout for TCP connections          (default : 7.5s)\n";
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
        | []        -> parsedArgs
        | "-h"::t   -> help (); nullOpts

        // Match valid options
        | "-s"::t ->
            (match t with
            | "FullHandshake"::tt | "fullhandshake"::tt | "fh"::tt | "FH"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(FullHandshake)} tt
            | "Traces"::tt | "traces"::tt | "ti"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(TraceInterpreter)} tt
            | _ -> help(); eprintf "ERROR : -s argument is not a valid scenario"; nullOpts
            )

        | "-r"::t ->
            (match t with
            | "Client"::tt | "C"::tt | "c"::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with role = Some(RoleClient)} tt
            | "Server"::tt | "S"::tt | "s"::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with role = Some(RoleServer)} tt
            | "MITM"::tt | "M"::tt | "m"::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with role = Some(RoleMITM)} tt
            | _ -> help(); eprintf "ERROR : -r argument is not a valid role"; nullOpts
            )

        | "-ca"::t ->
            (match t with
            | addr::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with connect_addr = Some(addr)} tt
            | [] -> help(); eprintf "ERROR : -ca has to be provided either a domain name or an ip address"; nullOpts
            )

        | "-cp"::t ->
            (match t with
            | sport::tt ->
                let success,port = System.Int32.TryParse sport in
                    if success then Parsing.innerParseCommandLineOpts {parsedArgs with connect_port = Some(port)} tt
                    else let _ = help(); eprintf "ERROR : -cp argument not a correct integer" in nullOpts
            | [] -> help(); eprintf "ERROR : -cp has to be provided a port number"; nullOpts
            )

        | "-ccert"::t ->
            (match t with
            | cn::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with cert_req = Some(true); connect_cert = Some(cn)} tt
            | _ -> help(); eprintf "ERROR : -ccert has to be provided a Certificate Common Name"; nullOpts
            )

        | "-la"::t ->
            (match t with
            | addr::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with listen_addr = Some(addr)} tt
            | [] -> help(); eprintf "ERROR : -la has to be provided either a domain name or an ip address"; nullOpts
            )

        | "-lp"::t ->
            (match t with
            | sport::tt ->
                let success,port = System.Int32.TryParse sport in
                    if success then Parsing.innerParseCommandLineOpts {parsedArgs with connect_port = Some(port)} tt
                    else let _ = help(); eprintf "ERROR : -lp argument is not a correct integer" in nullOpts
            | [] -> help(); eprintf "ERROR : -lp has to be provided a port number"; nullOpts
            )

        | "-lcert"::t ->
            (match t with
            | cn::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with cert_req = Some(true); listen_cert = Some(cn)} tt
            | [] -> help(); eprintf "ERROR : -lcert has to be provided a Certificate Common Name"; nullOpts
            )

        | "-cauth"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with cert_req = Some(true)} t

        | "-k"::t ->
            (match t with
            | "RSA"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with kex = Some(KeyExchangeRSA)} t
            | "DHE"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with kex = Some(KeyExchangeDHE)} t
            | "ECDHE"::t -> eprintf "ERROR : -k ECDHE support is in progress ! Be back soon =)"; nullOpts
            | _ -> help(); eprintf "ERROR : -k argument is not a valid key exchange mechanism"; nullOpts
            )

        | "-t"::t ->
            (match t with
            | sport::tt ->
                let success,timeout = System.Int32.TryParse sport in
                    if success then Parsing.innerParseCommandLineOpts {parsedArgs with timeout = Some(timeout)} tt
                    else let _ = help(); eprintf "ERROR : -t argument not a correct integer" in nullOpts
            | [] -> help(); eprintf "ERROR : -t has to be provided a port number"; nullOpts
            )

        // Info on the program
        | "-i"::t -> info (); nullOpts
        
        // Invalid command
        | h::t      -> help(); eprintf "Error : %A is not a valid option !\n" h; nullOpts

    end