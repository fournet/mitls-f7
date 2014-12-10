#light "off"

module FlexApps.Parsing

open TLSConstants

type ScenarioOpt    = // Normal
                      | FullHandshake 
                      // Experimental TLS 1.3 DHE
                      | TLS13
                      // Attacks
                      | FragmentedAlert | MalformedAlert | FragmentedClientHello 
                      | EarlyCCS | TripleHandshake 


type RoleOpt        = RoleClient | RoleServer | RoleMITM
type LogLevelOpt    = LogLevelTrace | LogLevelDebug | LogLevelInfo | LogLevelNone
type KeyExchangeOpt = KeyExchangeRSA | KeyExchangeDHE | KeyExchangeECDHE


type CommandLineOpts = {
    scenario      : option<ScenarioOpt>;
    role          : option<RoleOpt>;
    kex           : option<KeyExchangeOpt>;
    connect_addr  : string;
    connect_port  : int;
    connect_cert  : option<string>;
    listen_addr   : string;
    listen_port   : int;
    listen_cert   : string;
    min_pv        : ProtocolVersion;
    resume        : bool;
    renego        : bool;
    timeout       : int;
    testing       : bool;
    verbosity     : LogLevelOpt;
}

let defaultOpts = {
    scenario = None;
    role = None;
    kex = None;
    connect_addr = "localhost";
    connect_port = 443;
    connect_cert = None;
    listen_addr = "localhost";
    listen_port = 4433;
    listen_cert = "rsa.cert-01.mitls.org";
    min_pv = TLS_1p2;
    resume = false;
    renego = false;
    timeout = 7500;
    testing = false;
    verbosity = LogLevelInfo;
}

let stdout = System.Console.Out
let stderr = System.Console.Error

let flexbanner w =
    fprintf w "\n    --- FlexTLS Command Line Interface ---\n";
    fprintf w "\n"
        
let flexinfo w = 
    flexbanner w;
    fprintf w "\n";
    fprintf w "  - Version     : FlexTLS Ekr's special 0.0.1\n";
    fprintf w "                  December 10, 2014\n";
    fprintf w "\n";            
    fprintf w "  - Authors     : Benjamin Beurdouche & Alfredo Pironti\n";
    fprintf w "                  INRIA Paris-Rocquencourt\n";
    fprintf w "                  Team Prosecco\n";
    fprintf w "\n";            
    fprintf w "  - Website     : http://www.mitls.org\n"

        
let flexhelp w = 
    flexbanner w;
    fprintf w "  -h --help     :    This help message\n";
    fprintf w "  --version     :    Infos about this software\n";
    fprintf w "\n";
    fprintf w "  -s --scenario : *  Scenario to execute\n";
    fprintf w "                     - Full Handshake                {fh}\n";
    fprintf w "                     - SmackTLS                      {smacktls}\n";
    fprintf w "                     - Metrics\n";                   
    fprintf w "                         DH Parameters               {dhp,dhparams}\n";
    fprintf w "                     - Attacks\n";                   
    fprintf w "                         Malformed alert             {mal,malformedalert}\n";
    fprintf w "                         Fragmented alert            {fal,fragmentedalert}\n";
    fprintf w "                         Fragmented Client Hello     {fch,fragmentedch}\n";
    fprintf w "                         Early CCS                   {eccs,earlyccs}\n";
    fprintf w "                         Triple Handshake            {ths,triplehandshake}\n";
    fprintf w "                     - Experimental TLS 1.3 DHE      {13}\n";
    fprintf w "\n";                                             
    fprintf w "  -r --role     : []  Role\n";                  
    fprintf w "                     - Client                        {c,C,Client}  (default)\n";
    fprintf w "                     - Server                        {s,S,Server}\n";
    fprintf w "                     - Both                          {m,M,MITM}\n";
    fprintf w "  -k --kex      : []  Key exchange\n";               
    fprintf w "                     - RSA                           {r,rsa,RSA}   (default)\n";
    fprintf w "                     - DHE                           {dh,dhe,DHE}\n";
    fprintf w "                     - ECDHE                         {ec,ecdhe,ECDHE}\n";
    fprintf w "  --connect     : [] Connect to address (or domain) and port    (default : %s:%d)\n" defaultOpts.connect_addr defaultOpts.connect_port;
    fprintf w "  --client-cert : [] Use client authentication with the given CN\n";
    fprintf w "  --accept      : [] Accept address (or domain) and port        (default : %s:%d)\n" defaultOpts.listen_addr defaultOpts.listen_port;
    fprintf w "  --server-cert : [] Certificate CN to use if Server            (default : %s)\n" defaultOpts.listen_cert;
    fprintf w "  --resume      :    Resume after full handshake\n";
    fprintf w "  --renego      :    Renegotiate after full handshake\n";
//    fprintf w "  -t --timeout : [] Timeout for TCP connections           (default : 7500ms)\n";
//    printf "  -tests  :    Run self unit testing\n";
//    printf "\n";
//    printf "  -disable-exts     :    Disable all extensions\n";
//    printf "  -disable-vd-fin   :    Disable Finished verify data check \n";
//    printf "  -disable-vd-rni   :    Disable checking verify data in case of \n";
//    printf "                           Renegotiation Indication Extension\n";
    fprintf w "\n";
 //   printf "  --verbose    : [] Verbosity  (-) {0..3} (+) \n";
 //   printf "\n";
    fprintf w " *  =>  Require an argument\n";
    fprintf w " [] =>  Default will be used if not provided\n"




type Parsing =
    class

    static member innerParseCommandLineOpts parsedArgs args : option<CommandLineOpts> =
        // Process options
        match args with
        // Infos and Help
        | []        -> Some(parsedArgs)
        | "-h"::_
        | "--help"::_   -> flexhelp stdout ; None

        // Match valid options
        | "-s"::t
        | "--scenario"::t ->
            (match t with
            | "fullhandshake"::tt | "fh"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(FullHandshake)} tt
            | "malformedalert"::tt | "mal"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(MalformedAlert)} tt
            | "fragmentedch"::tt | "fch"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(FragmentedClientHello)} tt
            | "fragmentedalert"::tt | "fal"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(FragmentedAlert)} tt
            | "earlyccs"::tt | "eccs"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(EarlyCCS)} tt
            | "triplehandshake"::tt | "ths"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(TripleHandshake)} tt
            | "13"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(TLS13)} tt


            | s::_ -> flexhelp stderr; eprintf "ERROR : invalid scenario provided: %s\n" s; None
            | [] -> flexhelp stderr; eprintf "ERROR : scenario not provided\n"; None
            )

        | "-r"::t
        | "--role"::t ->
            (match t with
            | "Client"::tt | "C"::tt | "c"::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with role = Some(RoleClient)} tt
            | "Server"::tt | "S"::tt | "s"::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with role = Some(RoleServer)} tt
            | "MITM"::tt | "M"::tt | "m"::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with role = Some(RoleMITM)} tt
            | r::_ -> flexhelp stderr; eprintf "ERROR : invalid role provided: %s\n" r; None
            | [] -> flexhelp stderr; eprintf "ERROR : role not provided\n"; None
            )

        | "--connect"::t ->
            (match t with
            | addr::tt ->
                let addra = addr.Split [|':'|] in
                if addra.Length <> 2 then
                    (flexhelp stderr; eprintf "ERROR : invalid connect address provided: %s\n" addr; None)
                else
                    (let a,p = addra.[0],addra.[1] in
                    match System.Int32.TryParse p with
                    | true,p when p>0 -> Parsing.innerParseCommandLineOpts {parsedArgs with connect_addr = a; connect_port =  p} tt
                    | true,p -> flexhelp stderr; eprintf "ERROR : invalid connect port provided: %d\n" p; None
                    | false,_ -> flexhelp stderr; eprintf "ERROR : invalid connect port provided: %s\n" p; None)
            | [] -> flexhelp stderr; eprintf "ERROR : accept connect not provided\n"; None
            )

        | "--client-cert"::t ->
            (match t with
            | cn::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with connect_cert = Some(cn)} tt
            | _ -> flexhelp stderr; eprintf "ERROR : no client common name provided\n"; None
            )

        | "--accept"::t ->
            (match t with
            | addr::tt ->
                let addra = addr.Split [|':'|] in
                if addra.Length <> 2 then
                    (flexhelp stderr; eprintf "ERROR : invalid accept address provided: %s\n" addr; None)
                else
                    (let a,p = addra.[0],addra.[1] in
                    match System.Int32.TryParse p with
                    | true,p when p>0 -> Parsing.innerParseCommandLineOpts {parsedArgs with listen_addr = a; listen_port = p} tt
                    | true,p -> flexhelp stderr; eprintf "ERROR : invalid accept port provided: %d\n" p; None
                    | false,_ -> flexhelp stderr; eprintf "ERROR : invalid accept port provided: %s\n" p; None)
            | [] -> flexhelp stderr; eprintf "ERROR : accept address not provided\n"; None
            )

        | "--server-cert"::t ->
            (match t with
            | cn::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with listen_cert = cn} tt
            | [] -> flexhelp stderr; eprintf "ERROR : server common name not provided\n"; None
            )

        | "--resume"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with resume = true} t
        
        | "--renego"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with renego = true} t

        | "-k"::t
        | "--kex"::t ->
            (match t with
            | "RSA"::t | "rsa"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with kex = Some(KeyExchangeRSA)} t
            | "DHE"::t | "dhe"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with kex = Some(KeyExchangeDHE)} t
            | "ECDHE"::t | "ecdhe"::t -> eprintf "ERROR : ECDHE support is in progress. Sorry.\n"; None
            | k::_ -> flexhelp stderr; eprintf "ERROR : invalid key exchange provided: %s\n" k; None
            | [] -> flexhelp stderr; eprintf "ERROR : key exchange not provided\n"; None
            )

        // Info on the program
        | "--version"::t -> flexinfo stdout; None
        
        // Invalid command
        | h::_    -> flexhelp stderr; eprintf "ERROR : unrecognized option: %s\n" h; None

    end