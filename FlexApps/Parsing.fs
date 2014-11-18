#light "off"

module FlexApps.Parsing

open TLSConstants




type ScenarioOpt    = // Normal
                      | FullHandshake 
                      // TraceIN
                      | TraceInterpreter
                      // Metrics
                      | DHParams
                      // Attacks
                      | FragmentedAlert | MalformedAlert | FragmentedClientHello 
                      | LateCCS | EarlyCCS | TripleHandshake | SmallSubgroup | EarlyResume


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
    resume        : option<bool>;
    renego        : option<bool>;
    timeout       : option<int>;
    testing       : option<bool>;
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
    resume = None;
    renego = None;
    timeout = None;
    testing = None;
    verbosity = None;
}




let flexbanner () =
    printf "FlexTLS Command Line Interface\n"
        
let flexinfo () = 
    flexbanner ();
    printf "\n";
    printf "  - Version : FlexTLS 0.0.1\n";
    printf "              November 20, 2014\n";
    printf "\n";
    printf "  - Authors : Benjamin Beurdouche & Alfredo Pironti\n";
    printf "              INRIA Paris-Rocquencourt\n";
    printf "              Team Prosecco\n";
    printf "\n";
    printf "  - Website : http://www.mitls.org\n"

        
let flexhelp () = 
    flexbanner ();
    printf "  -info     : Infos about this software\n";
    printf "  -s        : *  Scenario to execute\n";
    printf "\n";
    printf "                 - Full Handshake        {fh}\n";
    printf "                 - Trace Interpreter     {ti,traceinterpreter}\n";
    printf "                 - Metrics\n";
    printf "                     DH Parameters       {dhp,dhparams}\n";
    printf "                 - Attacks\n";
    printf "                     Malformed alert     {mal,malformedalert}\n";
    printf "                     Fragmented alert    {fal,fragmentedalert}\n";
    printf "                     Fragmented Client Hello {fch,fragmentedch}\n";
    printf "                     Early CCS           {eccs,earlyccs}\n";
    printf "                     Late CCS            {lccs,lateccs}\n";
    printf "                     Triple Handshake    {ths,triplehandshake}\n";
    printf "                     Small Subgroup      {sgp,smallsubgroup}\n";
    printf "                     Early Resume        {eres,earlyresume}\n";
    printf "                 - Unit Testing\n";
    printf "                     All                 {uall,unitall}\n";
    printf "\n";
    printf "  -r        : []  Role\n";
    printf "                 - Client                {c,C,Client}  (default)\n";
    printf "                 - Server                {s,S,Server}\n";
    printf "                 - Both                  {m,M,MITM}\n";
    printf "  -k        : []  Key exchange\n";
    printf "                 - RSA                   {r,rsa,RSA}   (default)\n";
    printf "                 - DHE                   {dh,dhe,DHE}\n";
    printf "                 - ECDHE                 {ec,ecdhe,ECDHE}\n";
//    printf "  -pv     : [] Protocol version minimum\n";
//    printf "                - SSL 3.0 : {30,ssl3,SSL3}\n";
//    printf "                - TLS 1.0 : {10,tls10,TLS10}\n";
//    printf "                - TLS 1.1 : {11,tls11,TLS11}\n";
//    printf "                - TLS 1.2 : {12,tls12,TLS12}         (default)\n";
//    printf "                - TLS 1.3 : {13,tls13,TLS13}\n";
//    printf "  -cipher : [] Specify a ciphersuite\n";
    printf "  -ca       : [] Connect to address or domain _        (default : localhost)\n";
    printf "  -cp       : [] Connect to port number _              (default : 443)\n";
    printf "  -ccert    : [] Certificate CN to use if Client _     (default : rsa.cert-02.mitls.org)\n";
    printf "  -la       : [] Listening to address or domain _      (default : localhost)\n";
    printf "  -lp       : [] Listening to port number _            (default : 4433)\n";
    printf "  -lcert    : [] Certificate CN to use if Server       (default : rsa.cert-01.mitls.org)\n";
    printf "  -lauth    :    Request client authentication\n";
    printf "  -resum    :    Resume after full handshake\n";
    printf "  -reneg    :    Renegotiate after full handshake\n";
//    printf "  -t      : [] Timeout for TCP connections           (default : 7.5s)\n";
//    printf "  -tests  :    Run self unit testing\n";
//    printf "\n";
//    printf "  -disable-exts     :    Disable all extensions\n";
//    printf "  -disable-vd-fin   :    Disable Finished verify data check \n";
//    printf "  -disable-vd-rni   :    Disable checking verify data in case of \n";
//    printf "                           Renegotiation Indication Extension\n";
    printf "\n";
    printf "  -v        : [] Verbosity  (-) {0..3} (+) \n";
    printf "\n";
    printf " *  =>  Require an argument\n";
    printf " [] =>  Default will be used if not provided\n"




type Parsing =
    class

    static member innerParseCommandLineOpts parsedArgs args : CommandLineOpts =
        // Process options
        match args with
        // Infos and Help
        | []        -> parsedArgs
        | "-h"::t   -> flexhelp (); nullOpts

        // Match valid options
        | "-s"::t ->
            (match t with
            | "fullhandshake"::tt | "fh"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(FullHandshake)} tt
            | "traceinterpreter"::tt | "traces"::tt | "ti"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(TraceInterpreter)} tt
            | "dhparams"::tt | "dhp"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(DHParams)} tt
            | "malformedalert"::tt | "mal"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(MalformedAlert)} tt
            | "fragmentedch"::tt | "fch"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(FragmentedClientHello)} tt
            | "fragmentedalert"::tt | "fal"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(FragmentedAlert)} tt
            | "earlyccs"::tt | "eccs"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(EarlyCCS)} tt
            | "lateccs"::tt | "lccs"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(LateCCS)} tt
            | "triplehandshake"::tt | "ths"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(TripleHandshake)} tt
            | "smallsubgroup"::tt | "ssg"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(SmallSubgroup)} tt
            | "earlyresume"::tt | "eres"::tt ->
                Parsing.innerParseCommandLineOpts {parsedArgs with scenario = Some(EarlyResume)} tt

            | _ -> flexhelp(); eprintf "ERROR : -s argument is not a valid scenario\n"; nullOpts
            )

        | "-r"::t ->
            (match t with
            | "Client"::tt | "C"::tt | "c"::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with role = Some(RoleClient)} tt
            | "Server"::tt | "S"::tt | "s"::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with role = Some(RoleServer)} tt
            | "MITM"::tt | "M"::tt | "m"::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with role = Some(RoleMITM)} tt
            | _ -> flexhelp(); eprintf "ERROR : -r argument is not a valid role\n"; nullOpts
            )

        | "-ca"::t ->
            (match t with
            | addr::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with connect_addr = Some(addr)} tt
            | [] -> flexhelp(); eprintf "ERROR : -ca has to be provided either a domain name or an ip address\n"; nullOpts
            )

        | "-cp"::t ->
            (match t with
            | sport::tt ->
                let success,port = System.Int32.TryParse sport in
                    if success then Parsing.innerParseCommandLineOpts {parsedArgs with connect_port = Some(port)} tt
                    else let _ = flexhelp(); eprintf "ERROR : -cp argument not a correct integer\n" in nullOpts
            | [] -> flexhelp(); eprintf "ERROR : -cp has to be provided a port number\n"; nullOpts
            )

        | "-ccert"::t ->
            (match t with
            | cn::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with cert_req = Some(true); connect_cert = Some(cn)} tt
            | _ -> flexhelp(); eprintf "ERROR : -ccert has to be provided a Certificate Common Name\n"; nullOpts
            )

        | "-la"::t ->
            (match t with
            | addr::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with listen_addr = Some(addr)} tt
            | [] -> flexhelp(); eprintf "ERROR : -la has to be provided either a domain name or an ip address\n"; nullOpts
            )

        | "-lp"::t ->
            (match t with
            | sport::tt ->
                let success,port = System.Int32.TryParse sport in
                    if success then Parsing.innerParseCommandLineOpts {parsedArgs with connect_port = Some(port)} tt
                    else let _ = flexhelp(); eprintf "ERROR : -lp argument is not a correct integer\n" in nullOpts
            | [] -> flexhelp(); eprintf "ERROR : -lp has to be provided a port number\n"; nullOpts
            )

        | "-lcert"::t ->
            (match t with
            | cn::tt -> Parsing.innerParseCommandLineOpts {parsedArgs with cert_req = Some(true); listen_cert = Some(cn)} tt
            | [] -> flexhelp(); eprintf "ERROR : -lcert has to be provided a Certificate Common Name\n"; nullOpts
            )

        | "-cauth"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with cert_req = Some(true)} t
        
        | "-resum"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with resume = Some(true)} t
        
        | "-reneg"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with renego = Some(true)} t

        | "-k"::t ->
            (match t with
            | "RSA"::t | "rsa"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with kex = Some(KeyExchangeRSA)} t
            | "DHE"::t | "dhe"::t -> Parsing.innerParseCommandLineOpts {parsedArgs with kex = Some(KeyExchangeDHE)} t
            | "ECDHE"::t | "ecdhe"::t -> eprintf "ERROR : -k ECDHE support is in progress ! Be back soon =)\n"; nullOpts
            | _ -> flexhelp(); eprintf "ERROR : -k argument is not a valid key exchange mechanism\n"; nullOpts
            )

        | "-t"::t ->
            (match t with
            | sport::tt ->
                let success,timeout = System.Int32.TryParse sport in
                    if success then Parsing.innerParseCommandLineOpts {parsedArgs with timeout = Some(timeout)} tt
                    else let _ = flexhelp(); eprintf "ERROR : -t argument not a correct integer\n" in nullOpts
            | [] -> flexhelp(); eprintf "ERROR : -t has to be provided a port number\n"; nullOpts
            )

        // Info on the program
        | "-i"::t -> flexinfo (); nullOpts
        
        // Invalid command
        | h::t    -> flexhelp(); eprintf "ERROR : %A is not a valid option !\n" h; nullOpts

    end