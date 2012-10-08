module HttpEntryPoint

open System
open System.IO
open System.Net
open HttpServer
open Microsoft.FSharp.Text

let try_read_mimes path =
    try
        Mime.of_file path
    with :? IOException as e ->
        Console.WriteLine("cannot read mime-types: " + e.Message)
        Mime.MimeMap ()

let tlsoptions sessionDBDir serverName clientName = {
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
    TLSInfo.request_client_certificate = match clientName with | None -> false | Some(_) -> true
    
    TLSInfo.safe_renegotiation = true

    TLSInfo.server_name = serverName
    TLSInfo.client_name = match clientName with | None -> "" | Some(name) -> name

    TLSInfo.sessionDBFileName = Path.Combine(sessionDBDir, "sessionDBFile.bin")
    TLSInfo.sessionDBExpiry = Bytes.newTimeSpan 2 0 0 0 (* two days *)
}

type options = {
    rootdir   : string;
    certdir   : string;
    localaddr : IPEndPoint;
    localname : string;
    remotename: string option;
}

exception ArgError of string

let cmdparse = fun () ->
    let assembly = System.Reflection.Assembly.GetExecutingAssembly()
    let mypath   = Path.GetDirectoryName(assembly.Location)
    let options  = ref {
        rootdir   = Path.Combine(mypath, "htdocs");
        certdir   = Path.Combine(mypath, "sessionDB");
        localaddr = IPEndPoint(IPAddress.Loopback, 2443);
        localname = "tls.inria.fr";
        remotename= None }

    let valid_path = fun path ->
        Directory.Exists path

    let o_rootdir = fun s ->
        if not (valid_path s) then
            let msg = sprintf "Invalid path (root directory): %s" s in
                raise (ArgError msg);
        options := { !options with rootdir = s }

    let o_certdir = fun s ->
        if not (valid_path s) then
            let msg = sprintf "Invalid path (certs directory): %s" s in
                raise (ArgError msg);
        options := { !options with certdir = s }

    let o_port = fun i ->
        if i <= 0 || i > 65535 then
            raise (ArgError (sprintf "Invalid (bind) port: %d" i));
        let ep = IPEndPoint((!options).localaddr.Address, i) in
            options := { !options with localaddr = ep }

    let o_address = fun s ->
        try
            let ip = IPAddress.Parse s
            let ep = IPEndPoint(ip, (!options).localaddr.Port) in
                options := { !options with localaddr = ep }
        with :?System.FormatException ->
            raise (ArgError (sprintf "Invalid IP Address: %s" s))

    let o_localname = fun s ->
        options := { !options with localname = s}

    let o_remotename = fun s ->
        options := { !options with remotename = Some(s)}

    let specs = [
        "--root-dir"     , ArgType.String o_rootdir   , "HTTP root directory"
        "--sessionDB-dir", ArgType.String o_certdir   , "session database directory"
        "--bind-port"    , ArgType.Int    o_port      , "local port"
        "--bind-address" , ArgType.String o_address   , "local address"
        "--local-name"   , ArgType.String o_localname , "local host name"
        "--remote-name"  , ArgType.String o_remotename, "remote host name (if any)"]

    let specs = specs |> List.map (fun (sh, ty, desc) -> ArgInfo(sh, ty, desc))

    try
        ArgParser.Parse specs; !options

    with ArgError msg ->
        ArgParser.Usage(specs, sprintf "Error: %s\n" msg);
        exit 1

let _ =
    HttpLogger.HttpLogger.Level <- HttpLogger.DEBUG;

    let options    = cmdparse () in
    let tlsoptions = tlsoptions options.certdir options.localname options.remotename in
    let mimesmap   = try_read_mimes (Path.Combine(options.rootdir, "mime.types")) in

        HttpServer.run {
            docroot    = options.rootdir  ;
            mimesmap   = mimesmap         ;
            localaddr  = options.localaddr;
            tlsoptions = Some tlsoptions  ;
        }
