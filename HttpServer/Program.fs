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

let tlsoptions certdir = {
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
    TLSInfo.request_client_certificate = false
    TLSInfo.check_client_version_in_pms_for_old_tls = true
    TLSInfo.safe_renegotiation = true

    TLSInfo.server_cert_file = Path.Combine(certdir, "server")
    TLSInfo.trustedRootCertificates = []

    TLSInfo.sessionDBFileName = Path.Combine(certdir, "sessionDBFile.bin")
    TLSInfo.sessionDBExpiry = Bytes.newTimeSpan 2 0 0 0 (* two days *)
}

type options = {
    rootdir   : string;
    certdir   : string;
    localaddr : IPEndPoint;
}

exception ArgError of string

let cmdparse = fun () ->
    let assembly = System.Reflection.Assembly.GetExecutingAssembly()
    let mypath   = Path.GetDirectoryName(assembly.Location)
    let options  = ref {
        rootdir   = Path.Combine(mypath, "htdocs");
        certdir   = Path.Combine(mypath, "certificates");
        localaddr = IPEndPoint(IPAddress.Loopback, 2443); }

    let valid_root_path = fun s ->
        try
            Path.IsPathRooted s
        with :?System.ArgumentException ->
            false

    let o_rootdir = fun s ->
        if not (valid_root_path s) then
            let msg = sprintf "Invalid absolute path (root directory): %s" s in
                raise (ArgError msg);
        options := { !options with rootdir = s }

    let o_certdir = fun s ->
        if not (valid_root_path s) then
            let msg = sprintf "Invalid absolute path (certs directory): %s" s in
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

    let specs = [
        "--root-dir"    , ArgType.String o_rootdir, "HTTP root directory (absolute)"
        "--cert-dir"    , ArgType.String o_certdir, "certificates root directory (absolute)"
        "--bind-port"   , ArgType.Int    o_port   , "local port"
        "--bind-address", ArgType.String o_address, "local address"]

    let specs = specs |> List.map (fun (sh, ty, desc) -> ArgInfo(sh, ty, desc))

    try
        ArgParser.Parse specs; !options

    with ArgError msg ->
        ArgParser.Usage(specs, sprintf "Error: %s\n" msg);
        exit 1

let _ =
    HttpLogger.HttpLogger.Level <- HttpLogger.DEBUG;

    let options    = cmdparse () in
    let tlsoptions = tlsoptions options.certdir in
    let mimesmap   = try_read_mimes (Path.Combine(options.rootdir, "mime.types")) in

        HttpServer.run {
            docroot    = options.rootdir  ;
            mimesmap   = mimesmap         ;
            localaddr  = options.localaddr;
            tlsoptions = Some tlsoptions  ;
        }
