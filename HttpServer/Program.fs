module HttpEntryPoint

open System
open System.IO
open System.Net
open HttpServer

let try_read_mimes path =
    try
        Mime.of_file path
    with :? IOException as e ->
        Console.WriteLine("cannot read mime-types: " + e.Message)
        Mime.MimeMap ()

let tlsoptions = {
    AppConfig.minVer = CipherSuites.ProtocolVersion.SSL_3p0
    AppConfig.maxVer = CipherSuites.ProtocolVersion.TLS_1p2

    AppConfig.ciphersuites =
        CipherSuites.cipherSuites_of_nameList [
            CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA;
            CipherSuites.TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        ]

    AppConfig.compressions = [ CipherSuites.NullCompression ]

    AppConfig.honourHelloReq = AppConfig.HRPResume
    AppConfig.allowAnonCipherSuite = false
    AppConfig.request_client_certificate = false
    AppConfig.check_client_version_in_pms_for_old_tls = true
    AppConfig.safe_renegotiation = true

    AppConfig.server_cert_file = "server"
    AppConfig.certificateValidationPolicy = (fun _ -> true)
    AppConfig.isCompatibleSession = (fun oldS newS -> oldS = newS)

    AppConfig.sessionDBFileName = "sessionDBFile.bin"
    AppConfig.sessionDBExpiry = new System.TimeSpan(2,0,0,0) (* two days *)
}

let _ =
    HttpLogger.HttpLogger.Level <- HttpLogger.DEBUG;

    let docroot    = "../../" //"C:\htdocs" in
    let localaddr  = IPEndPoint(IPAddress.Loopback, 2443) in
    let mimesmap   = try_read_mimes (Path.Combine(docroot, "mime.types")) in
        
        SessionDB.create tlsoptions;

        HttpServer.run {
            docroot    = docroot        ;
            mimesmap   = mimesmap       ;
            localaddr  = localaddr      ;
            tlsoptions = Some tlsoptions;
        }
