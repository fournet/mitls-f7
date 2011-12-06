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
    AppCommon.minVer = CipherSuites.ProtocolVersionType.SSL_3p0
    AppCommon.maxVer = CipherSuites.ProtocolVersionType.TLS_1p2

    AppCommon.ciphersuites =
        CipherSuites.cipherSuites_of_nameList [
            CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA;
            CipherSuites.TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        ]

    AppCommon.compressions = [ CipherSuites.Null ]

    AppCommon.honourHelloReq = AppCommon.HRPResume
    AppCommon.allowAnonCipherSuite = false
    AppCommon.request_client_certificate = false
    AppCommon.check_client_version_in_pms_for_old_tls = true
    AppCommon.safe_renegotiation = true

    AppCommon.server_cert_file = "server"
    AppCommon.certificateValidationPolicy = (fun _ -> true)

    AppCommon.sessionDBFileName = "sessionDBFile.bin"
    AppCommon.sessionDBExpiry = new System.TimeSpan(2,0,0,0) (* two days *)
}

let _ =
    HttpLogger.HttpLogger.Level <- HttpLogger.DEBUG;

    let docroot    = "C:\htdocs" in
    let localaddr  = IPEndPoint(IPAddress.Loopback, 2443) in
    let mimesmap   = try_read_mimes (Path.Combine(docroot, "mime.types")) in
        
        SessionDB.create tlsoptions;

        HttpServer.run {
            docroot    = docroot        ;
            mimesmap   = mimesmap       ;
            localaddr  = localaddr      ;
            tlsoptions = Some tlsoptions;
        }
