(* ------------------------------------------------------------------------ *)
open System
open System.IO
open System.Net
open Microsoft.FSharp.Reflection

open TLStream

(* ------------------------------------------------------------------------ *)
let block = 256 * 1024

(* ------------------------------------------------------------------------ *)
exception NotAValidEnumeration

let enumeration<'T> () =
    let t = typeof<'T>

    if not (FSharpType.IsUnion(t)) then
        raise NotAValidEnumeration;

    let cases = FSharpType.GetUnionCases(t)

    if not (Array.forall
                (fun (c : UnionCaseInfo) -> c.GetFields().Length = 0)
                (FSharpType.GetUnionCases(t))) then
        raise NotAValidEnumeration;

    let cases =
        Array.map
            (fun (c : UnionCaseInfo) ->
                (c.Name, FSharpValue.MakeUnion(c, [||]) :?> 'T))
            cases
    in
        cases

(* ------------------------------------------------------------------------ *)
let cs_map = Map.ofArray (enumeration<TLSConstants.cipherSuiteName> ())
let vr_map = Map.ofArray (enumeration<TLSConstants.ProtocolVersion> ())

(* ------------------------------------------------------------------------ *)
let unnull dfl x =
    if x = null then dfl else x

(* ------------------------------------------------------------------------ *)
type options = {
    certname     : string;
    ciphersuites : TLSConstants.cipherSuiteName list;
}

(* ------------------------------------------------------------------------ *)
let tlsconfig options isserver = {
    TLSInfo.minVer = TLSConstants.TLS_1p0
    TLSInfo.maxVer = TLSConstants.TLS_1p2

    TLSInfo.ciphersuites = TLSConstants.cipherSuites_of_nameList options.ciphersuites

    TLSInfo.compressions = [ TLSConstants.NullCompression ]

    TLSInfo.honourHelloReq = TLSInfo.HRPResume
    TLSInfo.allowAnonCipherSuite = false
    TLSInfo.check_client_version_in_pms_for_old_tls = true
    TLSInfo.request_client_certificate = false
    
    TLSInfo.safe_renegotiation = true

    TLSInfo.server_name = options.certname;
    TLSInfo.client_name = ""

    TLSInfo.sessionDBFileName = (if isserver then "sessionDBFile.bin" else "sessionDBFile-client.bin")
    TLSInfo.sessionDBExpiry   = Bytes.newTimeSpan 1 0 0 0 (* one day *)
}

(* ------------------------------------------------------------------------ *)
let server (listener : Sockets.TcpListener) config =
    let buffer = Array.create block 0uy in

    while true do
        use socket = listener.AcceptTcpClient () in

        try
            let stream = new TLStream (socket.GetStream (), config, TLStream.TLSServer, false) in
            let loop   = ref true in
                while !loop do
                    if stream.Read (buffer, 0, buffer.Length) = 0 then
                        loop := false
                done
        with e ->
            printfn "%A" e
    done

(* ------------------------------------------------------------------------ *)
let entry () =
    let certname =
        unnull "rsa.cert-01.mitls.org"
            (Environment.GetEnvironmentVariable ("CERTNAME"))

    let options = {
        certname     = certname;
        ciphersuites = List.map snd (Map.toList cs_map);
    }

    let listener = new Sockets.TcpListener(IPAddress.Loopback, 5000) in
    listener.Start ();
    server listener (tlsconfig options true)

(* ------------------------------------------------------------------------ *)
let _ =
    CryptoProvider.CoreCrypto.Config ();
    entry ()
