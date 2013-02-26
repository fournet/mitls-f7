open System
open System.Net
open System.Net.Sockets

open Org.BouncyCastle.Crypto.Prng
open Org.BouncyCastle.Crypto.Tls

(* ------------------------------------------------------------------------ *)
let block = 256 * 1024

let ciphers =
    Map.ofList [
      ("TLS_RSA_WITH_RC4_128_MD5", CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
      ("TLS_RSA_WITH_RC4_128_SHA", CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
      ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
      ("TLS_RSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
      ("TLS_RSA_WITH_AES_256_CBC_SHA", CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
      ("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
      ("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
      ("TLS_DHE_DSS_WITH_AES_256_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA); ]

(* ------------------------------------------------------------------------ *)
let udata = Array.create (1024*1024) 0uy

let initialize_udata () =
    let rnd = new CryptoApiRandomGenerator() in
        rnd.NextBytes(udata, 0, udata.Length)

(* ------------------------------------------------------------------------ *)
type MyAuthentication () =
    interface TlsAuthentication with
        member self.NotifyServerCertificate (_ : Certificate) =
            ()

        member self.GetClientCredentials (_ : CertificateRequest) =
            null

(* ------------------------------------------------------------------------ *)
type MyTlsClient (cs : CipherSuite) =
    inherit DefaultTlsClient ()

    override this.GetCipherSuites() =
        [|cs|]

    override this.GetAuthentication () =
        new MyAuthentication () :> TlsAuthentication

(* ------------------------------------------------------------------------ *)
let client () =
    let cs = Environment.GetEnvironmentVariable("CIPHERSUITE") in
    let cs = Map.find cs ciphers in

    let hsdone  = ref 0 in
    let hsticks = ref (int64 (0)) in

    for i = 0 to 20 do
        use socket = new TcpClient ()
        socket.Connect (IPAddress.Loopback, 5000)

        let t1 = DateTime.Now.Ticks in
        let tlssock = new TlsProtocolHandler(socket.GetStream ())

        tlssock.Connect (new MyTlsClient (cs));

        if i <> 0 then begin
            hsdone  := !hsdone  + 1;
            hsticks := !hsticks + (DateTime.Now.Ticks - t1);
        end

        tlssock.Close ();
    done;
    
    use socket = new TcpClient ()
    socket.Connect (IPAddress.Loopback, 5000)

    let tlssock = new TlsProtocolHandler(socket.GetStream ())
    tlssock.Connect (new MyTlsClient (cs))

    let sent  = ref 0 in
    let upos  = ref 0 in
    let ticks = DateTime.Now.Ticks in

        while !sent < 64*1024*1024 do
            if udata.Length - !upos < block then begin
                upos := 0
            end;
            tlssock.Stream.Write (udata, !upos, block)
            sent := !sent + block;
            upos := !upos + block;
        done;
        tlssock.Close ();

        let ticks = DateTime.Now.Ticks - ticks in
             ((!sent, ticks), (!hsdone, !hsticks))

(* ------------------------------------------------------------------------ *)
let program () =
    let cs = Environment.GetEnvironmentVariable("CIPHERSUITE") in

    initialize_udata ()

    let ((sent, ticks), (hsdone, hsticks)) = client () in
    let rate = float(sent) / (float(ticks) / float(TimeSpan.TicksPerSecond)) in
    let hsrate = float(hsdone) / (float(hsticks) / float(TimeSpan.TicksPerSecond)) in
        printfn "%s: %.2f HS/s" cs hsrate;
        printfn "%s: %.2f MiB/s" cs (rate / (1024. * 1024.))

(* ------------------------------------------------------------------------ *)
let _ = program ()
