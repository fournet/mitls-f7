open System
open System.Net
open System.Net.Sockets

open Org.BouncyCastle.Crypto.Prng
open Org.BouncyCastle.Crypto.Tls

(* ------------------------------------------------------------------------ *)
let block = 256 * 1024

(* ------------------------------------------------------------------------ *)
let udata = Array.create (1024*1024) 0uy

let initialize_udata () =
    let rnd = new CryptoApiRandomGenerator() in
        rnd.NextBytes(udata, 0, udata.Length)

(* ------------------------------------------------------------------------ *)
let client () =
    use socket = new TcpClient ()
    socket.Connect (IPAddress.Loopback, 5000)

    let tlssock = new TlsProtocolHandler(socket.GetStream ())
    tlssock.Connect (new AlwaysValidVerifyer ())

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
            (!sent, ticks)

(* ------------------------------------------------------------------------ *)
let program () =
    initialize_udata ()

    let (sent, ticks) = client () in
    let rate = float(sent) / (float(ticks) / float(TimeSpan.TicksPerSecond)) in
        printfn "%.2f MiB/s" (rate / (1024. * 1024.))

(* ------------------------------------------------------------------------ *)
let _ = program ()
