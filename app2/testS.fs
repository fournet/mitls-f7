module testS

open TLStream
open System.Net
open System.Net.Sockets

let test =
    let sock = TcpListener (IPEndPoint(IPAddress.Loopback, 2443)) in
    sock.Server.SetSocketOption(SocketOptionLevel.Socket,
                                          SocketOptionName.ReuseAddress,
                                          true);
    sock.Start()
    for i = 1 to 1000 do
    let s = sock.AcceptTcpClient() in
    let stream = s.GetStream() in
    ignore (new TLStream(stream,TLSInfo.defaultConfig,TLSServer))
    done