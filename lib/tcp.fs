module Tcp

open System.Net.Sockets
open System.Net
open Bytes
open Error

type NetworkStream = N of System.Net.Sockets.NetworkStream
type TcpListener = T of System.Net.Sockets.TcpListener

(* Server side *)

let listen addr port =
    let tcpList = new System.Net.Sockets.TcpListener(IPAddress.Parse(addr),port) in
    tcpList.Start();
    T tcpList

let acceptTimeout timeout (T tcpList) =
    let client = tcpList.AcceptTcpClient() in
    client.ReceiveTimeout <- timeout;
    client.SendTimeout <- timeout;
    N (client.GetStream())

let accept t =
    acceptTimeout 0 t

let stop (T tcpList) =
    tcpList.Stop()

(* Client side *)

let connectTimeout timeout addr port =
    let tcpCl = new TcpClient(addr,port) in
    tcpCl.ReceiveTimeout <- timeout;
    tcpCl.SendTimeout <- timeout;
    N (tcpCl.GetStream())

let connect addr port =
    connectTimeout 0 addr port

(* Input/Output *)

let dataAvailable (N ns) =
    try
        Correct (ns.DataAvailable)
    with
        | _ -> Error (Tcp,Internal)

let rec read_acc (N ns) nbytes prev =
    if nbytes = 0 then
        prev
    else
        let buf = Array.zeroCreate nbytes in
        let read = ns.Read (buf, 0, nbytes) in
        let rem = nbytes - read in
        read_acc (N ns) rem (Array.append prev (Array.sub buf 0 read))

let read (N ns) nbytes =
    try
        Correct (read_acc (N ns) nbytes (Array.zeroCreate 0))
    with
        | _ -> Error (Tcp,Internal)


let write (N ns) content =
    try
        Correct (ns.Write (content, 0, content.Length))
    with
        | _ -> Error (Tcp,Internal)

let close (N ns) =
    ns.Close()

