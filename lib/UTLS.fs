module UTLS

// TODO: locking

(* ------------------------------------------------------------------------ *)
open Bytes
open Error
open Dispatch
open TLSInfo
open TLS

(* ------------------------------------------------------------------------ *)
type rawfd   = Tcp.NetworkStream
type fd      = int
type queryhd = int

let EI_BADHANDLE  = -1
let EI_BADCERTIDX = -2
let EI_READERROR  = -3
let EI_CLOSE      = -4
let EI_FATAL      = -5
let EI_WARNING    = -6
let EI_CERTQUERY  = -7
let EI_HANDSHAKEN = -8
let EI_DONTWRITE  = -9
let EI_WRITEERROR = -10
let EI_MUSTREAD   = -11
let EI_HSONGOING  = -12

type handleinfo = {
    conn : Connection;
}

let handleinfo_of_conn (c : Connection) : handleinfo =
    { conn = c; }

type fdmap = (fd * handleinfo) list

let fds = ref ([] : fdmap)
let fdc = ref 0

(* ------------------------------------------------------------------------ *)
let new_fd (conn : Connection) : fd =
    let fd = !fdc in
        fds := (fd, handleinfo_of_conn conn) :: !fds;
        fdc := !fdc + 1;
        fd

(* ------------------------------------------------------------------------ *)
let rec unbind_fd_r (fd : fd) (fds : fdmap) : fdmap =
    match fds with
    | [] -> []
    | (h, hi) :: fds ->
        let fds = unbind_fd_r fd fds in
            if fd = h then fds else (h, hi) :: fds

let unbind_fd (fd : fd) : unit =
    fds := unbind_fd_r fd !fds

(* ------------------------------------------------------------------------ *)
let rec connection_of_fd_r (fd : fd) (fds : fdmap) : Connection option =
    match fds with
    | [] -> None
    | (h, hd) :: fds ->
        if fd = h then Some hd.conn else connection_of_fd_r fd fds

let connection_of_fd (fd : fd) : Connection option =
    connection_of_fd_r fd !fds

(* ------------------------------------------------------------------------ *)
let rec update_fd_connection_r (fd : fd) (conn : Connection) (fds : fdmap) : fdmap =
    match fds with
    | [] -> Error.unexpectedError "[fd] unbound"
    | (h, hd) :: fds ->
        if fd = h then
            (h, { hd with conn = conn }) :: fds
        else
            (h, hd) :: (update_fd_connection_r fd conn fds)

let update_fd_connection (fd : fd) (conn : Connection) : unit =
    fds := update_fd_connection_r fd conn !fds

(* ------------------------------------------------------------------------ *)
let read (fd : int) : int * bytes =
    match connection_of_fd fd with
    | None -> (EI_BADHANDLE, [||])

    | Some c ->
        match TLS.read c with
        | TLS.ReadError _ ->
            (EI_READERROR, [||])

        | TLS.Close _ ->
            unbind_fd fd
            (EI_CLOSE, [||])

        | TLS.Fatal e ->
            unbind_fd fd
            (EI_FATAL, Alert.alertBytes e)

        | TLS.Warning (conn, e) ->
            let _ = update_fd_connection fd conn in
                (EI_WARNING, Alert.alertBytes e)

        | TLS.CertQuery (conn, q) -> failwith ""
(*            match add_query_cert fd q with
            | None -> (EI_BADHANDLE, [||])
            | Some idx ->
                ignore (update_fd_connection fd conn);
                (EI_CERTQUERY, Bytes.bytes_of_int 4 idx)
*)

        | TLS.Handshaken conn ->
            let _ = update_fd_connection fd conn in
                (EI_HANDSHAKEN, [||])

        | TLS.Read (conn, (rg, m)) ->
            let plain =
                DataStream.deltaRepr
                    (Dispatch.getEpochIn conn) (TLS.getInStream conn) rg m
            in
                let _ = update_fd_connection fd conn in
                    (Bytes.length plain, plain)

        | TLS.DontWrite conn ->
            let _ = update_fd_connection fd conn in
                (EI_DONTWRITE, [||])

(* ------------------------------------------------------------------------ *)
let write (fd : fd) (bytes : bytes) : int =
    match connection_of_fd fd with
    | None      -> EI_BADHANDLE
    | Some conn -> 
        let length = Bytes.length bytes in
        let delta  =
            DataStream.createDelta
                (Dispatch.getEpochOut conn) (TLS.getOutStream conn)
                (length, length) bytes
        in
            match TLS.write conn ((length, length), delta) with
            | TLS.WriteError _ ->
                unbind_fd fd; EI_WRITEERROR
            | TLS.WriteComplete conn ->
                let _ = update_fd_connection fd conn in
                    length
            | TLS.WritePartial (conn, (r, m)) ->
                let _ = update_fd_connection fd conn in
                let rem =
                    DataStream.deltaRepr
                        (Dispatch.getEpochOut conn) (TLS.getOutStream conn) r m
                in
                    (length - (Bytes.length rem))
            | TLS.MustRead conn ->
                let _ = update_fd_connection fd conn in
                    EI_MUSTREAD

(* ------------------------------------------------------------------------ *)
let shutdown (fd : fd) : unit =
    match connection_of_fd fd with
    | None -> ()
    | Some conn ->
        let _ = TLS.full_shutdown conn in
            unbind_fd fd

(* ------------------------------------------------------------------------ *)
let connect (rawfd : rawfd) (config : config) : fd =
    let conn = TLS.connect rawfd config in
        new_fd conn

(* ------------------------------------------------------------------------ *)
let accept_connected (rawfd : rawfd) (config :config) : fd =
    let conn = TLS.accept_connected rawfd config in
        new_fd conn
