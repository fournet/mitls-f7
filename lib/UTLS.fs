
module UTLS

open Error
open Dispatch

type rawfd = int
type fd = int

type ioresult_i =
    | ReadError  of ioerror
    | Close
    | Fatal      of alertDescription
    | Warning    of alertDescription 
    | CertQuery  of query
    | Handshaken
    | Read       of int * int
    | DontWrite
    
type ioresult_o =
    | WriteError    of ioerror
    | WriteComplete
    | WritePartial  of int * int
    | MustRead

let fds = ref ([] : (int * Connection) list)

let get_conn = fun fd ->
    let rec doit = fun fds ->
        match fds with
        | [] -> None
        | (i, c) :: fds ->
            if fd = i then Some c else doit fds
    in
        doit !fds

let set_conn = fun fd conn ->
    let rec doit = fun fds ->
        match fds with
        | [] -> [(fd, conn)]
        | (i, c) :: fds ->
            if fd = i then (fd, conn) :: fds else (i, c) :: (doit fds)
    in
        fds := doit !fds

let rem_conn = fun fd ->
    let rec doit = fun fds ->
        match fds with
        | [] -> []
        | (i, c) :: fds ->
            if fd = i then doit fds else (i, c) :: (doit fds)
    in
        fds := doit !fds

let read = fun fd ->
    match get_conn fd with
    | None -> None
    | Some conn ->
        match TLS.read conn with
        | TLS.ReadError e -> Some (ReadError e)
        | TLS.Close _ ->
            rem_conn fd;
            Some Close
        | TLS.Fatal e -> Some (Fatal e)
        | TLS.Warning (conn, e) ->
            set_conn fd conn;
            Some (Warning e)
        | TLS.CertQuery (conn, q) ->
            set_conn fd conn;
            Some (CertQuery q)
        | TLS.Handshaken conn ->
            set_conn fd conn;
            Some Handshaken
        | TLS.Read (conn, (rg, m)) ->
            set_conn fd conn;
            Some (Read rg) (* FIXME *)
        | TLS.DontWrite conn ->
            set_conn fd conn;
            Some DontWrite

let shutdown = fun fd ->
    match get_conn fd with
    | None -> ()
    | Some conn ->
        ignore (TLS.shutdown conn);
        rem_conn fd