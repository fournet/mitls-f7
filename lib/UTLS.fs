module UTLS

open Bytes
open Error
open Dispatch

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

type handleinfo = {
    conn     : Connection;
    queryidx : int;
    queries  : (int * query) list;
}

let handleinfo_of_conn = fun c ->
    { conn = c; queryidx = 0; queries = []; }

let fds = ref ([] : (fd * handleinfo) list)

(* ------------------------------------------------------------------------ *)
let new_fd = fun conn ->
    let fd : fd = 1 + (List.max (List.map (fun (x, _) -> x) !fds)) in
        fds := (fd, handleinfo_of_conn conn) :: !fds;
        fd

let apply_to_handle = fun fd f ->
    let rec doit = fun fds ->
        match fds with
        | [] -> ([], None)
        | (i, c) :: fds ->
            if fd = i then
                let c, r = f c in ((i, c) :: fds, Some r)
            else
                let (fds, r) = doit fds in ((i, c) :: fds, r)
    in
        let (newfds, r) = doit !fds in
            fds := newfds; r

let connection_of_fd = fun fd ->
    apply_to_handle fd (fun c -> (c, c.conn))

let update_fd_connection = fun fd conn ->
    apply_to_handle fd (fun c -> ({c with conn = conn}, ()))

let unbind_fd = fun fd ->
    fds := List.filter (fun (i, c) -> i = fd) !fds

let add_query_cert = fun fd query ->
    apply_to_handle fd (fun c ->
        let idx = c.queryidx in
            ({ c with
                    queryidx = c.queryidx + 1;
                    queries  = (idx, query) :: c.queries }, idx))

let get_query_cert = fun fd idx ->
    apply_to_handle fd (fun c ->
        let (theq, othq) = List.partition (fun (qi, q) -> qi = idx) c.queries in
        let q =
            match theq with
            | []          -> None
            | (_, q) :: _ -> Some q
        in
            (c, q))

let pop_query_cert = fun fd idx ->
    apply_to_handle fd (fun c ->
        let (theq, othq) =
            List.partition (fun (qi, q) -> qi = idx) c.queries in
            ({ c with queries = othq }, theq))

(* ------------------------------------------------------------------------ *)
let get_query = fun fd idx ->
    match get_query_cert fd idx with
    | None          -> (EI_BADHANDLE , [||])
    | Some None     -> (EI_BADCERTIDX, [||])
    | Some (Some q) -> (0, Certificate.certificateBytes q)

let read = fun fd ->
    match connection_of_fd fd with
    | None -> (EI_BADHANDLE, [||])

    | Some c ->
        match TLS.read c with
        | TLS.ReadError e ->
            (EI_READERROR, [||])

        | TLS.Close _ ->
            unbind_fd fd
            (EI_CLOSE, [||])

        | TLS.Fatal e ->
            unbind_fd fd
            (EI_FATAL, Alert.alertBytes e)

        | TLS.Warning (conn, e) ->
            ignore (update_fd_connection fd conn)
            (EI_WARNING, Alert.alertBytes e)

        | TLS.CertQuery (conn, q) ->
            match add_query_cert fd q with
            | None -> (EI_BADHANDLE, [||])
            | Some idx ->
                ignore (update_fd_connection fd conn);
                (EI_CERTQUERY, Bytes.bytes_of_int 4 idx)

        | TLS.Handshaken conn ->
            ignore (update_fd_connection fd conn)
            (EI_HANDSHAKEN, [||])

        | TLS.Read (conn, (rg, m)) ->
            let plain =
                DataStream.deltaRepr
                    (Dispatch.getEpochIn conn) (TLS.getInStream conn) rg m
            in
                ignore (update_fd_connection fd conn);
                (Bytes.length plain, plain)

        | TLS.DontWrite conn ->
            ignore (update_fd_connection fd conn)
            (EI_DONTWRITE, [||])

let write = fun fd bytes ->
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
            | TLS.WriteError e ->
                unbind_fd fd; EI_WRITEERROR
            | TLS.WriteComplete conn ->
                ignore (update_fd_connection fd conn);
                length
            | TLS.WritePartial (conn, (r, m)) ->
                ignore (update_fd_connection fd conn);
                let rem =
                    DataStream.deltaRepr
                        (Dispatch.getEpochOut conn) (TLS.getOutStream conn) r m
                in
                    (length - (Bytes.length rem))
            | TLS.MustRead conn ->
                ignore (update_fd_connection fd conn);
                EI_MUSTREAD

let shutdown = fun fd ->
    match connection_of_fd fd with
    | None -> ()
    | Some conn ->
        ignore (TLS.shutdown conn);
        unbind_fd fd

let authorize = fun fd idx ->
    match connection_of_fd fd with
    | None -> EI_BADHANDLE
    | Some conn ->
        match pop_query_cert fd idx with
        | None               -> EI_BADHANDLE
        | Some []            -> EI_BADCERTIDX
        | Some ((_, q) :: _) ->
            let conn = TLS.authorize conn q in
                ignore (update_fd_connection fd conn);
                0

let refuse = fun fd idx ->
    match connection_of_fd fd with
    | None -> EI_BADHANDLE
    | Some conn ->
        match pop_query_cert fd idx with
        | None               -> EI_BADHANDLE
        | Some []            -> EI_BADCERTIDX
        | Some ((_, q) :: _) ->
            let conn = TLS.authorize conn q in
                ignore (update_fd_connection fd conn);
                0

let rehandshake = fun fd config ->
    match connection_of_fd fd with
    | None -> EI_BADHANDLE
    | Some conn ->
        let conn = TLS.rehandshake conn config in
            ignore (update_fd_connection fd conn);
            0

let rekey = fun fd config ->
    match connection_of_fd fd with
    | None -> EI_BADHANDLE
    | Some conn ->
        let conn = TLS.rekey conn config in
            ignore (update_fd_connection fd conn);
            0

let request = fun fd config ->
    match connection_of_fd fd with
    | None -> EI_BADHANDLE
    | Some conn ->
        let conn = TLS.request conn config in
            ignore (update_fd_connection fd conn);
            0

let connect = fun rawfd config ->
    let conn = TLS.connect rawfd config in
        new_fd conn

let accept_connected = fun rawfd config ->
    let conn = TLS.accept_connected rawfd config in
        new_fd conn

let resume = fun rawfd sid config ->
    match TLS.resume rawfd sid config with
    | Error   _    -> -1
    | Correct conn ->  new_fd conn
