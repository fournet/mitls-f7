module MiHTTPData

open Bytes
open Range
open TLSInfo
open DataStream

type document =
| PartialStatus   of cbytes
| PartialHeaders  of (cbytes * cbytes) list * cbytes
| PartialDocument of (cbytes * cbytes) list * (int * cbytes)
| Document        of (cbytes * cbytes) list * cbytes
| Invalid

type cdocument = (cbytes * cbytes) list * cbytes

let bempty : cbytes = [||]
let bget (c : cbytes) (i : int) = c.[i]
let blength (c : cbytes) = Array.length c
let bsub (c : cbytes) i j = Array.sub c i j
let bjoin (c1 : cbytes) (c2 : cbytes) = (Array.append c1 c2 : cbytes)

let LF = 0x10uy
let CR = 0x13uy

let rec find_crlf (i : int) (x : cbytes) =
    if i >= blength(x) then None else
    if bget x i = LF then Some (i, 1) else
    if bget x i = CR then
        if i+1 >= blength(x) then None else
        if bget x i = LF then Some (i, 2) else Some (i, 1)
    else
        None

let pull_line (x : cbytes) =
    match find_crlf 0 x with
    | None -> None
    | Some (i, j) -> Some (bsub x 0 i, bsub x (i+j) (blength x))

let get_contents_length (headers : (cbytes * cbytes) list) =
    (None : int option)

let split_header (header : cbytes) =
    (None : (cbytes * cbytes) option)

let create () : document =
    PartialStatus bempty

let progress1 (d : document) (x : cbytes) =
    if blength x > 0 then
        match d with
        | Invalid -> Some (Invalid, bempty)
        | Document _ -> Some (Invalid, bempty)

        | PartialStatus status ->
            match pull_line x with
            | None -> Some (PartialStatus (bjoin status x), bempty)
            | Some (_, x) -> Some (PartialHeaders ([], bempty), x)

        | PartialHeaders (headers, data) ->
            match pull_line x with
            | None -> Some (PartialHeaders (headers, bjoin data x), bempty)
            | Some (l, x) ->
                if   blength l = 0
                then match get_contents_length headers with
                     | None    -> Some (Invalid, bempty)
                     | Some cl -> Some (PartialDocument (headers, (cl, bempty)), x)
                else match split_header (bjoin data l) with
                     | None        -> Some (Invalid, bempty)
                     | Some (k, v) -> Some (PartialHeaders  ((k, v) :: headers, bempty), x)

        | PartialDocument (headers, (len, data)) ->
            if   len - blength data < blength x
            then Some (Invalid, bempty)
            else if   len - blength data = blength x
                 then Some (Document (headers, bjoin data x), bempty)
                 else Some (PartialDocument (headers, (len, bjoin data x)), bempty)
    else
        None

let rec progress (d : document) (x : cbytes) =
    fprintfn stderr "%s\n" (Bytes.iutf8 (abytes x))
    match progress1 d x with
    | None -> if blength x > 0 then Invalid else d
    | Some (d, x) -> progress d x

let finalize (d : document) =
    match d with
    | Document (hd, d) -> Some (hd, d)
    | _ -> None

let push_delta (e : epoch) (s : stream) (r : range) (x : delta) (d : document) =
    progress d (cbytes (deltaBytes e s r x))

let request (e : epoch) (s : stream) ((r1, r2) : range) (x : string) =
    let request = sprintf "GET %s HTTP/1.0\r\n\r\n" x in
    let request = utf8 request in
    if x.Length < r1 || x.Length > r2 then
        Error.unexpected "invalid range"
    else
        DataStream.createDelta e s (r1, r2) request
