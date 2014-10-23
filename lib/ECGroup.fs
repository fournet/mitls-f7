#light "off"

module ECGroup

open Bytes
open CoreKeys
open Error
open TLSError
open TLSConstants

type ec_curve =
| ECC_P256
| ECC_P384
| ECC_P521
| ECC_EXPLICIT_PRIME
| ECC_EXPLICIT_BINARY
| ECC_UNKNOWN of int

type point_format =
| ECP_UNCOMPRESSED
| ECP_UNKNOWN of int

type point = ecpoint

let getParams c : ecdhparams =
    match c with
    | ECC_P256 -> { curve_name = "secp256r1"; }
    | ECC_P384 -> { curve_name = "secp384r1"; }
    | ECC_P521 -> { curve_name = "secp521r1"; }
    | _ -> failwith "(impossible)"

let curve_id (p:ecdhparams) : bytes =
    match p.curve_name with
    | "secp256r1" -> abyte2 (0uy, 23uy)
    | "secp384r1" -> abyte2 (0uy, 24uy)
    | "secp521r1" -> abyte2 (0uy, 25uy)
    | _ -> failwith "(impossible)"

(* ADL: Stub for supporting more point format options *)
let serialize_point (p:ecdhparams) (e:point) =
    vlbytes 1 (CoreECDH.serialize e)

let parse_point (p:ecdhparams) (b:bytes) : point option =
    let clen = match p.curve_name with
    | "secp256r1" -> 32
    | "secp384r1" -> 48
    | "secp521r1" -> 66
    | _ -> failwith "(impossible)" in
    if length b = 2*clen + 1 then
        let (et, r) = split b 1 in
        match cbyte et with
        | 4uy ->
            let (a,b) = split r clen in
            let e = {ecx = a; ecy = b;} in
            if CoreECDH.is_on_curve p e then Some e else None
        |_ -> None
    else
        None