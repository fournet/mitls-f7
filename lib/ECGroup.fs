#light "off"

module ECGroup

open Bytes
open CoreKeys
open Error
open TLSError

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