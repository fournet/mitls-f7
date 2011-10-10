module TLSCrypto

open Error_handling
open StdCrypto
open Formats

let MAC pv alg key data =
    match pv with
    | ProtocolVersionType.SSL_3p0 -> sslKeyedHash alg key data
    | x when x >= ProtocolVersionType.TLS_1p0 -> hmac alg key data
    | _ -> Error(MAC, Unsupported)