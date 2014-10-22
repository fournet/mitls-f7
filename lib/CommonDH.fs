module CommonDH

open Bytes
open TLSConstants
open CoreKeys

type element = {
 dhe_p : DHGroup.elt option;
 dhe_ec : ECGroup.point option;
}

let dhe_nil = {
 dhe_p = None;
 dhe_ec = None;
}

type secret = Key of bytes

type parameters =
| DHP_P of dhparams
| DHP_EC of ecdhparams

exception Invalid_DH

let get_p (e:element) =
    match e with
    | {dhe_p = Some x; dhe_ec = None; } -> x
    | _ -> raise Invalid_DH

let get_ec (e:element) =
    match e with
    | {dhe_p = None; dhe_ec = Some x; } -> x
    | _ -> raise Invalid_DH

let serializeKX (p:parameters) (e:element) : bytes =
    match p with
    | DHP_P(dhp) -> (vlbytes 2 dhp.dhp) @| (vlbytes 2 dhp.dhg) @| (vlbytes 2 (get_p e))
    | DHP_EC(ecp) -> abyte 0uy

let checkElement (p:parameters) (e:element) : element option =
    match p with
    | DHP_P(dhp) ->
        match DHGroup.checkElement dhp (get_p e) with
        | None -> None
        | Some x -> Some {dhe_nil with dhe_p = Some x}
    | DHP_EC(ecp) -> None