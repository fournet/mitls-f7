module TLSPlain

open Error_handling
open Algorithms
open HS_ciphersuites
open Formats
open TLSInfo
open Data

type Lengths = {tlens: int list}

let max_TLSPlaintext_fragment_length = 1<<<14 (* just a reminder *)
let fragmentLength = max_TLSPlaintext_fragment_length (* 1 *)

(* No way the following will typecheck. I use native byte/int conversions *)
let compute_padlen ki len =
    let alg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
    let bs = blockSize alg in
    let len_no_pad = len + 1 in (* 1 byte for the padlen byte *)
    let min_padlen =
        let overflow = len_no_pad % bs in
        if overflow = 0 then
            overflow
        else
            bs - overflow
    (* Always use fixed padding size *)
    min_padlen
    (*
    match ki.sinfo.protocol_version with
    | ProtocolVersionType.SSL_3p0 ->
        (* At most one bs. See sec 5.2.3.2 of SSL 3 draft *)
        min_padlen
    | v when v >= ProtocolVersionType.TLS_1p0 ->
        let rand = bs * (((int (OtherCrypto.mkRandom 1).[0]) - min_padlen) / bs) in 
        min_padlen + rand
    | _ -> unexpectedError "[compute_pad] invoked on wrong protocol version"
    *)

let computeAddedLen ki len =
    let cs = ki.sinfo.cipher_suite in
    match cs with
    | x when isNullCipherSuite x ->
        0
    | x when isOnlyMACCipherSuite x ->
        macLength (macAlg_of_ciphersuite cs)
    | _ -> (* GCM or MtE
                TODO: add support for GCM, now we only support MtE *)
        let macLen = macLength (macAlg_of_ciphersuite cs) in
        let padLen = compute_padlen ki (len + macLen) in
        macLen + padLen + 1

let estimateLengths ki len =
    (* Basic implementation: split at fragment length, then add some constant amount for mac and pad; last fragment treated specially.
       Even if protocol version would allow, when chosing target ciphertext length we consider a constant fixed length for padding.
       Maybe when getting a fragment given a target chipher length, we might get a random shorter fragment so as to exploit padding. *)
    let nfrag = len / fragmentLength in
    let res =
        if nfrag > 0 then
            let addedLen = computeAddedLen ki fragmentLength in          
            List.init nfrag (fun idx -> (fragmentLength + addedLen))
        else
            List.empty
    let rem = len % fragmentLength in
    if rem = 0 then
        {tlens = res}
    else
        let addedLen = computeAddedLen ki rem in
        {tlens = res @ [ rem + addedLen ] }

type appdata = {bytes: bytes}

let appdata (ki:KeyInfo) (lens:Lengths) data = {bytes = data}

type fragment = {bytes: bytes}

let concat_fragment_appdata (ki:KeyInfo) (tlen:int) data (lens:Lengths) (appdata:appdata) :appdata =
    let resData = data.bytes @| appdata.bytes in
    {bytes = resData}

let app_fragment (ki:KeyInfo) lens (appdata:appdata) : ((int * fragment) * (Lengths * appdata)) =
    (* FIXME: given the cipertext target length, we should get a *smaller* plaintext fragment
       (so that MAC and padding can be added back).
       Right now, we *wrongly* return a fragment which is as big as the target lenght *)
    match lens.tlens with
    | thisLen::remLens ->
        (* The following split must be replace, fixed *)
        let (thisData,remData) = split appdata.bytes thisLen in
        ((thisLen,{bytes = thisData}), ({tlens = remLens},{bytes = remData}))
    | [] -> ((0,{bytes = [||]}),(lens,appdata))

let pub_fragment (ki:KeyInfo) (data:bytes) : ((int * fragment) * bytes) = (* TODO, which target size should we stick to? *)
    unexpectedError "[TODO] not implemented yet"

type mac = {bytes: bytes}
type plain = {bytes: bytes}

let concat_fragment_mac_pad (ki:KeyInfo) tlen (data:fragment) (mac:mac) =
    let step1 = data.bytes @| mac.bytes in
    let padlen = tlen - (Bytearray.length step1) - 1 in (* -1 for the byte containing pad len *)
    let pad = Array.create (padlen + 1) (byte padlen) in
    {bytes = step1 @| pad}

let split_mac (ki:KeyInfo) (plainLen:int) (plain:plain) : (fragment * mac) =
    (* TODO: copy/paste code that parses plaintext immediately after decryption in MtE *)
    unexpectedError "[TODO] not implemented yet"