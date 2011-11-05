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

// We need a typable version; not so hard (but we may need axioms on arrays)
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

let fragmentSize (ki:KeyInfo) (lens:Lengths) (appdataLen:int) =
    (* TODO: The following should be implemented here:
       - Take the first item in lens (length of the next ciphertext)
       - From this value, compute the (smaller) size of the next plaintext
       - Return the latter *)
    appdataLen

let app_fragment (ki:KeyInfo) lens (appdata:appdata) : ((int * fragment) * (Lengths * appdata)) =
    (* FIXME: given the cipertext target length, we should get a *smaller* plaintext fragment
       (so that MAC and padding can be added back). In fact, we want to call "fragmentSize" inside this function.
       Right now, we *wrongly* return a fragment which is as big as the target lenght.
       Moreover, we should also perform compression *now*. After we extract the next fragment from appdata, we compress it
       and only after we return it. The target length will be compatible with the compressed length, because the
       estimateLengths function takes compression into account. *)
    match lens.tlens with
    | thisLen::remLens ->
        (* The following split must be replace, fixed *)
        let (thisData,remData) = split appdata.bytes thisLen in
        ((thisLen,{bytes = thisData}), ({tlens = remLens},{bytes = remData}))
    | [] -> ((0,{bytes = [||]}),(lens,appdata))

let pub_fragment (ki:KeyInfo) (data:bytes) : ((int * fragment) * bytes) = (* TODO, which target size should we stick to? *)
    unexpectedError "[TODO] not implemented yet"

type mac = {bytes: bytes}

type add_data = bytes
type mac_plain = {bytes: bytes}

let ad_fragment (ki:KeyInfo) (ad:add_data) (frag:fragment) =
    let plainLen = Bytearray.bytes_of_int 2 (Bytearray.length frag.bytes) in
    let fullData = ad @| plainLen in 
    {bytes = fullData @| frag.bytes}

type plain = {bytes: bytes}

let concat_fragment_mac_pad (ki:KeyInfo) tlen (data:fragment) (mac:mac) =
    let step1 = data.bytes @| mac.bytes in
    let padlen = tlen - (Bytearray.length step1) - 1 in (* -1 for the byte containing pad len *)
    let pad = Array.create (padlen + 1) (byte padlen) in
    {bytes = step1 @| pad}

let split_mac (ki:KeyInfo) (plainLen:int) (plain:plain) : (fragment * mac) =
    (* TODO: copy/paste code that parses plaintext immediately after decryption in MtE *)
    unexpectedError "[TODO] not implemented yet"

(* Only for MACOnlyCipherSuites *)
let fragment_mac_to_cipher (ki:KeyInfo) (n:int) (f:fragment) (m:mac) = (* TODO: check lengths are ok *)
    f.bytes @| m.bytes
let cipher_to_fragment_mac (ki:KeyInfo) (n:int) (c:bytes) : fragment * mac = (* TODO: check lengths are ok *)
    let cs = ki.sinfo.cipher_suite in
    let maclen = Algorithms.macLength (macAlg_of_ciphersuite cs) in
    let macStart = (Bytearray.length c) - maclen
    if macStart < 0 then
        (* FIXME: is this safe?
           I (AP) think so because our locally computed mac will have some different length.
           Also timing is not an issue, because the attacker can guess the check should fail anyway. *)
        ({bytes = c},{bytes = [||]})
    else
        let (frag,mac) = split c macStart in
        ({bytes = frag},{bytes = mac})
(* Olny for NullCipherSuites *)
let fragment_to_cipher (ki:KeyInfo) (n:int) (f:fragment) = (* TODO: check lengths are ok *)
    f.bytes
let cipher_to_fragment (ki:KeyInfo) (n:int) (c:bytes) : fragment = (* TODO: check lengths are ok *)
    {bytes = c}

(* Only to be used by trusted crypto libraries MAC, ENC *)
let mac_plain_to_bytes (mplain:mac_plain) = mplain.bytes

let mac_to_bytes (mac:mac) = mac.bytes
let bytes_to_mac b : mac = {bytes = b}

let plain_to_bytes (plain:plain) = plain.bytes
let bytes_to_plain b :plain = {bytes = b}