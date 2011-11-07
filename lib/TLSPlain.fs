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
       Maybe when getting a fragment given a target chipher length, we might get a random shorter fragment so as to exploit padding.
       Note: if compression is enabled, we should come out with fragment sizes that are compatible with compressed app data.
       The estimation is quite hard to do, as it depends on app data entropy, and not only their length. *)
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
    (* TODO: If ki says so, first decompress data, then append it *)
    (* FIXME: should we append (decompressed) data at the bottom of appadata? *)
    let resData = data.bytes @| appdata.bytes in
    {bytes = resData}

let fragmentSize (ki:KeyInfo) (tlen:int) =
    (* Reverse of estimateLengths: return the size of the plaintext fragment to be extracted from appdata.
       Right now we ignore compression. Shall we take it into account now or later? Probably later. *)
    let cs = ki.sinfo.cipher_suite in
    match cs with
    | x when isNullCipherSuite x ->
        (* No Padding, No MAC *)
        tlen
    | x when isOnlyMACCipherSuite x ->
        (* Only MAC, subtract it *)
        let macLen = macLength (macAlg_of_ciphersuite cs) in
        tlen - macLen
    | _ ->
        (* Only valid for MtE; GCM is not taken into account yet *)
        let macLen = macLength (macAlg_of_ciphersuite cs) in
        let bs = blockSize (encAlg_of_ciphersuite cs) in
        tlen - (macLen + 1 + bs) // probably not always working (especially with SSL 3.0, but mostly working

let app_fragment (ki:KeyInfo) lens (appdata:appdata) : ((int * fragment) * (Lengths * appdata)) =
    (* Given the cipertext target length, we get a *smaller* plaintext fragment
       (so that MAC and padding can be added back).
       TODO: we should also perform compression *now*. After we extract the next fragment from appdata, we compress it
       and only after we return it. The target length will be compatible with the compressed length, because the
       estimateLengths function takes compression into account. *)
    match lens.tlens with
    | thisLen::remLens ->
        let flen = fragmentSize ki thisLen in
        let (thisData,remData) = split appdata.bytes flen in
        (* TODO: apply compression on thisData *)
        ((thisLen,{bytes = thisData}), ({tlens = remLens},{bytes = remData}))
    | [] -> ((0,{bytes = [||]}),(lens,appdata))

let pub_fragment (ki:KeyInfo) (data:bytes) : ((int * fragment) * bytes) = (* TODO, which target size should we stick to? *)
    unexpectedError "[TODO] not implemented yet"

type mac = MACt of MAC.mac

type add_data = bytes
type mac_plain = MACPLAINt of MAC.mac_plain

let ad_fragment (ki:KeyInfo) (ad:add_data) (frag:fragment) =
    let plainLen = Bytearray.bytes_of_int 2 (Bytearray.length frag.bytes) in
    let fullData = ad @| plainLen in 
    MACPLAINt (fullData @| frag.bytes)

type plain = {bytes: bytes}

let concat_fragment_mac_pad (ki:KeyInfo) tlen (data:fragment) (MACt(mac):mac) =
    let step1 = data.bytes @| mac in
    let padlen = tlen - (Bytearray.length step1) - 1 in (* -1 for the byte containing pad len *)
    let pad = Array.create (padlen + 1) (byte padlen) in
    {bytes = step1 @| pad}

let split_mac (ki:KeyInfo) (plainLen:int) (plain:plain) : (bool * (fragment * mac)) =
    let macSize = macLength (macAlg_of_ciphersuite ki.sinfo.cipher_suite) in
    let (tmpdata, padlenb) = split plain.bytes (plainLen - 1) in
    let padlen = int padlenb.[0] in
    let padstart = plainLen - padlen - 1 in
    if padstart < 0 then
        (* Pretend we have a valid padding of length zero, but set we must fail *)
        let macStart = plainLen - macSize - 1 in
        let (frag,mac) = split tmpdata macStart in
        (true,({bytes=frag},MACt(mac)))
        (*
        (* Evidently padding has been corrupted, or has been incorrectly generated *)
        (* in TLS1.0 we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
        match ki.sinfo.protocol_version with
        | v when v >= ProtocolVersionType.TLS_1p1 ->
            (* Pretend we have a valid padding of length zero, but set we must fail *)
            correct(data,true)
        | v when v = ProtocolVersionType.SSL_3p0 || v = ProtocolVersionType.TLS_1p0 ->
            (* in TLS1.0/SSL we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
            Error (RecordPadding,CheckFailed)
        | _ -> unexpectedError "[check_padding] wrong protocol version"
        *)
    else
        let (data_no_pad,pad) = split tmpdata padstart in
        match ki.sinfo.protocol_version with
        | v when v = ProtocolVersionType.TLS_1p0 || v = ProtocolVersionType.TLS_1p1 || v = ProtocolVersionType.TLS_1p2 ->
            let expected = Array.create padlen (byte padlen) in
            if equalBytes expected pad then
                let macStart = plainLen - macSize - padlen - 1 in
                let (frag,mac) = split data_no_pad macStart in
                (false,({bytes=frag},MACt(mac)))
            else
                (* Pretend we have a valid padding of length zero, but set we must fail *)
                let macStart = plainLen - macSize - 1 in
                let (frag,mac) = split tmpdata macStart in
                (true,({bytes=frag},MACt(mac)))
                (*
                (* in TLS1.0 we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
                if  v = ProtocolVersionType.TLS_1p0 then
                    Error (RecordPadding,CheckFailed)
                else
                    (* Pretend we have a valid padding of length zero, but set we must fail *)
                    correct (data,true)
                *)
        | ProtocolVersionType.SSL_3p0 ->
            (* Padding is random in SSL_3p0, no check to be done on its content.
               However, its length should be at most one bs
               (See sec 5.2.3.2 of SSL 3 draft). Enforce this check (which
               is performed by openssl, and not by wireshark for example). *)
            let encAlg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
            let bs = blockSize encAlg in
            if padlen >= bs then
                (* Pretend we have a valid padding of length zero, but set we must fail *)
                let macStart = plainLen - macSize - 1 in
                let (frag,mac) = split tmpdata macStart in
                (true,({bytes=frag},MACt(mac)))
                (*
                (* Insecurely report the error. Only TLS 1.1 and above should
                   be secure with this respect *)
                Error (RecordPadding,CheckFailed)
                *)
            else
                let macStart = plainLen - macSize - padlen - 1 in
                let (frag,mac) = split data_no_pad macStart in
                (false,({bytes=frag},MACt(mac)))
        | _ -> unexpectedError "[check_padding] wrong protocol version"

(* Only for MACOnlyCipherSuites *)
let fragment_mac_to_cipher (ki:KeyInfo) (n:int) (f:fragment) (MACt(m):mac) = (* TODO: check lengths are ok *)
    f.bytes @| m
let cipher_to_fragment_mac (ki:KeyInfo) (n:int) (c:bytes) : fragment * mac = (* TODO: check lengths are ok *)
    let cs = ki.sinfo.cipher_suite in
    let maclen = Algorithms.macLength (macAlg_of_ciphersuite cs) in
    let macStart = (Bytearray.length c) - maclen
    if macStart < 0 then
        (* FIXME: is this safe?
           I (AP) think so because our locally computed mac will have some different length.
           Also timing is not an issue, because the attacker can guess the check should fail anyway. *)
        ({bytes = c},MACt([||]))
    else
        let (frag,mac) = split c macStart in
        ({bytes = frag},MACt(mac))
(* Olny for NullCipherSuites *)
let fragment_to_cipher (ki:KeyInfo) (n:int) (f:fragment) = (* TODO: check lengths are ok *)
    f.bytes
let cipher_to_fragment (ki:KeyInfo) (n:int) (c:bytes) : fragment = (* TODO: check lengths are ok *)
    {bytes = c}

(* Only to be used by trusted crypto libraries MAC, ENC *)
let mac_plain_to_bytes (MACPLAINt(mplain):mac_plain) = mplain

let mac_to_bytes (MACt(mac):mac) = mac
let bytes_to_mac b : mac = MACt(b)

let plain_to_bytes (plain:plain) = plain.bytes
let bytes_to_plain b :plain = {bytes = b}