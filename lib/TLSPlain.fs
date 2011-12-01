module TLSPlain

open Error
open Algorithms
open CipherSuites
open Formats
open TLSInfo
open Bytes

/// Relating lengths of fragment plaintexts and ciphertexts

type Lengths = {tlens: int list}

let max_TLSPlaintext_fragment_length = 1<<<14 (* just a reminder *)
let fragmentLength = max_TLSPlaintext_fragment_length (* 1 *)

// We need a typable version; not so hard (but we may need axioms on arrays)
//CF patched so that padlen includes its length byte.
// the spec is that 
// len + padLength % bs = 0 /\ padLength in 1..256
let padLength sinfo len =
    let alg = encAlg_of_ciphersuite sinfo.cipher_suite in
    let bs = blockSize alg in
    let overflow = (len + 1) % bs // at least one extra byte of padding
    if overflow = 0 then 1 else 1 + bs - overflow 
    (* Always use fixed padding size *)
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

let extraLength sinfo len =
    let cs = sinfo.cipher_suite in
    match cs with
    | x when isNullCipherSuite x    -> 0
    | x when isOnlyMACCipherSuite x -> macSize (macAlg_of_ciphersuite cs)
    | _ -> (* GCM or MtE
                TODO: add support for GCM, now we only support MtE *)
        let macLen = macSize (macAlg_of_ciphersuite cs) in
        let padLen = padLength sinfo (len + macLen) in
        macLen + padLen

(*
// as a total function
let cipherLength sinfo len =
    len + 
    let cs = sinfo.cipher_suite in
    if isNullCipherSuite cs then 0 else 
        let macLen = macLength (macAlg_of_ciphersuite cs) in
        macLen + 
        if isOnlyMACCipherSuite cs then 0 else padLength sinfo (len + macLen) 
        // TODO: add support for GCM, now we only support MtE
*)

let estimateLengths sinfo len =
    (* Basic implementation: split at fragment length, then add some constant amount for mac and pad; last fragment treated specially.
       Even if protocol version would allow, when choosing target ciphertext length we consider a constant fixed length for padding.
       Maybe when getting a fragment given a target chipher length, we might get a random shorter fragment so as to exploit padding.
       Note: if compression is enabled, we should come out with fragment sizes that are compatible with compressed app data.
       The estimation is quite hard to do, as it depends on app data entropy, and not only their length. *)
    let nfrag = len / fragmentLength in
    let rem = len % fragmentLength in
    let res =
        if nfrag > 0 then
            let addedLen = extraLength sinfo fragmentLength in          
            List.init nfrag (fun idx -> (fragmentLength + addedLen))
        else
            List.empty
    if rem = 0 then
        {tlens = res}
    else
        let addedLen = extraLength sinfo rem in
        {tlens = res @ [ rem + addedLen ] }

(*
//CF idem but probably easier to typecheck 
let rec Lengths sinfo len =
    if len > fragmentLength then 
      cipherLength sinfo fragmentLength :: 
      Lengths sinfo (len - fragmentLength) 
    else 
      [cipherLength sinfo len]
*)

/// Application Data

type appdata = {bytes: bytes}

let appdata (si:SessionInfo) (lens:Lengths) data = {bytes = data}
let empty_appdata = {bytes = [||]}
let empty_lengths = {tlens = []}
let is_empty_appdata data = data.bytes = [||]

type fragment = {bytes: bytes}

let concat_fragment_appdata (si:SessionInfo) (tlen:int) data (lens:Lengths) (appdata:appdata) :(Lengths * appdata) =
    (* TODO: If ki says so, first decompress data, then append it *)
    let resData = appdata.bytes @| data.bytes in
    let resData:appdata = {bytes = resData} in
    let resLengths = lens.tlens @ [tlen] in
    let resLengths = {tlens = resLengths} in
    (resLengths,resData)

let app_fragment (si:SessionInfo) lens (appdata:appdata) : ((int * fragment) * (Lengths * appdata)) =
    (* The idea is: Given the cipertext target length, we get a *smaller* plaintext fragment
       (so that MAC and padding can be added back).
       In practice: since estimateLengths acts deterministically on the appdata length, we do the same here, and
       we rely on the fact that the implementation here is the same in estimateLenghts, so that our fragment size is
       always aligned with the estimated ones.
       TODO: we should also perform compression *now*. After we extract the next fragment from appdata, we compress it
       and only after we return it. The target length will be compatible with the compressed length, because the
       estimateLengths function takes compression into account. *)
    match lens.tlens with
    | thisLen::remLens ->
        (* Same implementation as estimateLengths, but one fragment at a time *)
        if length appdata.bytes > fragmentLength then
            (* get one full fragment of appdata *)
            (* TODO: apply compression on thisData *)
            let (thisData,remData) = split appdata.bytes fragmentLength in
            ((thisLen,{bytes = thisData}),({tlens = remLens},{bytes = remData}))
        else
            (* consume all the remaining appdata. assert remLens is the empty list *)
            ((thisLen,{bytes = appdata.bytes}), ({tlens = remLens},{bytes = [||]}))
    | [] -> ((0,{bytes = [||]}),(lens,appdata))

let get_bytes (appdata:appdata) = appdata.bytes

let pub_fragment (si:SessionInfo) (data:bytes) : ((int * fragment) * bytes) =
    let (frag,rem) =
        if length data > fragmentLength then
            split data fragmentLength
        else
            (data,[||])
    let addedLen = extraLength si (length frag) in
    let totlen = (length frag) + addedLen in
    ((totlen,{bytes = frag}),rem)

let pub_fragment_to_bytes (si:SessionInfo) (tlen:int) (fragment:fragment) = fragment.bytes

type mac = MACt of MAC.mac

type add_data = bytes
type mac_plain = MACPLAINt of MAC.mac_plain

let ad_fragment (ki:KeyInfo) (ad:add_data) (frag:fragment) =
    let plainLen = bytes_of_int 2 (length frag.bytes) in
    let fullData = ad @| plainLen in 
    MACPLAINt (fullData @| frag.bytes)

type plain = {bytes: bytes}

let pad (p:int)  = Array.create p (byte (p-1))
(* val pad (p:int) { 1 <= p /\ p <= 256 } -> b:bytes { b = Pad(p) } *)

(* this is the Encode function of MAC-then-Encode-then-Encrypt;
   in contrast with Paterson et al, typing prevents any runtime error. *)

let concat_fragment_mac_pad (ki:KeyInfo) cipherlen (data:fragment) (MACt(mac):mac) =
    let p = cipherlen - length data.bytes - length mac  
    {bytes = data.bytes @| mac @| pad p}

(* this is the Decode function of Mac-then-Encode-then-Encrypt,
   somehow an inverse of the function above;
   plainLen is just length plain, right? cloned & rewritten, to be discussed
   AP: Yes indeed, plainLen is length plain, but explicitly put as an argument,
   to be able to easily index the returned fragment. This plainLen is the same
   that you pass as input parameter to the AEAD decryption function. *)

let split_fragment_mac_pad (ki:KeyInfo) (plain:plain) : fragment * mac * bool =
(* 
val split_flagment_mac_pad ki:KeyInfo -> plain:plain 
  {    SupportedProtocolVersion(ki) 
    /\ Length(plain) > MacLen(ki)
    /\ Blocks(plain) } -> f:fragment * m:mac * b:bool 
  {    ( b=true  /\ ?p. plain = fragment @| mac @| padding p )
    \/ ( b=false /\ not ?fragment,mac,p. Length(mac)=... /\ plain = fragment @| mac @| padding p ) }
// We need preconditions stating that: 
// - the protocol version is supported.
// - Length(plain) > maclen (or even maclen + bs with SSL3?) 
// - Length(plain) consists of n blocks
// We also need a precise postcondition to guarantee success on genuine decryptions & failure with modified padding.
*)
    let v = ki.sinfo.protocol_version
    let l = length plain.bytes
    let m = macSize (macAlg_of_ciphersuite ki.sinfo.cipher_suite) in

    let fail() : fragment * mac * bool = 
        (* Parse the message pretending we have a valid padding of minimal length.
           in TLS1.0 we fail just after returning; in more recent versions we fail
           later, after checking the MAC. See sec.6.2.3.2 Implementation Note. 
           This is not perfect, as we may compute the MAC on more blocks than sent,
           or fail after checking the MAC on fewer blocks for some pad-like fragments *)
        let p = 1
        let (fragment_mac,padding) = split plain.bytes  (l - p)
        let (fragment,mac)         = split fragment_mac (l - p - m) 
        {bytes=fragment},MACt(mac),true in (* true: we MustFail *)

    let p = int(plain.bytes.[l-1]) + 1 in
    if l < m + p (* not enough bytes *) then fail()
    else 
        let (fragment_mac,padding) = split plain.bytes  (l - p) in
        let (fragment,mac)         = split fragment_mac (l - p - m) in
        if   (    v = ProtocolVersionType.SSL_3p0 
               && p <= blockSize(encAlg_of_ciphersuite ki.sinfo.cipher_suite) ) 
               (* Padding is random in SSL_3p0, no check to be done on its content.
                  However, its length should be at most one block [SSL3, 5.2.3.2]
                  We enforce this check (performed by openssl, and not by wireshark for example)
                  but we do not report any specific Padding error. *)

          || (    (v = ProtocolVersionType.TLS_1p0 || v = ProtocolVersionType.TLS_1p1 || v = ProtocolVersionType.TLS_1p2)  
               && equalBytes padding (pad p)) 
          
        then {bytes=fragment},MACt(mac),false
        else fail()

let split_mac (ki:KeyInfo) (plainLen:int) (plain:plain) : (bool * (fragment * mac)) =
    let macSize = macSize (macAlg_of_ciphersuite ki.sinfo.cipher_suite) in
    let (tmpdata, padlenb) = split plain.bytes (plainLen - 1) in
    let padlen = int padlenb.[0] in
    // use instead, as this is untrusted anyway:
    // let padlen = (int plain.[length plain - 1]) + 1
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


/// MACOnlyCipherSuites
// TODO: statically enforce that length f.bytes + maclen = n 
let fragment_mac_to_cipher (ki:KeyInfo) (n:int) (f:fragment) (MACt(m):mac) = f.bytes @| m
let cipher_to_fragment_mac (ki:KeyInfo) (n:int) (c:bytes) : fragment * mac = 
    let maclen = 
        let cs = ki.sinfo.cipher_suite in
        macSize (macAlg_of_ciphersuite cs) in
    let macStart = length c - maclen
    if macStart < 0 then
        (* FIXME: is this safe?
           I (AP) think so because our locally computed mac will have some different length.
           Also timing is not an issue, because the attacker can guess the check should fail anyway. *)
    //CF: no, the MAC has the wrong size; I'd rather have a static precondition on the length of c.
        ({bytes = c},MACt([||]))
    else
        let (frag,mac) = split c macStart in
        ({bytes = frag},MACt(mac))

/// NullCipherSuites
// TODO: statically enforce that length f.bytes = n 
let fragment_to_cipher (ki:KeyInfo) (n:int) (f:fragment) = f.bytes 
let cipher_to_fragment (ki:KeyInfo) (n:int) (c:bytes) : fragment = {bytes = c} 


/// Only to be used by trusted crypto libraries MAC, ENC
//CF no, to be discussed
let mac_plain_to_bytes (MACPLAINt(mplain):mac_plain) = mplain

let mac_to_bytes (MACt(mac):mac) = mac
let bytes_to_mac b : mac = MACt(b)

let plain_to_bytes (plain:plain) = plain.bytes
let bytes_to_plain b :plain = {bytes = b}