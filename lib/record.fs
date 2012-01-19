module Record

open Bytes
open Error
open TLSInfo
open TLSKey
open Formats
open CipherSuites
open AEAD

//CF to be enforced statically, inasmuch as possible
// but then we probably need them for TLSPlain too
//let max_TLSPlaintext_fragment_length  = 1<<<14
//let max_TLSCompressed_fragment_length = 1<<<15
//let max_TLSEncrypted_fragment_length  = 1<<<16

type ConnectionState = {
  key: recordKey;
  iv3: ENCKey.iv3;
  seqn: int; (* uint64 actually CF:TODO?*)
  }
type sendState = ConnectionState
type recvState = ConnectionState

let incN (ki:KeyInfo) (s:ConnectionState) =
    let new_seqn = s.seqn + 1 in
    { s with seqn = new_seqn }

let initConnState (ki:KeyInfo) (ccsData:ccs_data) =
  { key = ccsData.key;
    iv3 = ccsData.iv3;
    seqn = 0;
  }

/// format the (public) additional data bytes, for MACing & verifying

let makeAD ki conn ct =
    let version = ki.sinfo.protocol_version in
    let bseq = bytes_of_seq conn.seqn in
    let bct  = ctBytes ct in
    let bver = versionBytes version in
    if version = SSL_3p0 
    then bseq @| bct
    else bseq @| bct @| bver

/// packet format

let makePacket ct ver data =
    let l = length data in 
    let bct  = ctBytes ct in
    let bver = versionBytes ver in
    let bl   = bytes_of_int 2 l in
    bct @| bver @| bl @| data

let parseHeader b = 
    let (ct1,rem4) = split b 1 
    let (pv2,len2) = split rem4 2 
    match parseCT ct1 with
    | Error(x,y) -> Error(x,y)
    | Correct(ct) ->
    match CipherSuites.parseVersion pv2 with
    | Error(x,y) -> Error(x,y)
    | Correct(pv) -> 
    let len = int_of_bytes len2 
    // No need to check len, since it's on 2 bytes and the max allowed value is 2^16.
    correct(ct,pv,len)

let getMACKey key =
    match key with
    | RecordMACKey k -> k
    | _ -> unexpectedError "[getMACKey] invoked on invalid key"

let getAEADKey key =
    match key with
    | RecordAEADKey k -> k
    | _ -> unexpectedError "[getAEADKey] invoked on invalid key"

(* This replaces send. It's not called send, since it doesn't send anything on the
   network *)
let recordPacketOut ki conn tlen ct fragment =
    (* No need to deal with compression. It is handled internally by TLSPlain,
       when returning us the next (already compressed!) fragment *)
    (*
    match make_compression conn.rec_ki.sinfo fragment with
    | Error (x,y) -> Error (x,y)
    | Correct compressed ->
    *)
    let (conn, payload) =
        match ki.sinfo.cipher_suite with
        | x when isNullCipherSuite x -> 
            (conn,TLSFragment.repr ki tlen fragment)
        | x when isOnlyMACCipherSuite x ->
            let key = getMACKey conn.key in
            let addData = makeAD ki conn ct in
            let data = MACPlain.MACPlain ki tlen addData fragment in
            let mac = Mac.MAC {ki=ki;tlen=tlen} key data in
            (conn, (TLSFragment.repr ki tlen fragment) @| (MACPlain.reprMACed ki mac))
        | _ ->
            let addData = makeAD ki conn ct in
            let key = getAEADKey conn.key in
            let (newIV,payload) = AEAD.encrypt ki key conn.iv3 tlen addData fragment in
            let conn = {conn with iv3 = newIV} in
            (conn,payload)
    let conn = incN ki conn in
    let packet = makePacket ct ki.sinfo.protocol_version payload in
    (conn,packet)

(* CF: an attempt to simplify for typechecking 
let recordPacketOut2 conn clen ct fragment =
    let suite = conn.rec_ki.sinfo.cipher_suite 
    let conn, payload = 
        if isNullCipherSuite suite then 
            conn,
            fragment_to_cipher conn.rec_ki clen fragment
        else 
            let ad = makeAD conn ct in
            if isOnlyMACCipherSuite suite then           
                let key = getMACKey conn.key in
                let text = mac_plain_to_bytes (ad_fragment conn.rec_ki ad fragment)
                let mac = Mac.MAC conn.rec_ki key text 
                conn, 
                fragment_mac_to_cipher conn.rec_ki clen fragment (bytes_to_mac mac)
            else
                let key = getAEADKey conn.key in
                let newIV, payload = AEAD.encrypt conn.rec_ki key conn.iv3 clen ad fragment 
                {conn with iv3 = newIV},
                payload
    incN conn,
    makePacket ct conn.local_pv payload 
*)

let recordPacketIn ki conn len ct payload =
    //CF tlen is not checked? can we write an inverse of makePacket instead?
    let cs = ki.sinfo.cipher_suite in
    let msgRes =
        match cs with
        | x when isNullCipherSuite x -> 
            correct(conn, ki len payload)
        | x when isOnlyMACCipherSuite x ->
            let (msg,mac) = cipher_to_fragment_mac ki len payload in
            let data = makeAD ki conn ct in
            let toVerify = ad_fragment ki data msg in
            let key = getMACKey conn.key in
            if Mac.VERIFY ki key (mac_plain_to_bytes toVerify) (mac_to_bytes mac) then
                correct(conn,msg)
            else
            Error(MAC,CheckFailed)
        | _ ->
            let data = makeAD ki conn ct in
            let key = getAEADKey conn.key in
            match AEAD.decrypt ki key conn.iv3 len data payload with
            | Error(x,y) -> Error(x,y)
            | Correct (newIV, plain) ->
                let conn = {conn with iv3 = newIV} in
                correct (conn,plain)
    match msgRes with
    | Error(x,y) -> Error(x,y)
    | Correct (conn,msg) ->
    (* We now always return the compressed fragment. Decompression is handled internally by TLSPlain *)
    (*
    match make_decompression conn.rec_ki.sinfo msg with
    | Error(x,y) -> Error(x,y)
    | Correct (msg) ->
    *)
    let conn = incN ki conn in
    correct(conn,ct,len,msg)



/// old stuff, to be deleted?

(* 
// We'll need to qualify system errors,
// as some of them break confidentiality 
let send conn ct fragment =
    match make_compression conn fragment with
    | Error (x,y) -> Error (x,y)
    | Correct compressed ->
    match compute_mac conn ct compressed with
    | Error (x,y) -> Error (x,y)
    | Correct mac ->
    let content = append compressed mac in
    let toEncrypt = prepare_enc conn content in
    match encrypt conn toEncrypt with
    | Error (x,y) -> Error (x,y)
    | Correct c ->
        let (conn, payload) = c in
        let conn = incN conn in
        let packet = makePacket ct conn.protocol_version payload in
        match Tcp.write conn.net_conn packet with
        | Error (x,y) -> Error (x,y)
        | Correct _ -> correct (conn)
*)

(* Legacy implementation of recv. Now replaced by recordPacketIn, which does not deal with the network channel *)
(* 
let recv conn =
    let net = conn.net_conn in
//Cedric: we need refinements to keep track of lengths, starting from TCP.read etc
    match Tcp.read net 5 with
    | Error (x,y) -> Error (x,y)
    | Correct header ->
    let (ct,pv,len) = parseHeader header in
    if   (  conn.protocol_version <> UnknownPV 
         && pv <> conn.protocol_version)
      || pv = UnknownPV 
    then Error (RecordVersion,CheckFailed)
    else
        (* We commit to the received protocol version.
           In fact, this only changes the protcol version when receiving the first fragment *)
        let conn = {conn with protocol_version = pv} in
        (* No need to check len, since it's on 2 bytes and the max allowed value
           is 2^16. So, here len is always safe *)
        match Tcp.read net len with 
        | Error (x,y) -> Error (x,y) 
        | Correct payload ->
        match decrypt conn payload with
        | Error (x,y) -> Error (x,y)
        | Correct c ->
        let (conn,compr_and_mac_and_pad) = c in
        match parse_plaintext conn compr_and_mac_and_pad with
        | Error (x,y) -> Error (x,y)
        | Correct c ->
        let (compr,mac) = c in
        match verify_mac conn ct compr mac with
        | Error (x,y) -> Error (x,y)
        | Correct c ->
        match make_decompression conn compr with
        | Error (x,y) -> Error (x,y)
        | Correct (msg) ->
        let conn = incN conn in
        correct (ct,msg,conn)
*)


(* check_length and make_(de)compression are now internally handled by TLSPlain *)
(*
let check_length (item: bytes) max_len result errorType =
    if length item < max_len then
        correct (result)
    else
        Error (errorType, CheckFailed)

let make_compression conn (data:bytes) =
    (* Assume data is a fragment of correct length; 
       Ensure the result is not longer than 2^15 bytes *)
    match conn.compression with
    | Null -> correct (data) (* Post-condition is always satisfied *)
    | _ -> Error (RecordCompression, Unsupported)

let make_decompression conn data =
    (* Assume data is a compressed fragment of proper length *)
    match conn.compression with
    | Null -> check_length data max_TLSPlaintext_fragment_length data RecordCompression
    | _ -> Error (RecordCompression, Unsupported)
*)
