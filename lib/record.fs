module Record

open Bytes
open Error
open TLSInfo
open TLSPlain
open Formats
open CipherSuites
open AEAD

type recordKey =
    | RecordAEADKey of AEADKey
    | RecordMACKey of Mac.key
    | NoneKey

type ccs_data =
    { ki: KeyInfo;
      key: recordKey;
      iv3: ENC.iv3;
    }

type ConnectionState = {
  rec_ki: KeyInfo;
  key: recordKey;
  iv3: ENC.iv3;
  seq_num: int; (* uint64 actually CF:TODO?*)
  local_pv: ProtocolVersionType;
  }
type sendState = ConnectionState
type recvState = ConnectionState

type preds = FragmentSend of ConnectionState * ContentType * bytes

let incSeqNum (conn_state:ConnectionState) =
    let new_seq_num = conn_state.seq_num + 1 in
    { conn_state with seq_num = new_seq_num }

let initConnState ki key iv pv =
  { rec_ki = ki;
    key = key;
    iv3 = iv;
    seq_num = 0;
    local_pv = pv;
  }

let create out_ki in_ki minpv =
    let sendState = initConnState out_ki NoneKey (ENC.NoIV ()) minpv in
    let recvState = initConnState in_ki NoneKey (ENC.NoIV ()) ProtocolVersionType.UnknownPV in
    (sendState, recvState)

// to be enforced statically, inasmuch as possible
let max_TLSPlaintext_fragment_length  = 1<<<14
let max_TLSCompressed_fragment_length = 1<<<15
let max_TLSEncrypted_fragment_length  = 1<<<16

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

(* format the (public) additional data bytes, for MACing & verifying *)
let makeAD conn ct =
    let version = conn.local_pv in
    let bseq = bytes_of_seq conn.seq_num in
    let bct  = bytes_of_contentType ct in
    let bver = bytes_of_protocolVersionType version in
    match version with
    | ProtocolVersionType.SSL_3p0             -> bseq @| bct
    | x when x >= ProtocolVersionType.TLS_1p0 -> bseq @| bct @| bver
    | _ -> unexpectedError "[makeAD] invoked on invalid protocol version"

let makePacket ct ver data =
  let l = length data in 
  let bct  = bytes_of_contentType ct in
  let bver = bytes_of_protocolVersionType ver in
  let bl   = bytes_of_int 2 l in
  bct @| bver @| bl @| data

//CF we'll need refinements to prevent parsing errors.
//CF can we move the check to Dispatch?
let parse_header conn header =
  let (ct1,rem4) = split header 1 in
  let (pv2,len2) = split rem4 2 in
  let ct  = contentType_of_bytes ct1 in
  let pv  = protocolVersionType_of_bytes pv2 in
  let len = int_of_bytes len2 in
  if   (  conn.local_pv <> ProtocolVersionType.UnknownPV 
         && pv <> conn.local_pv)
      || pv = ProtocolVersionType.UnknownPV 
    then Error (RecordVersion,CheckFailed)
  else
    (* We commit to the received protocol version.
       In fact, this only changes the protcol version when receiving the first fragment *)
    let conn = {conn with local_pv = pv} in
    correct (conn,ct,len)


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
        let conn = incSeqNum conn in
        let packet = makePacket ct conn.protocol_version payload in
        match Tcp.write conn.net_conn packet with
        | Error (x,y) -> Error (x,y)
        | Correct _ -> correct (conn)
*)

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
let recordPacketOut conn tlen ct (fragment:fragment) =
    (* No need to deal with compression. It is handled internally by TLSPlain,
       when returning us the next (already compressed!) fragment *)
    (*
    match make_compression conn.rec_ki.sinfo fragment with
    | Error (x,y) -> Error (x,y)
    | Correct compressed ->
    *)
    let (conn, payload) =
        match conn.rec_ki.sinfo.cipher_suite with
        | x when isNullCipherSuite x -> 
            (conn,fragment_to_cipher conn.rec_ki tlen fragment)
        | x when isOnlyMACCipherSuite x ->
            let key = getMACKey conn.key in
            let addData = makeAD conn ct in
            let data = ad_fragment conn.rec_ki addData fragment in
            let mac = Mac.MAC conn.rec_ki key (mac_plain_to_bytes data) in
            (conn,fragment_mac_to_cipher conn.rec_ki tlen fragment (bytes_to_mac mac))
        | _ ->
            let addData = makeAD conn ct in
            let key = getAEADKey conn.key in
            let (newIV,payload) = AEAD.encrypt conn.rec_ki key conn.iv3 tlen addData fragment in
            let conn = {conn with iv3 = newIV} in
            (conn,payload)
    let conn = incSeqNum conn in
    let packet = makePacket ct conn.local_pv payload in
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
    incSeqNum conn,
    makePacket ct conn.local_pv payload 
*)

let send_setVersion conn pv = {conn with local_pv = pv }

let send_setCrypto ccs_data =
    initConnState ccs_data.ki ccs_data.key ccs_data.iv3 ccs_data.ki.sinfo.protocol_version

let recordPacketIn conn packet =
    let (header,payload) = split packet 5 in
    match parse_header conn header with
    | Error(x,y) -> Error(x,y)
    | Correct (conn,ct,tlen) ->
    //CF tlen is not checked? can we write an inverse of makePacket instead?
    let cs = conn.rec_ki.sinfo.cipher_suite in
    let msgRes =
        match cs with
        | x when isNullCipherSuite x -> 
            correct(conn,cipher_to_fragment conn.rec_ki tlen payload)
        | x when isOnlyMACCipherSuite x ->
            let (msg,mac) = cipher_to_fragment_mac conn.rec_ki tlen payload in
            let data = makeAD conn ct in
            let toVerify = ad_fragment conn.rec_ki data msg in
            let key = getMACKey conn.key in
            if Mac.VERIFY conn.rec_ki key (mac_plain_to_bytes toVerify) (mac_to_bytes mac) then
                correct(conn,msg)
            else
            Error(MAC,CheckFailed)
        | _ ->
            let data = makeAD conn ct in
            let key = getAEADKey conn.key in
            match AEAD.decrypt conn.rec_ki key conn.iv3 tlen data payload with
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
    let conn = incSeqNum conn in
    correct(conn,ct,tlen,msg)

(* Legacy implementation of recv. Now replaced by recordPacketIn, which does not deal with the network channel *)
(* 
let recv conn =
    let net = conn.net_conn in
//Cedric: we need refinements to keep track of lengths, starting from TCP.read etc
    match Tcp.read net 5 with
    | Error (x,y) -> Error (x,y)
    | Correct header ->
    let (ct,pv,len) = parse_header header in
    if   (  conn.protocol_version <> ProtocolVersionType.UnknownPV 
         && pv <> conn.protocol_version)
      || pv = ProtocolVersionType.UnknownPV 
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
        let conn = incSeqNum conn in
        correct (ct,msg,conn)
*)

let recv_setVersion conn pv =
    {conn with local_pv = pv}

let recv_checkVersion conn pv =
    if pv = conn.local_pv then
        correct ()
    else
        Error(RecordVersion,CheckFailed)

let recv_setCrypto ccs_data =
    initConnState ccs_data.ki ccs_data.key ccs_data.iv3 ccs_data.ki.sinfo.protocol_version