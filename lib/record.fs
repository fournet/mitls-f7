module Record

open Data
open Bytearray
open Error_handling
open TLSInfo
open TLSPlain
open Formats
open HS_ciphersuites
open AEAD

type recordKey =
    | RecordAEADKey of AEADKey
    | RecordMACKey of MAC.macKey
    | NoneKey

type ConnectionState = {
  rec_ki: KeyInfo;
  key: recordKey;
  ivOpt: ENC.ivOpt;
  seq_num: int; (* uint64 actually *)
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
    ivOpt = iv;
    seq_num = 0;
    local_pv = pv;
  }

let create in_ki out_ki minpv =
    let sendState = initConnState out_ki NoneKey ENC.NoneIV minpv in
    let recvState = initConnState in_ki NoneKey ENC.NoneIV ProtocolVersionType.UnknownPV in
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

let prepareAddData conn ct =
    let version = conn.local_pv in

    let bseq_num = bytes_of_seq conn.seq_num in
    let bct = [| byte_of_contentType ct |] in
    let bver = bytes_of_protocolVersionType version in
    match version with
    | ProtocolVersionType.SSL_3p0 -> bseq_num @| bct
    | x when x >= ProtocolVersionType.TLS_1p0 -> bseq_num @| bct @| bver
    | _ -> unexpectedError "[prepareAddData] invoked on invalid protocol version"

let generatePacket ct ver data =
  let l = length data in 
  let bct = [| byte_of_contentType ct |] in
  let bver = bytes_of_protocolVersionType ver in
  let bl = bytes_of_int 2 l in
  bct @| bver @| bl @| data

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
        let packet = generatePacket ct conn.protocol_version payload in
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
    | _ -> unexpectedError "[getMACKey] invoked on invalid key"

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
    let payloadRes =
        match conn.rec_ki.sinfo.cipher_suite with
        | x when isNullCipherSuite x -> correct (conn,fragment_to_cipher conn.rec_ki tlen fragment)
        | x when isOnlyMACCipherSuite x ->
            let key = getMACKey conn.key in
            let addData = prepareAddData conn ct in
            let data = ad_fragment conn.rec_ki addData fragment in
            match MAC.MAC conn.rec_ki key (mac_plain_to_bytes data) with
            | Error(x,y) -> Error(x,y)
            | Correct(mac) -> correct(conn,fragment_mac_to_cipher conn.rec_ki tlen fragment (bytes_to_mac mac))
        | _ ->
            let addData = prepareAddData conn ct in
            let key = getAEADKey conn.key in
            match AEAD.AEAD_ENC conn.rec_ki key conn.ivOpt tlen addData fragment with
            | Error(x,y) -> Error(x,y)
            | Correct(newIV,payload) ->
                let conn = {conn with ivOpt = newIV} in
                correct(conn,payload)
    match payloadRes with
    | Error(x,y) -> Error(x,y)
    | Correct(conn, payload) ->
    let conn = incSeqNum conn in
    let packet = generatePacket ct conn.local_pv payload in
    correct(conn,packet)


let send_setVersion conn pv = {conn with local_pv = pv }

let send_setCrypto ki key iv =
    initConnState ki key iv ki.sinfo.protocol_version

let parse_header conn header =
  let [x;y;z] = splitList header [1;2] in
  let ct = contentType_of_byte x.[0] in
  let pv = protocolVersionType_of_bytes y in
  let len = int_of_bytes 2 z in
  if   (  conn.local_pv <> ProtocolVersionType.UnknownPV 
         && pv <> conn.local_pv)
      || pv = ProtocolVersionType.UnknownPV 
    then Error (RecordVersion,CheckFailed)
  else
    (* We commit to the received protocol version.
       In fact, this only changes the protcol version when receiving the first fragment *)
    let conn = {conn with local_pv = pv} in
    correct (conn,ct,len)

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

let recordPacketIn conn packet =
    let (header,payload) = split packet 5 in
    match parse_header conn header with
    | Error(x,y) -> Error(x,y)
    | Correct (conn,ct,tlen) ->
    let cs = conn.rec_ki.sinfo.cipher_suite in
    let msgRes =
        match cs with
        | x when isNullCipherSuite x -> correct(conn,cipher_to_fragment conn.rec_ki tlen payload)
        | x when isOnlyMACCipherSuite x ->
            let (msg,mac) = cipher_to_fragment_mac conn.rec_ki tlen payload in
            let addData = prepareAddData conn ct in
            let toVerify = ad_fragment conn.rec_ki addData msg in
            let key = getMACKey conn.key in
            match MAC.VERIFY conn.rec_ki key (mac_plain_to_bytes toVerify) (mac_to_bytes mac) with
            | Error(x,y) -> Error(x,y)
            | Correct(_) ->
                correct(conn,msg)
        | _ ->
            let addData = prepareAddData conn ct in
            let key = getAEADKey conn.key in
            match AEAD.AEAD_DEC conn.rec_ki key conn.ivOpt tlen addData payload with
            | Error(x,y) -> Error(x,y)
            | Correct (newIV, plain) ->
                let conn = {conn with ivOpt = newIV} in
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
    correct(conn,ct,msg)


let recv_setVersion conn pv =
    {conn with local_pv = pv}

let recv_checkVersion conn pv =
    if pv = conn.local_pv then
        correct ()
    else
        Error(RecordVersion,CheckFailed)

let recv_setCrypto ki key iv =
    initConnState ki key iv ki.sinfo.protocol_version