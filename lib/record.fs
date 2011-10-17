module Record

open Data
open Bytearray
open Error_handling
open TLSInfo
open Formats
open HS_ciphersuites
open AEAD

type recordKey =
    | RecordAEADKey of AEADKey
    | RecordMACKey of HMAC.macKey
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

type fragment = bytes

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

// MAC computations
//Cedric: we should use some generic vlen marshaller for data, 
//        avoid appendList, marshall seq_num and ct later,
//        and maybe pass a "ver option" to merge the two cases.

(* I’d like to merge the two functions
   compute_mac_ssl_blob bseq_num bct data
   compute_mac_tls_blob bseq_num bct bver data
into 
  MACed 
  (n:seqnum)
  (ct:ContentType)
  (version:ProtocolVersionType)
  (data:bytes)
so that (1) the marshalling is hidden, and (2) we can prove this function injective, with no special case for older SSLs

-> b:bytes { b = MACbytes(n,ct,version,data) }

ask MACbytes(n0,ct0,v0,d0) = MACbytes(n1,ct1,v1,d1) => n0=n1 /\ ... 
[for now we use relations, KHashBytes and MACBytes, to be merged]
*)

let prepareAddData conn ct data =
    let version = conn.local_pv in

    let bseq_num = bytes_of_seq conn.seq_num in
    let bct = [| byte_of_contentType ct |] in
    let bver = bytes_of_protocolVersionType version in
    let dlength = bytes_of_int 2 (length data) in
    match version with
    | ProtocolVersionType.SSL_3p0 -> bseq_num @| bct @| dlength
    | x when x >= ProtocolVersionType.TLS_1p0 -> bseq_num @| bct @| bver @| dlength
    | _ -> unexpectedError "[prepareAddData] invoked on invalid protocol version"

let verify_mac conn ct compr givenmac =
    match conn.sparams.mac_algorithm with
    | MA_null -> 
        if equalBytes givenmac empty_bstr 
          then correct ()
          else Error (MAC, CheckFailed)
    | alg -> 
        let version = conn.protocol_version in
        let key = conn.mk in
        let bseq_num = bytes_of_seq conn.seq_num in
        let bct = bytes_of_contentType ct in
        let bver = bytes_of_protocolVersionType version in
        match version with
        | ProtocolVersionType.SSL_3p0 ->
            let mmsg = compute_mac_ssl_blob bseq_num bct compr in
            match alg with
            | MA_md5  -> keyedHashVerify md5  ssl_pad1_md5  ssl_pad2_md5  key mmsg givenmac
            | MA_sha1 -> keyedHashVerify sha1 ssl_pad1_sha1 ssl_pad2_sha1 key mmsg givenmac
            | _       -> Error (MAC, Unsupported)
        | v when v = ProtocolVersionType.TLS_1p0 || v = ProtocolVersionType.TLS_1p1 || v = ProtocolVersionType.TLS_1p2 ->
            let data = compute_mac_tls_blob bseq_num bct bver compr in
            match alg with
            | MA_md5  -> hmacmd5Verify  key data givenmac
            | MA_sha1 -> hmacsha1Verify key data givenmac
            | _       -> Error (MAC, Unsupported)
        | ProtocolVersionType.SSL_2p0 -> Error (MAC, Unsupported)
        | _ -> unexpectedError "[verify_mac] only to be invoked after a version has been negotiated"

// this will be outside of authenc 
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

(* This will replace send. It's not called send, since it doesn't send anything on the
   network *)
let recordPacketOut conn ct fragment =
    match make_compression conn.rec_ki.sinfo fragment with
    | Error (x,y) -> Error (x,y)
    | Correct compressed ->
    let payloadRes =
        match conn.rec_ki.sinfo.cipher_suite with
        | x when isNullCipherSuite x -> correct (conn,compressed)
        | x when isOnlyMACCipherSuite x ->
            let addData = prepareAddData conn ct compressed in
            let key = getMACKey conn.key in
            let data = addData @| compressed in
            match MAC.MAC conn.rec_ki key data with
            | Error(x,y) -> Error(x,y)
            | Correct(payload) -> correct(conn,payload)
        | _ ->
            let addData = prepareAddData conn ct compressed in
            let key = getAEADKey conn.key in
            match AEAD.AEAD_ENC conn.rec_ki key conn.ivOpt addData compressed with
            | Error(x,y) -> Error(x,y)
            | Correct(newIV,payload) ->
                if PVRequiresExplicitIV conn.rec_ki.sinfo.protocol_version then
                    let payload = newIV @| payload in
                    correct(conn,payload)
                else
                    let conn = {conn with ivOpt = ENC.SomeIV (newIV)} in
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
    correct (ct,pv,len)

let get_iv_ciphertext version bulk_cipher_algorithm iv ciphertext =
    let bs = get_block_cipher_size bulk_cipher_algorithm in
    match version with
    | x when x = ProtocolVersionType.TLS_1p1 || x = ProtocolVersionType.TLS_1p2 -> (split ciphertext bs)
    | x when x = ProtocolVersionType.SSL_3p0 || x = ProtocolVersionType.TLS_1p0 -> (iv,ciphertext)
    | x when x = ProtocolVersionType.SSL_2p0 -> unexpectedError "[get_iv_ciphertext] Unsupported protocol version, but the caller should ensure we are not called."
    | _ -> unexpectedError "[get_iv_ciphertext] Protocol version must be known when getting the IV"


let decrypt_fun block_cipher_algorithm key iv data  =
    match block_cipher_algorithm with
    | BCA_des     -> des_decrypt_wiv_nopad key iv data
    | BCA_aes_128 -> aes_decrypt_wiv_nopad key iv data
    | BCA_aes_256 -> aes_decrypt_wiv_nopad key iv data
    | _           -> Error (Encryption, Unsupported) (* FIXME: other block BCAs are truly unsupported, but other stream BCAs (e.g. null) are in fact "unexpectedErrors" *)

let block_decrypt conn_state data = 
    match conn_state.cipher_state with
    | BlockCipherState (key,iv) ->
        (let ver = conn_state.protocol_version in
        match ver with
        | ProtocolVersionType.SSL_2p0 -> Error(Encryption,Unsupported)
        | _ ->
        let (iv,data) = get_iv_ciphertext ver
                                          conn_state.sparams.bulk_cipher_algorithm
                                          iv data in
        match decrypt_fun conn_state.sparams.bulk_cipher_algorithm key iv data with
        | Error (x,y) -> Error (x,y)
        | Correct plain ->
        match check_length plain max_TLSCompressed_fragment_length plain Encryption with
        | Error (x,y) -> Error (x,y) 
        | Correct plain ->
            let next_iv = compute_next_iv ver conn_state.sparams.bulk_cipher_algorithm data in
            let conn_state = { conn_state with cipher_state = BlockCipherState(key,next_iv) } in
            correct (conn_state, plain))
    | _ -> unexpectedError "[block_decrypt] invoked with a non BlockCipherState" 


let decrypt conn_state (payload:bytes) =
    (* Assume payload has correct maximum length.
       Check that the compressed fragment has the correct maximum length *)
    let sp = conn_state.sparams in
    match sp.cipher_type with
    | CT_stream ->
        match sp.bulk_cipher_algorithm with
        | BCA_null -> check_length payload max_TLSCompressed_fragment_length (conn_state, payload) Encryption
        | _ -> Error (Encryption, Unsupported) (* FIXME: other stream BCAs are truly unsupported, but other block BCAs (e.g. aes, des) are in fact "unexpectedErrors" *)
    | CT_block -> block_decrypt conn_state payload 

let check_padding_cont (data:bytes)  =
   correct (data)
//Cedric: ?

let check_padding sp version (data:bytes) =
    let dlen = length data in
    let (tmpdata, padlenb) = split data (dlen - 1) in
    let padlen = int_of_bytes 1 padlenb in
    let padstart = dlen - padlen - 1 in
    if padstart < 0 then
        (* Evidently padding has been corrupted, or has been incorrectly generated *)
        (* in TLS1.0 we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
        match version with
        | v when v >= ProtocolVersionType.TLS_1p1 ->
            (* Pretend we have a valid padding of length zero *)
            check_padding_cont data
        | v when v = ProtocolVersionType.SSL_3p0 || v = ProtocolVersionType.TLS_1p0 ->
            (* in TLS1.0/SSL we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
            Error (RecordPadding,CheckFailed)
        | ProtocolVersionType.SSL_2p0 -> Error(RecordPadding,Unsupported)
        | _ -> unexpectedError "[check_padding] Protocol version should be known when checking the padding."
    else
        let (data_no_pad,pad) = split tmpdata padstart in
        match version with
        | v when v = ProtocolVersionType.TLS_1p0 || v = ProtocolVersionType.TLS_1p1 || v = ProtocolVersionType.TLS_1p2 ->
            let expected = createBytes padlen padlen in
            if equalBytes expected pad then
                check_padding_cont data_no_pad
            else
                (* in TLS1.0 we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
                if  v = ProtocolVersionType.TLS_1p0 then
                    Error (RecordPadding,CheckFailed)
                else
                    (* Pretend we have a valid padding of length zero *)
                    check_padding_cont data
        | ProtocolVersionType.SSL_3p0 ->
            (* Padding is random in SSL_3p0, no check to be done on its content.
               However, its length should be at most on bs
               (See sec 5.2.3.2 of SSL 3 draft). Enforce this check (which
               is performed by openssl, and not by wireshark for example). *)
            let bs = get_block_cipher_size sp.bulk_cipher_algorithm in
            if padlen >= bs then
                (* Insecurely report the error. Only TLS 1.1 and above should
                   be secure with this respect *)
                Error (RecordPadding,CheckFailed)
            else
                check_padding_cont data_no_pad
        | ProtocolVersionType.SSL_2p0 -> Error(RecordPadding,Unsupported)
        | _ -> unexpectedError "[check_padding] Protocol version should be known when checking the padding."

let parse_plaintext conn_state data =
    let result_depadding =
        match conn_state.sparams.cipher_type with
        | CT_block -> check_padding conn_state.sparams conn_state.protocol_version data
        | CT_stream -> correct (data)
    match result_depadding with
    | Error (x,y) -> Error (x,y)
    | Correct data_no_pad ->
        let hash_size = get_hash_size conn_state.sparams.mac_algorithm in
        let mac_start = (length data_no_pad) - hash_size in
        correct (split data_no_pad mac_start)
 
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

let split_mac cs data =
    let maclen = Algorithms.macLength (macAlg_of_ciphersuite cs) in
    let macStart = (length data) - maclen
    if macStart < 0 then
        Error(MAC,CheckFailed)
    else
        correct (split data macStart)

let recordPacketIn conn ct payload =
    let cs = conn.rec_ki.sinfo.cipher_suite in
    let msgRes =
        match cs with
        | x when isNullCipherSuite x -> correct(conn,payload)
        | x when isOnlyMACCipherSuite x ->
            match split_mac cs payload with
            | Error(x,y) -> Error(x,y)
            | Correct(msg,mac) ->
                let addData = prepareAddData conn ct msg in
                let toVerify = addData @| msg in
                let key = getMACKey conn.key in
                match MAC.VERIFY conn.rec_ki key toVerify mac with
                | Error(x,y) -> Error(x,y)
                | Correct(_) ->
                    correct(conn,msg)
        | _ ->
            let addData = prepareAddData conn ct msg in
            let key = getAEADKey conn.key in
            let (iv,payload) =
                if PVRequiresExplicitIV conn.local_pv then
                    let encAlg = encAlg_of_ciphersuite cs in
                    let ivLen = Algorithms.ivSize encAlg in
                    split payload ivLen
                else
                    match conn.ivOpt with
                    | ENC.SomeIV (iv) -> (iv,payload)
                    | ENC.NoneIV -> unexpectedError "[recordPacketIn] An IV should always be in the state if the protocol version requries so."
            match AEAD.AEAD_DEC conn.rec_ki key iv addData payload with
            | Error(x,y) -> Error(x,y)
            | Correct (newIV, plain) ->
                let conn = {conn with ivOpt = newIV} in
                correct (conn,plain)
    match msgRes with
    | Error(x,y) -> Error(x,y)
    | Correct (conn,msg) ->
    match make_decompression conn.rec_ki.sinfo msg with
    | Error(x,y) -> Error(x,y)
    | Correct (msg) ->
    let conn = incSeqNum conn in
    correct(conn,msg)


let recv_setVersion conn pv =
    {conn with local_pv = pv}

let recv_checkVersion conn pv =
    if pv = conn.local_pv then
        correct ()
    else
        Error(RecordVersion,CheckFailed)

let recv_setCrypto ki key iv =
    initConnState ki key iv ki.sinfo.protocol_version