module Record

open Data
open Bytearray
open CryptoTLS
open Tcp
open Formats
open Error_handling
open Sessions

type CipherState = 
  | BlockCipherState of Crypto.key * bytes    // (key,iv)
  | StreamCipherState

type preDirection =
    | CtoS
    | StoC

type Direction = preDirection

type ConnectionState = {
  rec_info: SessionInfo;
  dir: Direction;
  net_conn: NetworkStream;                (* underlying TCP connection *)
  compression: Compression;
  protocol_version: ProtocolVersionType;
  cipher_state: CipherState;
  mk: Crypto.key;
  seq_num: int; (* uint64 actually *)
  sparams: SecurityParameters; 
}

type sendState = ConnectionState
type recvState = ConnectionState
type fragment = bytes
type ccs_data = {
    ccs_info: SessionInfo;
    ccs_pv: ProtocolVersionType;
    ccs_comp: Compression;
    ccs_sparams: SecurityParameters;
    ccs_mkey: Crypto.key;
    ccs_ciphstate: CipherState}

type preds = FragmentSend of ConnectionState * ContentType * bytes

let indir info =
    match getSessionRole info with
    | ClientRole -> StoC
    | ServerRole -> CtoS

let outdir info =
    match getSessionRole info with
    | ClientRole -> CtoS
    | ServerRole -> StoC
  
let incSeqNum (conn_state:ConnectionState) =
    let new_seq_num = conn_state.seq_num + 1 in
    { conn_state with seq_num = new_seq_num }

let initConnState ns info dir pv =
  let mkey = symkey empty_bstr in
    {rec_info = info;
    dir = dir;
    net_conn = ns;
    compression = Null;
    protocol_version = pv;
    cipher_state = StreamCipherState; 
    mk = mkey;
    seq_num = 0;
    sparams = { 
                bulk_cipher_algorithm = BCA_null;
                cipher_type = CT_stream;
                mac_algorithm = MA_null;
              }
    }

let create ns info minpv =
    let outDir = outdir info in
    let sendState = initConnState ns info outDir minpv in
    let inDir = indir info in
    let recvState = initConnState ns info inDir UnknownPV in
    (sendState, recvState)

let max_TLSPlaintext_fragment_length = 1<<<14
let max_TLSCompressed_fragment_length = 1<<<15
let max_TLSEncrypted_fragment_length = 1<<<16

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


let compute_mac_ssl_blob bseq_num bct data =
    let dlength = bytes_of_int 2 (length data) in
    appendList [bseq_num; bct; dlength; data]

let compute_mac_ssl3 mac_alg mac_key bseq_num bct data =
    let mmsg = compute_mac_ssl_blob bseq_num bct data in
    match mac_alg with
    | MA_md5 ->
        keyedHash md5 ssl_pad1_md5 ssl_pad2_md5 mac_key mmsg
    | MA_sha1 ->
        keyedHash sha1 ssl_pad1_sha1 ssl_pad2_sha1 mac_key mmsg
    | _ -> unexpectedError "No other hash algorithm should be negotiated in SSL3"
let compute_mac_tls_blob bseq_num bct bver data =
    let dlength = bytes_of_int 2 (length data) in
    appendList [bseq_num; bct; bver; dlength; data]

let compute_mac_tls mac_alg mac_key bseq_num bct bver data =
    let mmsg = compute_mac_tls_blob bseq_num bct bver data in
    match mac_alg with
    | MA_md5 -> hmacmd5 mac_key mmsg
    | MA_sha1 -> hmacsha1 mac_key mmsg
    | _ -> Error (MAC, Unsupported)

let compute_mac conn_state ct data =
    let version = conn_state.protocol_version in
    let mac_alg = conn_state.sparams.mac_algorithm in
    if mac_alg = MA_null then
        correct (empty_bstr)
    else
        let mac_key = conn_state.mk in
        let bseq_num = bytes_of_seq conn_state.seq_num in
        let bct = bytes_of_contentType ct in
        let bver = bytes_of_protocolVersionType version in
        match version with
        | SSL_2p0 -> Error (MAC, Unsupported)
        | SSL_3p0 -> compute_mac_ssl3 mac_alg mac_key bseq_num bct data
        | x when x = TLS_1p0 || x = TLS_1p1 || x = TLS_1p2 -> 
            compute_mac_tls mac_alg mac_key bseq_num bct bver data
        | UnknownPV -> 
            unexpectedError "[compute_mac] only to be invoked after a version has been negotiated"

let compute_padlen sp data =
    let bs = get_block_cipher_size sp.bulk_cipher_algorithm in
    let len_no_pad = (length data) + 1 in (* 1 byte for the padlen byte *)
    let min_padlen = len_no_pad % bs in
    let rand = bs * (((int_of_bytes 1 (Crypto.mkRandom 1)) - min_padlen) / bs) in 
    min_padlen + rand

let prepare_enc conn_state data =
    let sp = conn_state.sparams in
    match sp.cipher_type with
    | CT_stream -> data
    | CT_block ->
        let padlen = compute_padlen sp data in
        append data (createBytes (padlen+1) padlen)

let encrypt_stream conn_state (data:bytes) =
    match conn_state.sparams.bulk_cipher_algorithm with
    | BCA_null -> correct (conn_state, data)
    | _ -> Error (Encryption, Unsupported)

let get_last_block bs (msg:bytes) =
    let (_,last) = split msg ((length msg) - bs) in
    last

let compute_next_iv version bulk_cipher_algorithm ciphertext =
    let bs = get_block_cipher_size bulk_cipher_algorithm in
    match version with
    | x when x = TLS_1p1 || x = TLS_1p2 ->
        let r = Crypto.mkRandom bs (* Only used when sending data *) in
          Pi.assume (Crypto.PubNonce(r)); r
    | x when x = SSL_3p0 || x = TLS_1p1 ->
        get_last_block bs ciphertext
    | x when x = UnknownPV -> unexpectedError "[compute_next_iv] Protocol version must be known when computing IV"
    | x when x = SSL_2p0 -> unexpectedError "[compute_next_iv] Unsupported protocol version, but the caller should not invoke us."

let encrypt_fun bca key iv data =
    match bca with
    | BCA_des -> des_encrypt_wiv key iv data
    | BCA_aes -> aes_encrypt_wiv key iv data
    | _ -> Error (Encryption, Unsupported)

let encrypt_block conn_state data =
    match conn_state.cipher_state with
    | BlockCipherState (key,iv) ->
        let bca = conn_state.sparams.bulk_cipher_algorithm in
        match encrypt_fun bca key iv data with
        | Error (x,y) -> Error(x,y)
        | Correct encrypted ->
        let ver = conn_state.protocol_version in
        match ver with
        | SSL_2p0 -> Error(Encryption,Unsupported)
        | _ ->
        let new_iv = compute_next_iv ver bca encrypted in
        let conn_state = { conn_state with cipher_state = BlockCipherState(key,new_iv) } in
        match ver with
        | x when x = TLS_1p1 || x = TLS_1p2 -> let data = append iv encrypted in correct (conn_state, data)
        | x when x = SSL_3p0 || x = TLS_1p0 -> correct (conn_state, encrypted)
    | _ -> unexpectedError "[encrypt_block] invoked on non BlockCipherState"

let encrypt conn_state data =
    match conn_state.sparams.cipher_type with 
    | CT_stream -> encrypt_stream conn_state data
    | CT_block -> encrypt_block conn_state data


let generatePacket ct ver data =
  let l = length data in 
  let bct = bytes_of_contentType ct in
  let bver = bytes_of_protocolVersionType ver in
  let bl = bytes_of_int 2 l in
  let dl = [bct;bver;bl;data] in
    appendList dl

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

let send_setVersion conn pv =
    {conn with protocol_version = pv }

let send_setCrypto conn ccs_d =
    let new_dir = outdir ccs_d.ccs_info in
    { rec_info = ccs_d.ccs_info;
      dir = new_dir;
      net_conn = conn.net_conn;
      compression = ccs_d.ccs_comp;
      protocol_version = ccs_d.ccs_pv;
      cipher_state = ccs_d.ccs_ciphstate;
      mk = ccs_d.ccs_mkey;
      seq_num = 0;
      sparams = ccs_d.ccs_sparams}
      
let parse_header header =
  let [x;y;z] = splitList header [1;2] in
  let ct = contentType_of_bytes x in
  let pv = protocolVersionType_of_bytes y in
  let len = int_of_bytes 2 z in
  (ct,pv,len)

let get_iv_ciphertext version bulk_cipher_algorithm iv ciphertext =
    let bs = get_block_cipher_size bulk_cipher_algorithm in
    match version with
    | x when x = TLS_1p1 || x = TLS_1p2 -> (iv,ciphertext)
    | x when x = SSL_3p0 || x = TLS_1p0 -> (split ciphertext bs)
    | x when x = UnknownPV -> unexpectedError "[get_iv_ciphertext] Protocol version must be known when getting the IV"
    | x when x = SSL_2p0 -> unexpectedError "[get_iv_ciphertext] Unsupported protocol version, but the caller should ensure we are not called."


let decrypt_fun block_cipher_algorithm key iv data  =
    match block_cipher_algorithm with
        | BCA_des -> des_decrypt_wiv key iv data
        | BCA_aes -> aes_decrypt_wiv key iv data
        | _ -> Error (Encryption, Unsupported) (* FIXME: other block BCAs are truly unsupported, but other stream BCAs (e.g. null) are in fact "unexpectedErrors" *)

let block_decrypt conn_state data = 
    match conn_state.cipher_state with
    | BlockCipherState (key,iv) ->
        (let ver = conn_state.protocol_version in
        match ver with
        | SSL_2p0 -> Error(Encryption,Unsupported)
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
       Check that the compressed fragment has the correct
       maximum length *)
    let sp = conn_state.sparams in
    match sp.cipher_type with
    | CT_stream ->
        match sp.bulk_cipher_algorithm with
        | BCA_null -> check_length payload max_TLSCompressed_fragment_length (conn_state, payload) Encryption
        | _ -> Error (Encryption, Unsupported) (* FIXME: other stream BCAs are truly unsupported, but other block BCAs (e.g. aes, des) are in fact "unexpectedErrors" *)
    | CT_block -> block_decrypt conn_state payload 

let check_padding_cont (data:bytes)  =
   correct (data)

let check_padding version (data:bytes) =
    let dlen = length data in
    let (tmpdata, padlenb) = split data (dlen - 1) in
    let padlen = int_of_bytes 1 padlenb in
    let padstart = dlen - padlen - 1 in
    let (data_no_pad,pad) = split tmpdata padstart in
    match version with
    | v when v = TLS_1p0 || v = TLS_1p1 || v = TLS_1p2 ->
        let expected = createBytes padlen padlen in
        if equalBytes expected pad then
            check_padding_cont data_no_pad
        else
            (* in TLS1.0 we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
            if  v = TLS_1p0 then
                Error (RecordPadding,CheckFailed)
            else
                (* Pretend we have a valid padding of length zero *)
                check_padding_cont data
    | SSL_3p0 ->
        (* Padding is random in SSL_3p0, no check to be done *)
        check_padding_cont data_no_pad
    | SSL_2p0 -> Error(RecordPadding,Unsupported)
    | UnknownPV -> unexpectedError "[check_padding] Protocol version should be known when checking the padding."

let parse_plaintext conn_state data =
    let result_depadding =
        match conn_state.sparams.cipher_type with
        | CT_block -> check_padding conn_state.protocol_version data
        | CT_stream -> correct (data)
    match result_depadding with
    | Error (x,y) -> Error (x,y)
    | Correct data_no_pad ->
        let hash_size = get_hash_size conn_state.sparams.mac_algorithm in
        let mac_start = (length data_no_pad) - hash_size in
        correct (split data_no_pad mac_start)

let verify_mac conn ct compr givenmac =
    let mac_alg = conn.sparams.mac_algorithm in
    if mac_alg = MA_null then
        if equalBytes givenmac empty_bstr then
            correct ()
        else
            Error (MAC, CheckFailed)
    else
        let version = conn.protocol_version in
        let mac_key = conn.mk in
        let bseq_num = bytes_of_seq conn.seq_num in
        let bct = bytes_of_contentType ct in
        let bver = bytes_of_protocolVersionType version in
        match version with
        | SSL_3p0 ->
            let mmsg = compute_mac_ssl_blob bseq_num bct compr in
            match mac_alg with
            | MA_md5 ->
                keyedHashVerify md5 ssl_pad1_md5 ssl_pad2_md5 mac_key mmsg givenmac
            | MA_sha1 ->
                keyedHashVerify sha1 ssl_pad1_sha1 ssl_pad2_sha1 mac_key mmsg givenmac
            | _ -> Error (MAC, Unsupported)
        | v when v = TLS_1p0 || v = TLS_1p1 || v = TLS_1p2 ->
            let data = compute_mac_tls_blob bseq_num bct bver compr in
            match mac_alg with
            | MA_md5 -> hmacmd5Verify mac_key data givenmac
            | MA_sha1 -> hmacsha1Verify mac_key data givenmac
            | _ -> Error (MAC, Unsupported)
        | UnknownPV -> 
            unexpectedError "[verify_mac] only to be invoked after a version has been negotiated"
        | SSL_2p0 -> Error (MAC, Unsupported)
 
let recv conn =
    let net = conn.net_conn in
    match Tcp.read net 5 with
    | Error (x,y) -> Error (x,y)
    | Correct header ->
    let (ct,pv,len) = parse_header header in
    if (conn.protocol_version <> UnknownPV && pv <> conn.protocol_version) || pv = UnknownPV then
        Error (RecordVersion,CheckFailed)
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

let dataAvailable conn =
    Tcp.dataAvailable conn.net_conn

let recv_setVersion conn pv =
    {conn with protocol_version = pv}

let recv_checkVersion conn pv =
    if pv = conn.protocol_version then
        correct ()
    else
        Error(RecordVersion,CheckFailed)

let recv_setCrypto conn ccs_d =
    let new_dir = indir ccs_d.ccs_info;
    { rec_info = ccs_d.ccs_info;
      dir = new_dir;
      net_conn = conn.net_conn;
      compression = ccs_d.ccs_comp;
      protocol_version = ccs_d.ccs_pv;
      cipher_state = ccs_d.ccs_ciphstate;
      mk = ccs_d.ccs_mkey;
      seq_num = 0;
      sparams = ccs_d.ccs_sparams;
    }

let coherentrw given recv send =
    given = recv.rec_info && given = send.rec_info