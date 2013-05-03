module Record

open Bytes
open Error
open TLSError
open TLSInfo
open TLSConstants
open Range

type ConnectionState =
    | NullState
    | SomeState of TLSFragment.history * StatefulLHAE.state

let someState (ki:epoch) (rw:rw) h s = SomeState(h,s)

type sendState = ConnectionState
type recvState = ConnectionState

let initConnState (ki:epoch) (rw:rw) s = 
  let eh = TLSFragment.emptyHistory ki in
  someState ki rw eh s

let nullConnState (ki:epoch) (rw:rw) = NullState

// packet format
let makePacket ct ver data =
    let l = length data in 
    let bct  = ctBytes ct in
    let bver = versionBytes ver in
    let bl   = bytes_of_int 2 l in
    bct @| bver @| bl @| data

let headerLength b =
    let (ct1,rem4) = split b 1  in
    let (pv2,len2) = split rem4 2 in
    let len = int_of_bytes len2 in
    // With a precise int/byte model,
    // no need to check len, since it's on 2 bytes and the max allowed value is 2^16.
    // Here we do a runtime check to get the same property statically
    if len <= 0 || len > max_TLSCipher_fragment_length then
        Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Wrong fragment length")
    else
        correct(len)

let parseHeader b = 
    let (ct1,rem4) = split b 1 in
    let (pv2,len2) = split rem4 2 in 
    match parseCT ct1 with
    | Error(z) -> Error(z)
    | Correct(ct) ->
    match TLSConstants.parseVersion pv2 with
    | Error(z) -> Error(z)
    | Correct(pv) -> 
    let len = int_of_bytes len2 in
    if len <= 0 || len > max_TLSCipher_fragment_length then
        Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Wrong frgament length")
    else
        correct(ct,pv,len)

(* This replaces send. It's not called send, 
   since it doesn't send anything on the network *)
let recordPacketOut ki conn pv rg ct fragment =
    (* No need to deal with compression. It is handled internally by TLSPlain,
       when returning us the next (already compressed!) fragment *)
    (*TODO
    match make_compression conn.rec_ki.sinfo fragment with
    | Error (x,y) -> Error (x,y)
    | Correct compressed ->
    *)
    let initEpoch = isInitEpoch ki in
    match (initEpoch, conn) with
    | (true,NullState) ->
        let eh = TLSFragment.emptyHistory ki in
        let payload = TLSFragment.repr ki ct eh rg fragment in
        let packet = makePacket ct pv payload in
        (conn,packet)
    | (false,SomeState(history,state)) ->
        let ad = StatefulPlain.makeAD ki ct in
        let sh = StatefulLHAE.history ki Writer state in
        let aeadF = StatefulPlain.RecordPlainToStAEPlain ki ct ad history sh rg fragment in
        let (state,payload) = StatefulLHAE.encrypt ki state ad rg aeadF in
        let history = TLSFragment.extendHistory ki ct history rg fragment in
        let packet = makePacket ct pv payload in
        (SomeState(history,state),
         packet)
    | _ -> unexpected "[recordPacketOut] Incompatible ciphersuite and key type"
    

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
                let key = getLHAEKey conn.key in
                let newIV, payload = LHAE.encrypt conn.rec_ki key conn.iv3 clen ad fragment 
                {conn with iv3 = newIV},
                payload
    incN conn,
    makePacket ct conn.local_pv payload 
*)

let recordPacketIn ki conn headPayload =
    let (header,payload) = split headPayload 5 in
    match parseHeader header with
    | Error(z) -> Error(z)
    | Correct (parsed) -> 
    let (ct,pv,plen) = parsed in
    // tlen is checked in headerLength, which is invoked by Dispatch
    // before invoking this function
    if length payload <> plen then
        let reason = perror __SOURCE_FILE__ __LINE__ "Wrong record packet size" in
        let err = AD_illegal_parameter,reason in
        Error err
    else
    let initEpoch = isInitEpoch ki in
    match (initEpoch,conn) with
    | (true,NullState) ->
        let rg = (plen,plen) in
        let eh = TLSFragment.emptyHistory ki in
        let msg = TLSFragment.plain ki ct eh rg payload in
        correct(conn,ct,pv,rg,msg)
    | (false,SomeState(history,state)) ->
        let ad = StatefulPlain.makeAD ki ct in
        let decr = StatefulLHAE.decrypt ki state ad payload in
        match decr with
        | Error(z) -> Error(z)
        | Correct (decrRes) ->
            let (newState, rg, plain) = decrRes in
            let oldH = StatefulLHAE.history ki Reader state in
            let msg = StatefulPlain.StAEPlainToRecordPlain ki ct ad history oldH rg plain in
            let history = TLSFragment.extendHistory ki ct history rg msg in
            let st' = someState ki Reader history newState in
            correct(st',ct,pv,rg,msg)
    | _ -> unexpected "[recordPacketIn] Incompatible ciphersuite and key type"

let history (e:epoch) (rw:rw) s =
    match s with
    | NullState -> TLSFragment.emptyHistory e
    | SomeState(h,_) -> h

