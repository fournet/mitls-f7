module Record

open Bytes
open Error
open TLSInfo
open TLSKey
open Formats
open CipherSuites
open StatefulPlain

type ConnectionState = {
  key: recordKey;
  state: state option;
}
type sendState = ConnectionState
type recvState = ConnectionState

let connState (ki:KeyInfo) (cs:ConnectionState) = 
  match cs.state with 
    | Some s -> s
    | None -> failwith "expected a valid AEAD state"

let initConnState (ki:KeyInfo) (ccsData:ccs_data) =
  let rk = ccsData.ccsKey in 
  match rk with 
    | RecordAEADKey k -> {key = rk; state = Some (initState ki k ccsData.ccsIV3)}
    | NoneKey -> {key = rk; state = None}

/// packet format

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
    if len <= 0 || len > FragCommon.max_TLSCipher_fragment_length then
        Error(Parsing,CheckFailed)
    else
        correct(len)

let parseHeader b = 
    let (ct1,rem4) = split b 1 in
    let (pv2,len2) = split rem4 2 in 
    match parseCT ct1 with
    | Error(x,y) -> Error(x,y)
    | Correct(ct) ->
    match CipherSuites.parseVersion pv2 with
    | Error(x,y) -> Error(x,y)
    | Correct(pv) -> 
    let len = int_of_bytes len2 in
    // With a precise int/byte model,
    // no need to check len, since it's on 2 bytes and the max allowed value is 2^16.
    // Here we do a runtime check to get the same property statically
    if len <= 0 || len > FragCommon.max_TLSCipher_fragment_length then
        Error(Parsing,CheckFailed)
    else
        correct(ct,pv,len)

(* This replaces send. It's not called send, since it doesn't send anything on the
   network *)
let recordPacketOut keyInfo conn tlen seqn ct fragment =
    (* No need to deal with compression. It is handled internally by TLSPlain,
       when returning us the next (already compressed!) fragment *)
    (*
    match make_compression conn.rec_ki.sinfo fragment with
    | Error (x,y) -> Error (x,y)
    | Correct compressed ->
    *)
    match (keyInfo.sinfo.cipher_suite, conn.key) with
    | (x,NoneKey) when isNullCipherSuite x ->
        let payload = TLSFragment.TLSFragmentRepr keyInfo ct (TLSFragment.emptyHistory keyInfo)  tlen fragment in
        let packet = makePacket ct keyInfo.sinfo.protocol_version payload in
        (conn,packet)
// MACOnly is now handled within AEAD
//    | (x,RecordMACKey(key)) when isOnlyMACCipherSuite x ->
//        let ad0 = TLSFragment.makeAD keyInfo.sinfo.protocol_version ct in
//        let addData = StatefulPlain.makeAD seqn ad0 in
//        let aeadSF = StatefulPlain.TLSFragmentToFragment keyInfo tlen seqn ct fragment in
//        let st = connState keyInfo conn in
//        let aeadF = AEADPlain.fragmentToPlain keyInfo st addData tlen aeadSF in
//        let data = AEPlain.concat keyInfo tlen addData aeadF in
//        let mac = AEPlain.mac keyInfo key data in
//        // FIXME: next line should be: ley payload = AEPlain.encodeNoPad ..., to match decodeNoPad, and remove dependency on tagRepr
//        let payload = (TLSFragment.TLSFragmentRepr keyInfo ct st.history tlen fragment) @| (AEPlain.tagRepr keyInfo mac) in
//        let packet = makePacket ct keyInfo.sinfo.protocol_version payload in
//        (conn,packet)
    | (_,RecordAEADKey(key)) ->
        let ad0 = TLSFragment.makeAD keyInfo.sinfo.protocol_version ct in
        // let addData = StatefulPlain.makeAD seqn ad0 in // AP: it is invoked within StatefulAEAD
        let aeadF = StatefulPlain.TLSFragmentToFragment keyInfo tlen seqn ct fragment in

        let (nr,payload) = StatefulAEAD.encrypt keyInfo (connState keyInfo conn) ad0 tlen aeadF in

        let conn = {conn with state = Some nr} in
        let packet = makePacket ct keyInfo.sinfo.protocol_version payload in
        (conn,packet)
    | _ -> unexpectedError "[recordPacketOut] Incompatible ciphersuite and key type"
    

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

let recordPacketIn ki conn (seqn:int) headPayload =
    let (header,payload) = split headPayload 5 in
    match parseHeader header with
    | Error(x,y) -> Error(x,y)
    | Correct (parsed) -> 
    let (ct,pv,plen) = parsed in
    // tlen is checked in headerLength, which is invoked by Dispatch
    // before invoking this function
    if length payload <> plen then
        Error(Record,CheckFailed)
    else
    let tlen = (plen,plen) in
    let cs = ki.sinfo.cipher_suite in
    match (cs,conn.key) with
    | (x,NoneKey) when isNullCipherSuite x ->
        let msg = TLSFragment.TLSFragment ki ct (TLSFragment.emptyHistory ki) tlen payload in
        correct(conn,ct,pv,tlen,msg)
// MACOnly is now handled within AEAD
//    | (x,RecordMACKey(key)) when isOnlyMACCipherSuite x ->
//        let ad0 = TLSFragment.makeAD ki.sinfo.protocol_version ct in
//        let ad = StatefulPlain.makeAD seqn ad0 in
//        let plain = AEPlain.plain ki tlen payload in
//        let (rg,msg,mac) = AEPlain.decodeNoPad ki ad plain in
//        let toVerify = AEPlain.concat ki rg ad msg in
//        let ver = AEPlain.verify ki key toVerify mac in
//        if ver then
//          let msg0 = AEADPlain.plainToFragment ki (connState ki conn) ad rg msg in
//          let msg = StatefulPlain.fragmentToTLSFragment ki (connState ki conn) ad rg msg0 in
//            correct(conn,ct,pv,rg,msg)
//        else
//            Error(MAC,CheckFailed)
    | (x,RecordAEADKey(key)) ->
        let ad0 = TLSFragment.makeAD ki.sinfo.protocol_version ct in
        // let ad = StatefulPlain.makeAD seqn ad0 in // AP: it is invoked within StatefulAEAD
        let decr = StatefulAEAD.decrypt ki (connState ki conn) ad0 payload in
        match decr with
        | Error(x,y) -> Error(x,y)
        | Correct (decrRes) ->
            let (ns, tlen, plain) = decrRes in
            let msg = StatefulPlain.fragmentToTLSFragment ki (connState ki conn) ad0 tlen plain in
            let conn = {conn with state = Some ns} in
            correct(conn,ct,pv,tlen,msg)
    | _ -> unexpectedError "[recordPacketIn] Incompatible ciphersuite and key type"
