module Record

open Bytes
open Error
open TLSInfo
open Formats
open CipherSuites
open TLSFragment

type ConnectionState =
    | NullState
    | SomeState of history * StatefulAEAD.state

type sendState = ConnectionState
type recvState = ConnectionState

let initConnState (ki:epoch) s =
  SomeState(emptyHistory ki,s)

let nullConnState (ki:epoch) = NullState

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
    if len <= 0 || len > DataStream.max_TLSCipher_fragment_length then
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
    if len <= 0 || len > DataStream.max_TLSCipher_fragment_length then
        Error(Parsing,CheckFailed)
    else
        correct(ct,pv,len)

(* This replaces send. It's not called send, since it doesn't send anything on the
   network *)
let recordPacketOut ki conn pv rg ct fragment =
    (* No need to deal with compression. It is handled internally by TLSPlain,
       when returning us the next (already compressed!) fragment *)
    (*
    match make_compression conn.rec_ki.sinfo fragment with
    | Error (x,y) -> Error (x,y)
    | Correct compressed ->
    *)
    let si = epochSI(ki) in
    match (si.cipher_suite, conn) with
    | (x,NullState) when isNullCipherSuite x ->
        let payload = fragmentRepr ki ct (emptyHistory ki) rg fragment in
        let packet = makePacket ct pv payload in
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
    | (_,SomeState(history,state)) ->
        let ad = makeAD ki ct in
        let sh = StatefulAEAD.history ki state in
        let aeadF = TLSFragmentToFragment ki ct history sh rg fragment in

        let (state,payload) = StatefulAEAD.encrypt ki state ad rg aeadF in
        let ff = StatefulPlain.contents ki sh ad rg aeadF in
        let history = addToHistory ki ct history rg ff in
        let conn = SomeState(history,state) in
        let packet = makePacket ct pv payload in
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

let recordPacketIn ki conn headPayload =
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
    let si = epochSI(ki) in
    let cs = si.cipher_suite in
    match (cs,conn) with
    | (x,NullState) when isNullCipherSuite x ->
        let rg = (plen,plen) in
        let msg = fragmentPlain ki ct (emptyHistory ki) rg payload in
        correct(conn,ct,pv,rg,msg)
// MACOnly is now handled within AEAD
//    | (x,RecordMACKey(key)) when isOnlyMACCipherSuite x ->
//        let ad0 = TLSFragment.makeAD epochSI(ki).protocol_version ct in
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
    | (x,SomeState(history,state)) ->
        let ad = makeAD ki ct in
        let decr = StatefulAEAD.decrypt ki state ad payload in
        match decr with
        | Error(x,y) -> Error(x,y)
        | Correct (decrRes) ->
            let (newState, rg, plain) = decrRes in
            let nh = StatefulAEAD.history ki state in
            let ff = StatefulPlain.contents ki nh ad rg plain in
            let msg = fragmentToTLSFragment ki ct history nh rg plain in
            let history = addToHistory ki ct history rg ff in
            let conn = SomeState(history,newState) in
            correct(conn,ct,pv,rg,msg)
    | _ -> unexpectedError "[recordPacketIn] Incompatible ciphersuite and key type"
