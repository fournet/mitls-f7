module Dispatch

open Bytes
open Formats
open Record
open Tcp
open Error
open Handshake
open AppData
open Alert
open TLSInfo
open AppCommon
open SessionDB

type predispatchState =
  | Init (* of ProtocolVersionType * ProtocolVersionType *) (* min and max *)
  | FirstHandshake (* of ProtocolVersionType *)             (* set by the ServerHello *) 
  | Finishing
  | Finished (* Only for Writing side, used to avoid sending data on a partially completed handshake *)
  | Open
  | Closing
  | Closed

type dispatchState = predispatchState

type dState = {
    disp: dispatchState;
    conn: ConnectionState;
    }

type preConnection = {
  ds_info : SessionInfo;
  poptions: protocolOptions;
  (* abstract protocol states for HS/CCS, AL, and AD *)
  handshake: Handshake.hs_state
  alert    : Alert.al_state
  appdata  : AppData.app_state    

  (* connection state for reading and writing *)
  read  : dState;
  write : dState;

  (* The actual socket *)
  ns: NetworkStream;
  }

type Connection = preConnection

type preds = DebugPred of Connection

let init ns dir poptions =
    (* Direction "dir" is always the outgouing direction.
       So, if we are a Client, it will be CtoS, if we're a Server: StoC *)
    let hs = Handshake.init_handshake dir poptions in
    let (outKI,inKI) = (init_KeyInfo init_sessionInfo dir, init_KeyInfo init_sessionInfo (dualDirection dir)) in
    let (send,recv) = Record.create outKI inKI poptions.minVer in
    let read_state = {disp = Init; conn = recv} in
    let write_state = {disp = Init; conn = send} in
    let al = Alert.init init_sessionInfo  in
    let app = AppData.init init_sessionInfo dir in
    { ds_info = init_sessionInfo;
      poptions = poptions;
      handshake = hs;
      alert = al;
      appdata = app;
      read = read_state;
      write = write_state;
      ns=ns;}

let resume ns sid ops =
    (* Only client side, can never be server side *)

    (* Ensure the sid is in the SessionDB, and it is for a client *)
    match select ops sid with
    | None -> unexpectedError "[resume] requested session expired or never stored in DB"
    | Some (retrievedStoredSession) ->
    match retrievedStoredSession.dir with
    | StoC -> unexpectedError "[resume] requested session is for server side"
    | CtoS ->
    let sinfo = retrievedStoredSession.sinfo in
    let hs = Handshake.resume_handshake sinfo retrievedStoredSession.ms ops in
    let (outKI,inKI) = (init_KeyInfo init_sessionInfo CtoS, init_KeyInfo init_sessionInfo StoC) in
    let (send,recv) = Record.create outKI inKI ops.minVer in
    let read_state = {disp = Init; conn = recv} in
    let write_state = {disp = Init; conn = send} in
    let al = Alert.init init_sessionInfo  in
    let app = AppData.init init_sessionInfo CtoS in
    let res = { ds_info = init_sessionInfo;
                poptions = ops;
                handshake = hs;
                alert = al;
                appdata = app;
                read = read_state;
                write = write_state;
                ns = ns;}
    let unitVal = () in
    (correct (unitVal), res)

let ask_rehandshake conn ops =
    let new_hs = Handshake.start_rehandshake conn.handshake ops in
    {conn with handshake = new_hs
               poptions = ops}

let ask_rekey conn ops =
    let new_hs = Handshake.start_rekey conn.handshake ops in
    {conn with handshake = new_hs
               poptions = ops}

let ask_hs_request conn ops =
    let new_hs = Handshake.start_hs_request conn.handshake ops in
    {conn with handshake = new_hs
               poptions = ops}

(*
let appDataAvailable conn =
    AppData.retrieve_data_available conn.appdata
*)

let getSessionInfo conn =
    conn.ds_info
   
let moveToOpenState c new_storable_info =
    (* If appropriate, store this session in the DB *)
    match new_storable_info.sinfo.sessionID with
    | None -> (* This session should not be stored *) ()
    | Some (sid) -> (* SessionDB. *) insert c.poptions sid new_storable_info

    let new_info = new_storable_info.sinfo in
    let new_hs = Handshake.new_session_idle c.handshake new_info new_storable_info.ms in
    let new_alert = Alert.init new_info in
    let new_appdata = AppData.set_SessionInfo c.appdata new_info in (* buffers have already been reset when each record layer direction did the CCS *)
    (* Read and write state should already have the same SessionInfo
        set after CCS, check it *)
    let c = {c with ds_info = new_info;
                    handshake = new_hs;
                    alert = new_alert;
                    appdata = new_appdata} in
    let read = c.read in
    match read.disp with
    | Finishing ->
        let new_read = {read with disp = Open} in
        let c_write = c.write in
        match c_write.disp with
        | Finishing ->
            let new_write = {c_write with disp = Open} in
            {c with read = new_read; write = new_write}
        | Finished ->
            let new_write = {c_write with disp = Open} in
            {c with read = new_read; write = new_write}
        | _ -> unexpectedError "[moveToOpenState] should only work on Finishing or Finished write states"
    | Finished ->
        let new_read = {read with disp = Open} in
        let c_write = c.write in
        match c_write.disp with
        | Finishing ->
            let new_write = {c_write with disp = Open} in
            {c with read = new_read; write = new_write}
        | Finished ->
            let new_write = {c_write with disp = Open} in
            {c with read = new_read; write = new_write}
        | _ -> unexpectedError "[moveToOpenState] should only work on Finishing or Finished write states"
    | _ -> unexpectedError "[moveToOpenState] should only work on Finishing read states"

let closeConnection c =
    let new_read = {c.read with disp = Closed} in
    let new_write = {c.write with disp = Closed} in
    {c with read = new_read; write = new_write}

(* Dispatch dealing with network sockets *)
let send ns conn tlen ct frag =
    let (conn,data) = Record.recordPacketOut conn tlen ct frag in
    match Tcp.write ns data with
    | Error(x,y) -> Error(x,y)
    | Correct(_) -> 
        printf "%s(%d) " (CTtoString ct) tlen 
        correct(conn)

(* which fragment should we send next? *)
(* we must send this fragment before restoring the connection invariant *)
let next_fragment (c:Connection) : (bool Result) * Connection =
  let c_write = c.write in
  match c_write.disp with
  | Closed -> unexpectedError "[next_fragment] should never be invoked on a closed connection."
  | _ ->
      let al_state = c.alert in
      match Alert.next_fragment al_state with
      | (EmptyALFrag,_) -> 
          let hs_state = c.handshake in
          match Handshake.next_fragment hs_state with 
          | (EmptyHSFrag, _) ->
            let app_state = c.appdata in
                match AppData.next_fragment app_state with
                | None -> (* nothing to do (tell the caller) *)
                          (correct (false),c)
                | Some ((tlen,f),new_app_state) ->
                          match c_write.disp with
                          | Open ->
                          (* we send some data fragment *)
                            match send c.ns c_write.conn tlen Application_data f with
                            | Correct(ss) ->
                                let new_write = { c_write with conn = ss } in
                                (correct (true), { c with appdata = new_app_state;
                                                          write = new_write } )
                            | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)
                          | _ -> (Error(Dispatcher,InvalidState), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
          | (CCSFrag((tlen,ccs),ccs_data),new_hs_state) ->
                    (* we send a (complete) CCS fragment *)
                    match c_write.disp with
                    | x when x = FirstHandshake || x = Open ->
                        match send c.ns c_write.conn tlen Change_cipher_spec ccs with
                        | Correct ss -> 
                            (* we change the CS immediately afterward *)
                            let ss = Record.send_setCrypto ccs_data in
                            let new_write = {disp = Finishing; conn = ss} in
                            (* FIXME: What if the outgoing buffer was not empty? How do we notify the user that not all
                               the committed data were sent? If we assume some sort of synch between protocol re-handshakes and
                               app data, at least when re-keying we should not empty this buffer. *)
                            let new_appdata = AppData.reset_outgoing c.appdata in
                            (* FIXME: we should update the ("outgoing" only) session info in alert protocol too, because
                               from now on, outgoing alerts should be issued for the new session info, even if the latter is
                               not confirmed to be safe yet.
                               Note that the hansdhake is already doing this, by using its "next_info" to issue data after the CCS
                               has been sent.
                               Re AppData, from now on it just cannot send any message anymore, until the upcoming
                               session info becomes valid (HSFullyFinished event).
                               (This is what the Finishing dispatch state stands for.) *)
                            (correct (true), { c with handshake = new_hs_state;
                                                      write = new_write;
                                                      appdata = new_appdata } )
                        | Error (x,y) -> (Error (x,y), closeConnection c) (* Unrecoverable error *)
                    | _ -> (Error(Dispatcher, InvalidState), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
          | (HSFrag((tlen,f)),new_hs_state) ->     
                      (* we send some handshake fragment *)
                      match c_write.disp with
                      | x when x = Init || x = FirstHandshake ||
                               x = Finishing || x = Open ->
                          match send c.ns c_write.conn tlen Handshake f with 
                          | Correct(ss) ->
                            let new_write = {c_write with conn = ss} in
                            (correct (true), { c with handshake = new_hs_state;
                                                      write     = new_write } )
                          | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)
                      | _ -> (Error(Dispatcher,InvalidState), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
          | (HSWriteSideFinished((tlen,lastFrag)),new_hs_state) ->
                (* check we are in finishing state *)
                match c_write.disp with
                | Finishing ->
                    (* Send the last fragment *)
                    match send c.ns c_write.conn tlen Handshake lastFrag with 
                          | Correct(ss) ->
                            let c_write = {c_write with conn = ss} in
                            let c = { c with handshake = new_hs_state;
                                             write     = c_write }
                            (* Move to the new state *)
                            let c_write = {c_write with disp = Finished}
                            let c = {c with write = c_write} in
                            (correct (false), c)
                          | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)
                | _ -> (Error(Dispatcher,InvalidState), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
          | (HSFullyFinished_Write((tlen,lastFrag),new_info),new_hs_state) ->
                match c_write.disp with
                | Finishing ->
                   (* according to the protocol logic and the dispatcher
                      implementation, we must now have an empty input buffer.
                      This means we can directly report a NewSessionInfo error
                      notification, and not a mustRead.
                      Check thus that we in fact have an empty input buffer *)
                   if not (AppData.is_incoming_empty c.appdata) then (* this is a bug. *)
                       (Error(Dispatcher,Internal), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
                   else
                       (* Send the last fragment *)
                       match send c.ns c_write.conn tlen Handshake lastFrag with 
                       | Correct(ss) ->
                         let new_write = {c_write with conn = ss} in
                         let c = { c with handshake = new_hs_state;
                                          write     = new_write }
                         (* Move to the new state *)
                         let c = moveToOpenState c new_info in
                         (Error(NewSessionInfo,Notification),c)
                       | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)
                | _ -> (Error(Dispatcher,InvalidState), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
      | (ALFrag(tlen,f),new_al_state) ->        
        match send c.ns c_write.conn tlen Alert f with 
        | Correct ss ->
            let new_write = {disp = Closing; conn = ss} in
            (correct (true), { c with alert = new_al_state;
                                      write   = new_write } )
        | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)
      | (LastALFrag(tlen,f),new_al_state) ->
        (* Same as above, but we set Closed dispatch state, instead of Closing *)
        match send c.ns c_write.conn tlen Alert f with 
        | Correct ss ->
            let new_write = {disp = Closed; conn = ss} in
            (* FIXME: if also the reading state is closed, return an error to notify the user
               that the communication is over. Otherwise we can enter infinte loops polling for data
               that will never arrive *)
            (correct (false), { c with alert = new_al_state;
                                       write   = new_write } )
        | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)

let rec writeOneAppFragment c =
    (* Writes *at most* one application data fragment. This might send no appdata fragment if
       - The handshake finishes (write side or fully)
       - An alert has been sent
     *)
    let unitVal = () in
    let c_write = c.write in
    match c_write.disp with
    | Closed -> (correct(unitVal),c)
    | _ ->
        match next_fragment c with
        | (Error (x,y),c) -> (Error(x,y),c)
        | (Correct (again),c) ->
        if again then
            (* be fair: don't do more sending now if we could read *)
            (* note: eventually all buffered data will be sent, they're are already committed
                        to be sent *)
            match Tcp.dataAvailable c.ns with
            | Error (x,y) -> (correct (unitVal),c) (* There's an error with TCP, but we can ignore it right now, and just pretend there are data to send, so the error will show up next time *)
            | Correct dataAv ->
            if dataAv then
                (correct(unitVal),c)
            else
                writeOneAppFragment c 
        else
            (correct (unitVal),c)

(* we have received, decrypted, and verified a record (ct,f); what to do? *)
let deliver ct tlen f c = 
  let c_read = c.read in
  match c_read.disp with
  | Closed -> unexpectedError "[deliver] should never be invoked on a closed connection state."
  | _ ->
  match (ct,c_read.disp) with 

  | Handshake, x when x = Init || x = FirstHandshake || x = Finishing || x = Open ->
    match Handshake.recv_fragment c.handshake tlen f with
    | (Correct(corr),hs) ->
        match corr with
        | HSAck ->
            ((correct (true), { c with handshake = hs} ))
        | HSChangeVersion(r,v) ->
            match c_read.disp with
            | Init ->
                (* Then, also c_write must be in Init state. It means this is the very first, unprotected handshake,
                   and we just negotiated the version. Tell the record layer which version to use; and move to the
                   FirstHandshake state *)
                match r with
                | CtoS ->
                    match Record.recv_checkVersion c_read.conn v with
                    | Correct (dummy) ->
                        let c_read = {c_read with disp = FirstHandshake} in
                        (* Also update the protocol version on the writing side of the record *)
                        let new_write_conn = Record.send_setVersion c.write.conn v in
                        let new_write = {c.write with conn = new_write_conn
                                                      disp = FirstHandshake} in
                        (correct (true), { c with handshake = hs;
                                                  read = c_read;
                                                  write = new_write} )
                    | Error(x,y) -> (Error(x,y), {c with handshake = hs} )
                | StoC ->
                    let new_recv = Record.recv_setVersion c_read.conn v in
                    let new_read = {c_read with conn = new_recv
                                                disp = FirstHandshake} in
                    let new_send = Record.send_setVersion c.write.conn v in
                    let new_write = {c.write with conn = new_send
                                                  disp = FirstHandshake} in
                    (correct (true), { c with handshake = hs;
                                              read = new_read;
                                              write = new_write} )
            | _ -> (* It means we are doing a re-negotiation. Don't alter the current version number at the record layer, because it
                     is perfectly valid. It will be updated after the next CCS, along with all other session parameters *)
                ((correct (true), { c with handshake = hs} ))
        | HSReadSideFinished ->
        (* Ensure we are in Finishing state *)
            match x with
            | Finishing ->
                (* We stop reading now. The subsequent writes invoked after
                   reading will send the appropriate handshake messages, and
                   the handshake will be fully completed *)
                (correct (false),{c with handshake = hs})
            | _ -> (Error(Dispatcher,InvalidState), {c with handshake = hs} )
        | HSFullyFinished_Read(new_info) ->
            let c = {c with handshake = hs} in
            (* Ensure we are in Finishing state *)
            match x with
            | Finishing ->
                let c = moveToOpenState c new_info in
                (Error(NewSessionInfo,Notification),c)
            | _ -> (Error(Dispatcher,InvalidState), c)
    | (Error(x,y),hs) -> (Error(x,y),{c with handshake = hs}) (* TODO: we might need to send some alerts *)

  | Change_cipher_spec, x when x = FirstHandshake || x = Open -> 
    match Handshake.recv_ccs c.handshake tlen f with 
    | (Correct(cryptoparams),hs) ->
        let new_recv = Record.recv_setCrypto cryptoparams in
        let new_read = {disp = Finishing; conn = new_recv} in
        (* Next statement should have no effect, since we should reach this
           code always with an empty input buffer *)
        let new_appdata = AppData.reset_incoming c.appdata in
        (correct (true), { c with handshake = hs;
                                  read = new_read;
                                  appdata = new_appdata} )
    | (Error (x,y),hs) -> (Error (x,y), {c with handshake = hs})

  | Alert, x ->
    match Alert.recv_fragment c.alert tlen f with
    | Correct (ALAck(state)) ->
      (correct (true), { c with alert = state})
    | Correct (ALClose_notify (state)) ->
        (* An outgoing close notify has already been buffered, if necessary *)
        (* Only close the reading side of the connection *)
        let new_read = {c_read with disp = Closed} in
        (correct (false), { c with read = new_read})
    | Correct (ALClose (state)) ->
        (* Other fatal alert, we close both sides of the connection *)
        let new_read = {c_read with disp = Closed} in
        let new_write = {c.write with disp = Closed} in
        (* FIXME: this generates an infinite loop. We should report an error to the user instead *)
        (correct (false), { c with read = new_read;
                                   write = new_write} )
    | Error (x,y) -> (Error(x,y),c) (* Always fatal, so don't need to track the current alert state? *)

  | Application_data, Open -> 
    let appstate = AppData.recv_fragment c.appdata tlen f in
    (correct (false), { c with appdata = appstate })
  | UnknownCT, _ -> (Error(Dispatcher,Unsupported),c)
  | _, _ -> (Error(Dispatcher,InvalidState),c)

//CF can we move header parsing/unparsing to Formats?
let parse_header header =
  (* Mostly the same as Record.parse_header,
     but here we don't perform any check on the protcol version *)
  let (ct1,rem4) = split header 1 in
  let (pv2,len2) = split rem4 2 in
  let ct = contentType_of_byte ct1.[0] in
  let pv = CipherSuites.protocolVersionType_of_bytes pv2 in
  let len = int_of_bytes len2 in
  (ct,pv,len)

let recv ns readState =
    match Tcp.read ns 5 with
    | Error (x,y) -> Error (x,y)
    | Correct header ->
        let (ct,pv,len) = parse_header header in
        (* No need to check len, since it's on 2 bytes and the max allowed value
           is 2^16. So, here len is always safe *)
        match Tcp.read ns len with 
        | Error (x,y) -> Error (x,y) 
        | Correct payload ->
            let fullMsg = header @| payload in
            printf "%s[%d] " (Formats.CTtoString ct) len;
            Record.recordPacketIn readState fullMsg
            // Could we instead call record on ct,pv,payload?

let rec readNextAppFragment conn =
    (* If available, read next data *)
    let c_read = conn.read in
    match c_read.disp with
    | Closed -> writeOneAppFragment conn
    | _ ->
    match Tcp.dataAvailable conn.ns with
    | Error (x,y) -> (Error(x,y),conn)
    | Correct canRead ->
    if canRead then
        match recv conn.ns c_read.conn with
        | Error (x,y) -> (Error (x,y),conn) (* TODO: if TCP error, return the error; if recoverable Record error, send Alert *)
        | Correct res ->
        let (recvSt,ct,tlen,f) = res in
        let new_read = {c_read with conn = recvSt} in
        let conn = {conn with read = new_read} in (* update the connection *)
        match deliver ct tlen f conn with
        | (Error (x,y),conn) -> (Error(x,y),conn)
        | (Correct (again),conn) ->
        if again then
            (* we just read non app-data, let's read more *)
            readNextAppFragment conn
        else
            (* We either read app-data, or a complete fatal alert,
               send buffered data *)
            writeOneAppFragment conn
    else
        (* Nothing to read, possibly send buffered data *)
        writeOneAppFragment conn

let commit conn b =
    let new_appdata = AppData.send_data conn.appdata b in
    {conn with appdata = new_appdata}

let write_buffer_empty conn =
    AppData.is_outgoing_empty conn.appdata

let readOneAppFragment conn =
    (* Similar to the OpenSSL strategy *)
    let c_appdata = conn.appdata in
    if not (AppData.is_incoming_empty c_appdata) then
        (* Read from the buffer *)
        let (read, new_appdata) = AppData.retrieve_data c_appdata in
        let conn = {conn with appdata = new_appdata} in
        (correct (read),conn)
    else
        (* Read from the TCP socket *)
        match readNextAppFragment conn with
        | (Correct (x),conn) ->
            (* One fragment may have been put in the buffer *)
            let c_appdata = conn.appdata in
            let (read, new_appdata) = AppData.retrieve_data c_appdata in
            let conn = {conn with appdata = new_appdata} in
            (correct (read),conn)
        | (Error (x,y),c) -> (Error(x,y),c)