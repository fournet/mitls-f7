module Dispatch

open Data
open Formats
open Record
open Tcp
open Error_handling
open Handshake
open AppData
open Alert
open Sessions
open AppCommon

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
  ds_info: SessionInfo;
  poptions: protocolOptions;
  (* abstract protocol states for HS/CCS, AL, and AD *)
  handshake: Handshake.hs_state
  alert    : Alert.al_state
  appdata  : AppData.app_state    

  (* connection state for reading and writing *)
  read  : dState;
  write : dState;
  }

type Connection = preConnection

type preds = DebugPred of Connection

let init ns role poptions =
    let (info,hs) = Handshake.init_handshake role poptions in
    let (send,recv) = Record.create ns info poptions.minVer in
    let read_state = {disp = Init; conn = recv} in
    let write_state = {disp = Init; conn = send} in
    let al = Alert.init info  in
    let app = AppData.init info in
    { ds_info = info;
      poptions = poptions;
      handshake = hs;
      alert = al;
      appdata = app;
      read = read_state;
      write = write_state}

let resume ns info ops =
    let hs = Handshake.resume_handshake info ops in
    let (send,recv) = Record.create ns info ops.minVer in
    let read_state = {disp = Init; conn = recv} in
    let write_state = {disp = Init; conn = send} in
    let al = Alert.init info  in
    let app = AppData.init info in
    let res = { ds_info = info;
                poptions = ops;
                handshake = hs;
                alert = al;
                appdata = app;
                read = read_state;
                write = write_state}
    let unitVal = () in
    match info.role with
    | ClientRole -> (correct (unitVal), res)
    | ServerRole -> (Error(Dispatcher,WrongInputParameters),res)

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

let appDataAvailable conn =
    AppData.retrieve_data_available conn.appdata

let getSessionInfo conn =
    conn.ds_info
   
let moveToOpenState c new_info =
    let new_hs = Handshake.new_session_idle c.handshake new_info in
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

(* which fragment should we send next? *)
(* we must send this fragment before restoring the connection invariant *)
let next_fragment n (c:Connection) : (bool Result) * Connection =
  let c_write = c.write in
  match c_write.disp with
  | Closed -> unexpectedError "[next_fragment] should never be invoked on a closed connection."
  | _ ->
      let al_state = c.alert in
      match Alert.next_fragment al_state n with
      | (EmptyALFrag,_) -> 
          let hs_state = c.handshake in
          match Handshake.next_fragment hs_state n with 
          | (EmptyHSFrag, _) ->
            let app_state = c.appdata in
                match AppData.next_fragment app_state n with
                | None -> (* nothing to do (tell the caller) *)
                          (correct (false),c)
                | Some x ->
                          let (f,new_app_state) = x in
                          match c_write.disp with
                          | Open ->
                          (* we send some data fragment *)
                            match Record.send c_write.conn Application_data f with
                            | Correct(ss) ->
                                let new_write = { c_write with conn = ss } in
                                (correct (true), { c with appdata = new_app_state;
                                                          write = new_write } )
                            | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)
                          | _ -> (Error(Dispatcher,InvalidState), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
          | (CCSFrag(ccs,cp),new_hs_state) ->
                    (* we send a (complete) CCS fragment *)
                    match c_write.disp with
                    | x when x = FirstHandshake || x = Open ->
                        match Record.send c_write.conn Change_cipher_spec ccs with
                        | Correct ss -> 
                            (* we change the CS immediately afterward *)
                            let ss = Record.send_setCrypto ss cp in
                            let new_write = {disp = Finishing; conn = ss} in
                            let new_appdata = AppData.reset_outgoing c.appdata in
                            (correct (true), { c with handshake = new_hs_state;
                                                      write = new_write;
                                                      appdata = new_appdata } )
                        | Error (x,y) -> (Error (x,y), closeConnection c) (* Unrecoverable error *)
                    | _ -> (Error(Dispatcher, InvalidState), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
          | (HSFrag(f),new_hs_state) ->     
                      (* we send some handshake fragment *)
                      match c_write.disp with
                      | x when x = Init || x = FirstHandshake ||
                               x = Finishing || x = Open ->
                          match Record.send c_write.conn Handshake f with 
                          | Correct(ss) ->
                            let new_write = {c_write with conn = ss} in
                            (correct (true), { c with handshake = new_hs_state;
                                                      write     = new_write } )
                          | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)
                      | _ -> (Error(Dispatcher,InvalidState), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
          | (HSWriteSideFinished(lastFrag),new_hs_state) ->
                (* check we are in finishing state *)
                match c_write.disp with
                | Finishing ->
                    (* Send the last fragment *)
                    match Record.send c_write.conn Handshake lastFrag with 
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
          | (HSFullyFinished_Write(lastFrag,new_info),new_hs_state) ->
                match c_write.disp with
                | Finishing ->
                   (* according to the protocol logic and the dispatcher
                      implementation, we must now have an empty input buffer.
                      This means we can directly report a NewSessionInfo error
                      notification, and not a mustRead.
                      Check thus that we in fact have an empty input buffer *)
                   if appDataAvailable c then (* this is a bug. *)
                       (Error(Dispatcher,Internal), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
                   else
                       (* Send the last fragment *)
                       match Record.send c_write.conn Handshake lastFrag with 
                       | Correct(ss) ->
                         let new_write = {c_write with conn = ss} in
                         let c = { c with handshake = new_hs_state;
                                          write     = new_write }
                         (* Move to the new state *)
                         let c = moveToOpenState c new_info in
                         (Error(NewSessionInfo,Notification),c)
                       | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)
                | _ -> (Error(Dispatcher,InvalidState), closeConnection c) (* TODO: we might want to send an "internal error" fatal alert *)
      | (ALFrag(f),new_al_state) ->        
        match Record.send c_write.conn Alert f with 
        | Correct ss ->
            let new_write = {disp = Closing; conn = ss} in
            (correct (true), { c with alert = new_al_state;
                                      write   = new_write } )
        | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)
      | (LastALFrag(f),new_al_state) ->
        (* Same as above, but we set Closed dispatch state, instead of Closing *)
        match Record.send c_write.conn Alert f with 
        | Correct ss ->
            let new_write = {disp = Closed; conn = ss} in
            (correct (false), { c with alert = new_al_state;
                                       write   = new_write } )
        | Error (x,y) -> (Error(x,y), closeConnection c) (* Unrecoverable error *)

let rec sendNextFragments c =
    let unitVal = () in
    let c_write = c.write in
    match c_write.disp with
    | Closed -> (correct(unitVal),c)
    | _ ->
        match next_fragment fragmentLength c with
        | (Error (x,y),c) -> (Error(x,y),c)
        | (Correct (again),c) ->
        if again then
            (* be fair: don't do more sending now if we could read *)
            (* note: eventually all buffered data will be sent, they're are already committed
                        to be sent *)
            match Record.dataAvailable c.read.conn with
            | Error (x,y) -> (correct (unitVal),c) (* There's an error with TCP, but we can ignore it right now, and just pretend there are data to send, so the error will show up next time *)
            | Correct dataAv ->
            if dataAv then
                (correct(unitVal),c)
            else
                sendNextFragments c 
        else
            (correct (unitVal),c)

(* we have received, decrypted, and verified a record (ct,f); what to do? *)
let deliver ct f c = 
  let c_read = c.read in
  match c_read.disp with
  | Closed -> unexpectedError "[deliver] should never be invoked on a closed connection state."
  | _ ->
  match (ct,c_read.disp) with 

  | Handshake, x when x = Init || x = FirstHandshake || x = Finishing || x = Open ->
    match Handshake.recv_fragment c.handshake f with
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
                | ClientRole ->
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
                | ServerRole ->
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
    match Handshake.recv_ccs c.handshake f with 
    | (Correct(cryptoparams),hs) ->
        let new_recv = Record.recv_setCrypto c_read.conn cryptoparams in
        let new_read = {disp = Finishing; conn = new_recv} in
        (* Next statement should have no effect, since we should reach this
           code always with an empty input buffer *)
        let new_appdata = AppData.reset_incoming c.appdata in
        (correct (true), { c with handshake = hs;
                                  read = new_read;
                                  appdata = new_appdata} )
    | (Error (x,y),hs) -> (Error (x,y), {c with handshake = hs})

  | Alert, x ->
    match Alert.recv_fragment c.alert f with
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
        (correct (false), { c with read = new_read;
                                   write = new_write} )
    | Error (x,y) -> (Error(x,y),c) (* Always fatal, so don't need to track the current alert state? *)

  | Application_data, Open -> 
    let appstate = AppData.recv_fragment c.appdata f in
    (correct (false), { c with appdata = appstate })
  | UnknownCT, _ -> (Error(Dispatcher,Unsupported),c)
  | _, _ -> (Error(Dispatcher,InvalidState),c)

let rec readNextAppFragment conn =
    (* If available, read next data *)
    let c_read = conn.read in
    match c_read.disp with
    | Closed -> sendNextFragments conn
    | _ ->
    match Record.dataAvailable c_read.conn with
    | Error (x,y) -> (Error(x,y),conn)
    | Correct canRead ->
    if canRead then
        match Record.recv c_read.conn with
        | Error (x,y) -> (Error (x,y),conn) (* TODO: if TCP error, return the error; if recoverable Record error, send Alert *)
        | Correct res ->
        let (ct,f,recvSt) = res in
        let new_read = {c_read with conn = recvSt} in
        let conn = {conn with read = new_read} in (* update the connection *)
        match deliver ct f conn with
        | (Error (x,y),conn) -> (Error(x,y),conn)
        | (Correct (again),conn) ->
        if again then
            (* we just read non app-data, let's read more *)
            readNextAppFragment conn
        else
            (* We either read app-data, or a complete fatal alert,
               send buffered data *)
            sendNextFragments conn
    else
        (* Nothing to read, possibly send buffered data *)
        sendNextFragments conn

let writeOneAppFragment conn d =
    (* FIXME: there's a bug on the writing side:
       In this function, we assume that if sendNextFragments returns
       a correct (_) value, then the app_data fragment has been sent.
       However, sendNextFragments returns correct *without* sending
       any app_data fragment at least in the following cases:
       - An alert has been sent;
       - The wirte-side part of a handshake has finised
         (This used to be a MustRead error, but has been changed, because
         it didn't make sense to return a MustRead error after a read invocation.
         Anyway, all this logic need to be re-though about.)
       We must fix this *)
    let c_write = conn.write in
    match c_write.disp with
    | Finished -> (Error(MustRead,Notification),conn)
    | _ ->
    let (frag,rem) = split d fragmentLength in
    let new_appdata = AppData.send_data conn.appdata frag in
    let conn = {conn with appdata = new_appdata} in
    match sendNextFragments conn with
    | (Correct (x), conn) -> (correct (frag, rem), conn)
    | (Error (x,y), conn) -> (Error(x,y), conn)

let readOneAppFragment conn n =
    (* Similar to the OpenSSL strategy *)
    let c_appdata = conn.appdata in
    if AppData.retrieve_data_available c_appdata then
        (* Read from the buffer *)
        let (read, new_appdata) = AppData.retrieve_data c_appdata n in
        let conn = {conn with appdata = new_appdata} in
        (correct (read),conn)
    else
        (* Read from the TCP socket *)
        match readNextAppFragment conn with
        | (Correct (x),conn) ->
            (* One fragment may have been put in the buffer *)
            let c_appdata = conn.appdata in
            let (read, new_appdata) = AppData.retrieve_data c_appdata n in
            let conn = {conn with appdata = new_appdata} in
            (correct (read),conn)
        | (Error (x,y),c) -> (Error(x,y),c)