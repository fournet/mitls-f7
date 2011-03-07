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

type dispatchState =
  | Init (* of ProtocolVersionType * ProtocolVersionType *) (* min and max *)
  | FirstHandshake (* of ProtocolVersionType *)             (* set by the ServerHello *) 
  | Finishing
  | Finished (* Only for Writing side, used to avoid sending data on a partially completed handshake *)
  | Open
  | Closing
  | Closed

type dState = {
    disp: dispatchState;
    conn: ConnectionState;
    }

type Connection = {
  ds_info: SessionInfo;
  (* abstract protocol states for HS/CCS, AL, and AD *)
  handshake: Handshake.hs_state
  alert    : Alert.al_state
  appdata  : AppData.app_state    

  (* connection state for reading and writing *)
  read  : dState;
  write : dState;
  }

let init ns role poptions =
    let (info,hs) = Handshake.init_handshake role poptions in
    let (send,recv) = Record.create ns info poptions.minVer in
    let read_state = {disp = Init; conn = recv} in
    let write_state = {disp = Init; conn = send} in
    let al = Alert.init info  in
    let app = AppData.init info in
    { ds_info = info;
      handshake = hs;
      alert = al;
      appdata = app;
      read = read_state;
      write = write_state}

let appDataAvailable conn =
    AppData.retrieve_data_available conn.appdata

let getSessionInfo conn =
    conn.ds_info
   
let moveToOpenState c new_info =
    let new_hs = Handshake.new_session_idle c.handshake new_info in
    let new_alert = Alert.init new_info in
    let new_appdata = AppData.init new_info in
    (* Read and write state should already have the same SessionInfo
        set after CCS *)
    let c = {c with ds_info = new_info;
                    handshake = new_hs;
                    alert = new_alert;
                    appdata = new_appdata} in
    let read = c.read in
    match read.disp with
    | Finishing ->
        let new_read = {read with disp = Open} in
        let write = c.write in
        match write.disp with
        | x when x = Finishing || x = Finished ->
            let new_write = {write with disp = Open} in
            {c with read = new_read; write = new_write}
        | _ -> unexpectedError "[moveToOpenState] should only work on Finishing or Finished write states"
    | _ -> unexpectedError "[moveToOpenState] should only work on Finishing read states"

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
                            | Error (x,y) -> (Error(x,y), {c with appdata = new_app_state}) (* This is a TCP error, there's not much we can do *)
                          | _ -> (Error(Dispatcher,InvalidState),{c with appdata = new_app_state})
          | (CCSFrag(ccs,cp),new_hs_state) ->
                    (* we send a (complete) CCS fragment *)
                    match c_write.disp with
                    (* Is the next test needed anymore, or do we rely on the
                       HS to provide CCS in the right time? Problem of synch
                       between HS state and Dispatcher state *)
                    | x when x = FirstHandshake || x = Open ->
                        match Record.send c_write.conn Change_cipher_spec ccs with
                        | Correct ss -> 
                        (* we change the CS immediately afterward *)
                            let ss = Record.send_setCrypto ss cp in
                            let new_write = {disp = Finishing; conn = ss} in
                            (correct (true), { c with handshake = new_hs_state;
                                                      write = new_write } )
                        | Error (x,y) -> (Error (x,y), {c with handshake = new_hs_state}) (* TCP error, like above *)
                    | _ -> (Error(Dispatcher, InvalidState),{c with handshake = new_hs_state})
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
                          | Error (x,y) -> (Error(x,y), {c with handshake = new_hs_state}) (* TCP error, like above *)
                      | _ -> (Error(Dispatcher,InvalidState), {c with handshake = new_hs_state})
          | (HSWriteSideFinished,new_hs_state) ->
                let c = {c with handshake = new_hs_state} in
                (* check we are in finishing state *)
                match c_write.disp with
                | Finishing ->
                    let c_write = {c_write with disp = Finished}
                    let c = {c with write = c_write} in
                    (Error(MustRead,Notification),c)
                | _ -> (Error(Dispatcher,InvalidState), c)
          | (HSFullyFinished_Write(new_info),new_hs_state) ->
                let c = {c with handshake = new_hs_state} in
                match c_write.disp with
                | Finishing ->
                   (* according to the protocol logic and the dispatcher
                      implementation, we must now have an empty input buffer.
                      This means we can directly report a NewSessionInfo error
                      notification, and not a mustRead.
                      Check thus that we in fact have an empty input buffer *)
                   if appDataAvailable c then (* this is a bug. *)
                       (Error(Dispatcher,Internal),c)
                   else
                       let c = moveToOpenState c new_info in
                       (Error(NewSessionInfo,Notification),c)
                | _ -> (Error(Dispatcher,InvalidState),c)
      | (ALFrag(f),new_al_state) ->        
        match Record.send c_write.conn Alert f with 
        | Correct ss ->
            let new_write = {disp = Closing; conn = ss} in
            (correct (true), { c with alert = new_al_state;
                                      write   = new_write } )
        | Error (x,y) -> (Error(x,y), {c with alert = new_al_state}) (* TCP error, like above *)
      | (LastALFrag(f),new_al_state) ->
        (* Same as above, but we set Closed dispatch state, instead of Closing *)
        match Record.send c_write.conn Alert f with 
        | Correct ss ->
            let new_write = {disp = Closed; conn = ss} in
            (correct (false), { c with alert = new_al_state;
                                       write   = new_write } )
        | Error (x,y) -> (Error(x,y),{c with alert = new_al_state}) (* TCP error, like above *)

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
    | (Correct(HSAck),hs)                 ->
       (correct (true), { c with handshake = hs} )
    | (Correct(HSChangeVersion(r,v)),hs)     ->
        match r with
        | ClientRole ->
            match Record.recv_checkVersion c_read.conn v with
            | Correct (dummy) ->
                (correct (true), { c with handshake = hs} )
            | Error(x,y) -> (Error(x,y), {c with handshake = hs} )
        | ServerRole ->
            let new_recv = Record.recv_setVersion c_read.conn v in
            let new_read = {c_read with conn = new_recv} in
            (correct (true), { c with handshake = hs;
                                      read = new_read} )
    | (Correct(HSReadSideFinished),hs) ->
        (* Ensure we are in Finishing state *)
        match x with
        | Finishing ->
            (* We stop reading now. The subsequent writes invoked after
               reading will send the appropriate handshake messages, and
               the handshake will be fully completed *)
            (correct (false),{c with handshake = hs})
        | _ -> (Error(Dispatcher,InvalidState), {c with handshake = hs} )
    | (Correct(HSFullyFinished_Read(new_info)),hs) ->
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
        (correct (true), { c with handshake = hs;
                                  read = new_read} )
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
            (* One fragment has been put in the buffer for sure *)
            let c_appdata = conn.appdata in
            let (read, new_appdata) = AppData.retrieve_data c_appdata n in
            let conn = {conn with appdata = new_appdata} in
            (correct (read),conn)
        | (Error (x,y),c) -> (Error(x,y),c)