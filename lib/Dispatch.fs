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

type dispatchState =
  | Init (* of ProtocolVersionType * ProtocolVersionType *) (* min and max *)
  | FirstHandshake (* of ProtocolVersionType *)             (* set by the ServerHello *) 
  | Finishing
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

  // unused yet: sessid: SessionID;
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

(* which fragment should we send next? *)
(* we must send this fragment before restoring the connection invariant *)

let next_fragment n (c:Connection) : (bool * Connection) Result =
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
                          correct (false,c)
                | Some x ->
                          let (f,new_app_state) = x in
                          match c_write.disp with
                          | Open ->
                          (* we send some data fragment; should we notify the app when done? *)
                            match Record.send c_write.conn Application_data f with
                            | Correct(ss) ->
                                let new_write = { c_write with conn = ss } in
                                correct ( true,
                                          { c with appdata = new_app_state;
                                                   write   = new_write } )
                            | Error (x,y) -> Error(x,y) (* This is a TCP error, there's not much we can do *)
                          | _ -> (* Not the right time to send app data *)
                                (* FIXME: true or false? or even Error(Dispatcher, InvalidState)?
                                   Should we try to send again in this case?
                                   Or some other protocol should be willing to send data in non-Open states? *)
                                correct (false, c)
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
                            correct ( true,
                                    { c with handshake = new_hs_state;
                                             write = new_write } )
                        | Error (x,y) -> Error (x,y) (* TCP error, like above *)
                    | _ -> Error(Dispatcher, InvalidState)
          | (HSFrag(f),new_hs_state) ->     
                      (* we send some handshake fragment *)
                      match c_write.disp with
                      | x when x = Init || x = FirstHandshake ||
                               x = Finishing || x = Open ->
                          match Record.send c_write.conn Handshake f with 
                          | Correct(ss) ->
                            let new_write = {c_write with conn = ss} in
                            correct ( true,{ c with handshake = new_hs_state;
                                                    write     = new_write } )
                          | Error (x,y) -> Error(x,y) (* TCP error, like above *)
                      | _ ->
                        Error(Dispatcher,InvalidState)
          | (LastHSFrag(new_info,f),new_hs_state) ->     
                      (* last handshake fragment: send it, update sessionInfo and switch to the Open state *) 
                      match c_write.disp with
                      | Finishing ->
                          match Record.send c_write.conn Handshake f with 
                          | Correct(ss) ->
                            (* TODO: Update SessionInfo globally -- FIXME: read/write direction? *)
                            let new_write = {disp = Open; conn = ss} in
                            correct ( true,{ c with handshake = new_hs_state;
                                                    write     = new_write } )
                          | Error (x,y) -> Error(x,y) (* TCP error, like above *)
                      | _ -> Error(Dispatcher,InvalidState)
      | (ALFrag(f),new_al_state) ->        
        match Record.send c_write.conn Alert f with 
        | Correct ss ->
            let new_write = {disp = Closing; conn = ss} in
            correct ( false,
                        { c with alert = new_al_state;
                                    write   = new_write } )
        | Error (x,y) -> Error(x,y) (* TCP error, like above *)
      | (LastALFrag(f),new_al_state) ->
        (* Same as above, but we set Closed dispatch state, instead of Closing *)
        match Record.send c_write.conn Alert f with 
        | Correct ss ->
            let new_write = {disp = Closed; conn = ss} in
            correct ( false,
                        { c with alert = new_al_state;
                                    write   = new_write } )
        | Error (x,y) -> Error(x,y) (* TCP error, like above *)

let max_TLSPlaintext_fragment_length = 1<<<14 (* just a reminder *)
let fragmentLength = max_TLSPlaintext_fragment_length (*1*)

let rec sendNextFragments c =
    let c_write = c.write in
    match c_write.disp with
    | Closed -> correct(c)
    | _ ->
        match next_fragment fragmentLength c with
        | Error (x,y) -> Error(x,y)
        | Correct res ->
        let (again, c) = res in
        if again then
            (* be fair: don't do more sending now if we could read *)
            (* note: eventually all buffered data will be sent, they're are already committed
                        to be sent *)
            match Record.dataAvailable c.read.conn with
            | Error (x,y) -> correct (c) (* There's an error with TCP, but we can ignore it right now, and just pretend there are data to send, so the error will show up next time *)
            | Correct dataAv ->
            if dataAv then
                correct(c)
            else
                sendNextFragments c 
        else
            correct (c)

(* we have received, decrypted, and verified a record (ct,f); what to do? *)

let deliver ct f c = 
  let c_read = c.read in
  match c_read.disp with
  | Closed -> unexpectedError "[deliver] should never be invoked on a closed connection state."
  | _ ->
  match (ct,c_read.disp) with 

  | Handshake, x when x = Init || x = FirstHandshake || x = Finishing || x = Open ->
    match Handshake.recv_fragment c.handshake f with 
    | Correct(HSAck(hs))                 ->
       correct ( true,
                   { c with handshake = hs} )
    | Correct(HSChangeVersion(hs,r,v))     ->
        match r with
        | ClientRole ->
            match Record.recv_checkVersion c_read.conn v with
            | Correct (dummy) ->
                correct ( true,
                         { c with handshake = hs} )
            | Error(x,y) -> Error(x,y)
        | ServerRole ->
            let new_recv = Record.recv_setVersion c_read.conn v in
            let new_read = {c_read with conn = new_recv} in
            correct ( true,
                      { c with handshake = hs;
                               read = new_read} )
    | Correct(HSFinished(new_info,hs)) ->
        (* Ensure we are in Finishing state *)
        match x with
        | Finishing ->
            (* TODO: update SessionInfo globally -- FIXME: read/write issue? *)
            let new_read = {c_read with disp = Open} in
            correct ( true,
                      { c with handshake = hs; read = new_read } )
        | _ -> Error(Dispatcher,InvalidState)
    | Error(x,y) -> Error(x,y)

  | Change_cipher_spec, x when x = FirstHandshake || x = Open -> 
    match Handshake.recv_ccs c.handshake f with 
    | Correct(res) ->
        let (hs,cryptoparams) = res in
        let new_recv = Record.recv_setCrypto c_read.conn cryptoparams in
        let new_read = {disp = Finishing; conn = new_recv} in
        correct ( true,
                { c with handshake = hs;
                             read = new_read} )
    | Error (x,y) -> Error (x,y)

  | Alert, x ->
    match Alert.recv_fragment c.alert f with
    | Correct (ALAck(state)) ->
      correct ( true,
                  { c with alert = state} )
    | Correct (ALClose_notify (state)) ->
        (* An outgoing close notify has already been buffered, if necessary *)
        (* Only close the reading side of the connection *)
        let new_read = {c_read with disp = Closed} in
        correct ( false,
                    { c with read = new_read})
    | Correct (ALClose (state)) ->
        (* Other fatal alert, we close both sides of the connection *)
        let new_read = {c_read with disp = Closed} in
        let new_write = {c.write with disp = Closed} in
        correct ( false,
                    { c with read = new_read;
                             write = new_write} )
    | Error (x,y) -> Error(x,y)

  | Application_data, Open -> 
    match AppData.recv_fragment c.appdata f with 
    | Correct (state) ->
        correct ( false,
                    { c with appdata = state })
    | Error (x,y) -> Error (x,y)
  | UnknownCT, _ -> Error(Dispatcher,Unsupported)
  | _, _ -> Error(Dispatcher,InvalidState)

let rec readNextAppFragment conn =
    (* If available, read next data *)
    let c_read = conn.read in
    match c_read.disp with
    | Closed -> sendNextFragments conn
    | _ ->
    match Record.dataAvailable c_read.conn with
    | Error (x,y) -> Error(x,y)
    | Correct canRead ->
    if canRead then
        match Record.recv c_read.conn with
        | Error (x,y) -> Error (x,y)
        | Correct res ->
        let (ct,f,recvSt) = res in
        let new_read = {c_read with conn = recvSt} in
        let conn = {conn with read = new_read} in (* update the connection *)
        match deliver ct f conn with
        | Error (x,y) -> Error(x,y)
        | Correct res ->
        let (again, conn) = res in
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


/// older stuff below

(*

let hs_output hs n = 
  match sending with 
  | send_HS b when b.Length > n -> 
    let f,b = split n b in Some f, { hs with sending = b }
  | send_HS b -> Some b, { hs with sending = Idle }
  | send_CCS -> Some ccs_fragment, { hs with sending = Idle }

type RecordMessage =
    | NoMsg
    | SomeMsg of (ContentType * bytes)

type DispatcherState =
    | FirstHandshake
    | Normal
    | ReHandshake
    | ReHandshakeAfterCCS
    | TLSClose
    | TLSError of ErrorCause

type CallbacksTable = {
    poll_hs: Dispatcher -> (Dispatcher * RecordMessage);
    poll_al: Dispatcher -> (Dispatcher * RecordMessage);
    poll_app: Dispatcher -> (Dispatcher * RecordMessage);
    dispatch_hs: Dispatcher -> RecordMessage -> Dispatcher;
    dispatch_al: Dispatcher -> RecordMessage -> Dispatcher;
    dispatch_app: Dispatcher -> RecordMessage -> Dispatcher;
}

and Dispatcher = D of (Connection * DispatcherState * CallbacksTable)

type CallbackType =
    | Handshake_and_Change_Cihper_Spec
    | Alert
    | Application_Data

type CallbackDirection =
    | Poll
    | Dispatch

let null_poll_cb (d:Dispatcher) = (d,NoMsg)
let null_dispatch_cb (d:Dispatcher) (msg:RecordMessage) = d

let initCallbackTable () = {
    poll_hs = null_poll_cb;
    poll_al = null_poll_cb;
    poll_app = null_poll_cb;
    dispatch_hs = null_dispatch_cb;
    dispatch_al = null_dispatch_cb;
    dispatch_app = null_dispatch_cb;
    }

let init ns pv =
    D (Record.create ns pv, FirstHandshake, initCallbackTable ())

let registerPollCallback (D (conn, state, cbtbl)) cbtype cbfun =
    let new_cbtbl =
        match cbtype with
        | Handshake_and_Change_Cihper_Spec -> {cbtbl with poll_hs = cbfun}
        | Alert -> {cbtbl with poll_al = cbfun}
        | Application_Data -> {cbtbl with poll_app = cbfun}
    D (conn, state, new_cbtbl)

let registerDispatchCallback (D (conn, state, cbtbl)) cbtype cbfun =
    let new_cbtbl =
        match cbtype with
        | Handshake_and_Change_Cihper_Spec -> {cbtbl with dispatch_hs = cbfun}
        | Alert -> {cbtbl with dispatch_al = cbfun}
        | Application_Data -> {cbtbl with dispatch_app = cbfun}
    D (conn, state, new_cbtbl)

let setHandshakeVersion (D (conn, state, cbtbl)) pv =
    let new_conn = Record.setHandshakeVersion conn pv in
    D(new_conn, state, cbtbl)

let rec pollNet (D (conn, state, cbtbl)) =
    
and runLoop (D (conn, state, cbtbl)) =
    (* Poll Alert Protocol *)
    let (D (conn, state, cbtbl), msg) = cbtbl.poll_al (D (conn, state, cbtbl)) in
    match msg with
    | SomeMsg (ct, payload) ->
        let sent = Record.send conn ct payload in
        match sent with
        | Error x -> TLSError x (* Any sending error is treated as fatal *)
        | Correct conn ->
            match state with
            | TLSClose -> TLSClose
            | _ -> runLoop (D (conn, state, cbtbl))
    | NoMsg ->
    (* Poll Handshake and CCS protocols *)
    let (D (conn, state, cbtbl), msg) = cbtbl.poll_hs (D (conn, state, cbtbl)) in
    match msg with
    | SomeMsg (ct, payload) ->
        let sent = Record.send conn ct payload in
        match sent with
        | Error x -> TLSError x (* Any sending error is treated as fatal *)
        | Correct conn ->
            match state with
            | TLSClose -> TLSClose
            | _ -> runLoop (D (conn, state, cbtbl))
    | NoMsg ->
    (* Check whether we should poll Application Data *)
    match state with
    | value when value = Normal || value = ReHandshake ->
        (* We want to poll the Applicaton Data *)
        let (D (conn, state, cbtbl), msg) = cbtbl.poll_app (D (conn, state, cbtbl)) in
        match msg with
        | SomeMsg (ct, payload) ->
            let sent = Record.send conn ct payload in
            match sent with
            | Error x -> TLSError x (* Any sending error is treated as fatal *)
            | Correct conn -> runLoop (D (conn, state, cbtbl))
        | NoMsg -> pollNet (D (conn, state, cbtbl))
    | _ -> pollNet (D (conn, state, cbtbl))

*)


(* ValidHSState and CCS invariants *)
(*
assume !hs,ds,cs. WriteState(ds,cs) => (ValidHSState(hs) <=> ( ValidHSDataOut(hs.hs_outgoing) /\
				       (cs.sparams.bulk_cipher_algorithm = BCA_null => Pub(hs.hs_outgoing) )))
*)
(* The following assume has to be proven by the Handhshake protocol. *)
(*
assume !hs,ccs,cp,pv,comp,spar,k,ciphst. (hs.ccs_outgoing = Some((ccs,cp)) /\ cp = (pv,comp,spar,k,ciphst)) => (pv <> UnknownPV /\
		(ValidStreamCipherSettings(pv,spar.cipher_type,ciphst,spar.bulk_cipher_algorithm,spar.mac_algorithm,k) \/
		 ValidStreamCipherSettings(pv,spar.cipher_type,ciphst,spar.bulk_cipher_algorithm,spar.mac_algorithm,k)))


assume !hs,ccs,cp,ds,cs. (WriteState(ds,cs) /\ hs.hs_outgoing = empty_bstr /\ hs.ccs_outgoing = Some((ccs,cp))) => (
		ValidHSState(hs) <=> (
			ValidHSDataOut(hs.hs_outgoing_after_ccs) /\ (* FIXME: This should happen only after ccs has been sent!
			And the fact that the counter restarts (modeled in send_setCrypto) should break the stream property (not modeled) *)
			ValidCCSDataOut(ccs) /\
			((ds = FirstHandshake /\ cs.sparams.bulk_cipher_algorithm = BCA_null /\ Pub(ccs)) \/
			( ds = Open /\ cs.sparams.bulk_cipher_algorithm <> BCA_null))
			
		))

assume !cs,ct,f. (SendConnState(cs) /\ ct = Change_cipher_spec /\ ValidCCSDataOut(f))
		    => FragmentSend(cs,ct,f)
*)        
(* Valid Alert state invariants *)
(*
assume !alstate,ds,cs. WriteState(ds,cs) => (ValidAlState(alstate) <=> (ValidAlDataOut(alstate.al_outgoing) (* FIXME: Next assumption is cheating *) /\ Pub(alstate.al_outgoing)))

assume !cs,ct,f. (SendConnState(cs) /\ ct = Alert /\ ValidAlDataOut(f))
		    => FragmentSend(cs,ct,f)
*)
(* ValidAppstate invariants *)
(*
assume !appstate,ds,cs. (WriteState(ds,cs) /\ ds = Open) => (ValidAppState(appstate) <=>
ValidAppDataOut(appstate.app_outgoing))

assume !cs,ct,f. (SendConnState(cs) /\ ct = Application_data /\ ValidAppDataOut(f))
		    => FragmentSend(cs,ct,f)
*)
(* Distributivity of concat *)
(*
assume !d,f,rem. IsConcat(d,f,rem) /\ ValidAppDataOut(d) => ValidAppDataOut(f) /\ ValidAppDataOut(rem)
assume !d,f,rem. IsConcat(d,f,rem) /\ ValidHSDataOut(d) => ValidHSDataOut(f) /\ ValidHSDataOut(rem)
assume !d,f,rem. IsConcat(d,f,rem) /\ ValidAlDataOut(d) => ValidAlDataOut(f) /\ ValidAlDataOut(rem)
*)
