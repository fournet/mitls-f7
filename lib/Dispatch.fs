module Dispatch

open Bytes
open Formats
//open Record
open Tcp
open Error
open Handshake
open Alert
open TLSInfo

open TLSFragment // Required by F7, or deliver won't parse.

type predispatchState =
  | Init
  | FirstHandshake
  | Finishing
  | Finished (* Only for Writing side, used to implement TLS False Start *)
  | Open
  | Closing
  | Closed

type dispatchState = predispatchState

type dState = {
    disp: dispatchState;
    conn: Record.ConnectionState;
    }

type preGlobalState = {
  (* abstract protocol states for HS/CCS, AL, and AD *)
  handshake: Handshake.hs_state;
  alert    : Alert.state;
  appdata  : AppDataStream.app_state;

  (* connection state for reading and writing *)
  read  : dState;
  write : dState;

  (* The actual socket *)
  ns: NetworkStream;
  }

type globalState = preGlobalState

type Connection = Conn of ConnectionInfo * globalState
let networkStream (Conn(id,g)) = g.ns

type nextCn = Connection
type query = Certificate.cert
// FIXME: Put the following definitions close to range and delta, and use them
type msg_i = (DataStream.range * DataStream.delta)
type msg_o = (DataStream.range * DataStream.delta)

// Outcomes for internal, one-message-at-a-time functions
type writeOutcome =
    | WError of ioerror
    | WriteAgain (* Possibly more data to send *)
    | WAppDataDone (* No more data to send in the current state *)
    | WHSDone
    | WMustRead (* Read until completion of Handshake *)
    | SentFatal of alertDescription
    | SentClose

type readOutcome =
    | WriteOutcome of writeOutcome 
    | RError of ioerror
    | RAgain
    | RAppDataDone
    | RQuery of query
    | RHSDone
    | RClose
    | RFatal of alertDescription
    | RWarning of alertDescription


let init ns role poptions =
    let (ci,hs) = Handshake.init role poptions in
    let id_in = ci.id_in in
    let id_out = ci.id_out in
    let recv = Record.nullConnState id_in in
    let send = Record.nullConnState id_out in
    let read_state = {disp = Init; conn = recv} in
    let write_state = {disp = Init; conn = send} in
    let al = Alert.init ci in
    let app = AppDataStream.init ci in
    let state = { handshake = hs;
                  alert = al;
                  appdata = app;
                  read = read_state;
                  write = write_state;
                  ns=ns;}
    Conn ( ci, state)

let resume ns sid ops =
    (* Only client side, can never be server side *)
    let (ci,hs) = Handshake.resume sid ops in
    let (send,recv) = (Record.nullConnState ci.id_out, Record.nullConnState ci.id_in) in
    let read_state = {disp = Init; conn = recv} in
    let write_state = {disp = Init; conn = send} in
    let al = Alert.init ci in
    let app = AppDataStream.init ci in
    let res = Conn ( ci,
                     { handshake = hs;
                       alert = al;
                       appdata = app;
                       read = read_state;
                       write = write_state;
                       ns = ns;}) in
    correct (res)

let rehandshake (Conn(id,conn)) ops =
    let (accepted,new_hs) = Handshake.rehandshake id conn.handshake ops in // Equivalently, id.id_in.sinfo
    (accepted,Conn(id,{conn with handshake = new_hs}))

let rekey (Conn(id,conn)) ops =
    let (accepted,new_hs) = Handshake.rekey id conn.handshake ops in // Equivalently, id.id_in.sinfo
    (accepted,Conn(id,{conn with handshake = new_hs}))

let request (Conn(id,conn)) ops =
    let (accepted,new_hs) = Handshake.request id conn.handshake ops in // Equivalently, id.id_in.sinfo
    (accepted,Conn(id,{conn with handshake = new_hs}))

let shutdown (Conn(id,conn)) =
    let new_al = Alert.send_alert id conn.alert AD_close_notify in
    let conn = {conn with alert = new_al} in
    Conn(id,conn)

let moveToOpenState (Conn(id,c)) =
    // Agreement should be on all protocols.
    // - As a pre-condition to invoke this function, we have agreement on HS protocol
    // - We have implicit agreement on appData, because the input/output buffer is empty
    //   (This can either be a pre-condition, or we can add a dynamic check here)
    // - We need to enforce agreement on the alert protocol.
    //   We do it here, by checking that our input buffer is empty. Maybe, we should have done
    //   it before, when we sent/received the CCS
    //if Alert.incomingEmpty id c.alert then
    let read = c.read in
    match read.disp with
    | Finishing | Finished ->
        let new_read = {read with disp = Open} in
        let c_write = c.write in
        match c_write.disp with
        | Finishing | Finished ->
            let new_write = {c_write with disp = Open} in
            let c = {c with read = new_read; write = new_write} in
            correct c
        | _ -> Error(Dispatcher,CheckFailed)
    | _ -> Error(Dispatcher,CheckFailed)
    //else
    //    Error(Dispatcher,CheckFailed)

let closeConnection (Conn(id,c)) =
    let new_read = {c.read with disp = Closed} in
    let new_write = {c.write with disp = Closed} in
    let new_hs = Handshake.invalidateSession id c.handshake in
    let c = {c with read = new_read;
                    write = new_write;
                    handshake = new_hs} in
    Conn(id,c)

(* Dispatch dealing with network sockets *)
let pickSendPV (Conn(id,c)) =
    match c.write.disp with
    | Init -> getMinVersion id c.handshake
    | FirstHandshake -> getNegotiatedVersion id c.handshake
    | _ -> let si = epochSI(id.id_out) in si.protocol_version

let send ns e write pv rg ct frag =
    let res = Record.recordPacketOut e write.conn pv rg ct frag in
    let (conn,data) = res in
    let dState = {write with conn = conn} in
    match Tcp.write ns data with
    | Error(x,y) -> Error(x,y)
    | Correct(_) -> Correct(dState)

type preds = GState of ConnectionInfo * globalState
(* which fragment should we send next? *)
(* we must send this fragment before restoring the connection invariant *)
let writeOne (Conn(id,c)) : (writeOutcome * Connection) Result =
  let c_write = c.write in
  match c_write.disp with
  | Closed -> Error (Dispatcher,InvalidState)
  | _ ->
      let state = c.alert in
      match Alert.next_fragment id state with
      | (Alert.EmptyALFrag,_) -> 
          let hs_state = c.handshake in
          match Handshake.next_fragment id hs_state with 
          | Handshake.OutIdle(_) ->
            let app_state = c.appdata in
                match AppDataStream.next_fragment id app_state with
                | None -> (correct (WAppDataDone,Conn(id,c)))
                | Some (next) ->
                          let (tlen,f,new_app_state) = next in
                          match c_write.disp with
                          | Open ->
                          (* we send some data fragment *)
                            let id_out = id.id_out in
                            let c_write_conn = c_write.conn
                            let history = Record.history id_out c_write_conn in
                            let frag = TLSFragment.construct id_out Application_data history tlen f
                            let pv = pickSendPV (Conn(id,c)) in
                            let resSend = send c.ns id_out c_write pv tlen Application_data frag in
                            match resSend with
                            | Correct(new_write) ->
                                let c = { c with appdata = new_app_state;
                                                 write = new_write }
                                (* Fairly, tell we're done, and we won't write more data *)
                                // KB: To Fix                                 
                                Pi.assume (GState(id,c));  
                                (Correct (WAppDataDone, Conn(id,c)) )


                            | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
                          | _ ->
                            (* We have data to send, but we cannot now. It means we're finishing a handshake.
                               Force to read, so that we'll complete the handshake and we'll be able to send
                               such data. *)
                            (* NOTE: We just ate up a fragment, which was not sent. That's not a big deal,
                               because we'll return MustRead to the app, which indeed means that no data
                               have been sent (It doesn't really matter at this point how we internally messed up
                               with the buffer, as long as we did not send anything on the network. *)
                              (correct(WMustRead, Conn(id,c)))   
          | Handshake.OutCCS(frag,newKeys) ->
                    let (rg,ccs) = frag in
                    let (nextID,nextWrite,new_hs_state) = newKeys in
                    let nextWCS = Record.initConnState nextID.id_out nextWrite in
                    (* we send a (complete) CCS fragment *)
                    match c_write.disp with
                    | x when x = FirstHandshake || x = Open ->
                        let history = Record.history id.id_out c_write.conn in
                        let frag = TLSFragment.construct id.id_out Change_cipher_spec history rg ccs in
                        let pv = pickSendPV (Conn(id,c)) in
                        let resSend = send c.ns id.id_out c.write pv rg Change_cipher_spec frag in
                        match resSend with
                        | Correct _ -> (* We don't care about next write state, because we're going to reset everything after CCS *)
                            (* Now:
                                - update the index and the state of other protocols
                                - move the outgoing state to Finishing, to signal we must not send appData now. *)
                            let new_write = {c.write with disp = Finishing; conn = nextWCS} in 
                            let new_ad = AppDataStream.reset_outgoing id c.appdata nextID in
                            let new_al = Alert.reset_outgoing id c.alert nextID in
                            let c = { c with write = new_write;
                                             handshake = new_hs_state;
                                             alert = new_al;
                                             appdata = new_ad} in 
                            (correct (WriteAgain, Conn(nextID,c)) )
                        | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error (x,y) (* Unrecoverable error *)
                    | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher, InvalidState) (* TODO: we might want to send an "internal error" fatal alert *)
          | (Handshake.OutSome((rg,f),new_hs_state)) ->     
                      (* we send some handshake fragment *)
                      match c_write.disp with
                      | x when x = Init || x = FirstHandshake ||
                               x = Finishing || x = Open ->
                          let history = Record.history id.id_out c_write.conn in
                          let frag = TLSFragment.construct id.id_out Handshake history rg f in
                          let pv = pickSendPV (Conn(id,c)) in
                          let resSend = send c.ns id.id_out c.write pv rg Handshake frag in
                          match resSend with 
                          | Correct(new_write) ->
                            let c = { c with handshake = new_hs_state;
                                             write  = new_write } in
                            //KB: to fix:
                            Pi.assume(GState(id,c));
                            (correct (WriteAgain, Conn(id,c)) )
                          | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
                      | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) (* TODO: we might want to send an "internal error" fatal alert *)
          | (Handshake.OutFinished((rg,lastFrag),new_hs_state)) ->
                (* check we are in finishing state *)
                match c_write.disp with
                | Finishing ->
                    (* Send the last fragment *)
                    let history = Record.history id.id_out c_write.conn in
                    let frag = TLSFragment.construct id.id_out Handshake history rg lastFrag in
                    let pv = pickSendPV (Conn(id,c)) in
                    let resSend = send c.ns id.id_out c.write pv rg Handshake frag in
                    match resSend with 
                          | Correct(new_write) ->
                            (* Also move to the Finished state *)
                            let c_write = {new_write with disp = Finished} in
                            let c = { c with handshake = new_hs_state;
                                             write     = c_write }
                            // KB: to fix:
                            Pi.assume(GState(id,c));
                            (Correct (WMustRead, Conn(id,c)))
                          | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
                | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) (* TODO: we might want to send an "internal error" fatal alert *)
          | (Handshake.OutComplete((rg,lastFrag),new_hs_state)) ->
                match c_write.disp with
                | Finishing ->
                    (* Send the last fragment *)
                    let history = Record.history id.id_out c_write.conn in
                    let frag = TLSFragment.construct id.id_out Handshake history rg lastFrag in
                    let pv = pickSendPV (Conn(id,c)) in
                    let resSend = send c.ns id.id_out c.write pv rg Handshake frag in
                    match resSend with 
                    | Correct(new_write) ->
                        let c = { c with handshake = new_hs_state;
                                         write     = new_write }
                        Pi.assume (GState(id,c));  
                        (* Move to the new state *)
                        // Sanity check: in and out session infos should be the same
                        if epochSI(id.id_in) = epochSI(id.id_out) then
                            match moveToOpenState (Conn(id,c)) with
                            | Correct(c) -> (correct(WHSDone,Conn(id,c)))
                            | Error(x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) // TODO: we might want to send an alert here
                        else
                            let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,CheckFailed)
                    | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
                | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) (* TODO: we might want to send an "internal error" fatal alert *)
      | (Alert.ALFrag(tlen,f),new_al_state) ->
        match c_write.disp with
        | Init | FirstHandshake | Open | Closing ->
            let history = Record.history id.id_out c_write.conn in
            let frag = TLSFragment.construct id.id_out Alert history tlen f in
            let pv = pickSendPV (Conn(id,c)) in
            let resSend = send c.ns id.id_out c.write pv tlen Alert frag in
            match resSend with 
            | Correct(new_write) ->
                let new_write = {new_write with disp = Closing} in
                let c = { c with alert   = new_al_state;
                                 write   = new_write }
                // KB: To Fix                                 
                Pi.assume (GState(id,c));  
                (correct (WriteAgain, Conn(id,c )))
            | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
        | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) (* Unrecoverable error *)
      | (Alert.LastALFrag(tlen,f,ad),new_al_state) ->
        match c_write.disp with
        | Init | FirstHandshake | Open | Closing ->
            (* We're sending a fatal alert. Send it, then close both sending and receiving sides *)
            let history = Record.history id.id_out c_write.conn in
            let frag = TLSFragment.construct id.id_out Alert history tlen f in
            let pv = pickSendPV (Conn(id,c)) in
            let resSend = send c.ns id.id_out c.write pv tlen Alert frag in
            match resSend with 
            | Correct(new_write) ->
                let c = {c with alert = new_al_state;
                                write = new_write}
                // KB: To Fix                                 
                Pi.assume (GState(id,c));  
                let closed = closeConnection (Conn(id,c)) in
                correct (SentFatal(ad), closed)
            | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
        | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) (* Unrecoverable error *)
      | (Alert.LastALCloseFrag(tlen,f),new_al_state) ->
        match c_write.disp with
        | Init | FirstHandshake | Open | Closing ->
            (* We're sending a close_notify alert. Send it, then only close our sending side.
               If we already received the other close notify, then reading is already closed,
               otherwise we wait to read it, then close. But do not close here. *)
            let history = Record.history id.id_out c_write.conn in
            let frag = TLSFragment.construct id.id_out Alert history tlen f in
            let pv = pickSendPV (Conn(id,c)) in
            let resSend = send c.ns id.id_out c.write pv tlen Alert frag in
            match resSend with
            | Correct(new_write) ->
                let new_write = {new_write with disp = Closed} in
                let c = {c with alert = new_al_state;
                                write = new_write}
                // KB: To Fix                                 
                Pi.assume (GState(id,c));  
                correct (SentClose, Conn(id,c))
            | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
        | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) (* Unrecoverable error *)

let recv (Conn(id,c)) =
    match Tcp.read c.ns 5 with // read & parse the header
    | Error (x,y)         -> Error(x,y)
    | Correct header ->
        match Record.headerLength header with
        | Error(x,y) -> Error(x,y)
        | Correct(len) ->
        match Tcp.read c.ns len with // read & process the payload
            | Error (x,y) -> Error(x,y) 
            | Correct payload ->
                let c_read = c.read in
                let c_read_conn = c_read.conn in
                let hp = header @| payload in 
                let recpkt = Record.recordPacketIn id.id_in c_read_conn hp in
                match recpkt with
                | Error(x,y) -> Error(x,y)
                | Correct(pack) -> 
                    let (c_recv,ct,pv,tl,f) = pack in
                    //printf "%s[%d] " (Formats.CTtoString ct) len; 
                    let si = epochSI(id.id_in) in
                    if c.read.disp = Init ||
                       (c.read.disp = FirstHandshake && pv = getNegotiatedVersion id c.handshake) ||
                       pv = si.protocol_version then
                        correct(c_recv,ct,tl,f)
                    else
                        Error(RecordVersion,CheckFailed)

(* we have received, decrypted, and verified a record (ct,f); what to do? *)
let readOne (Conn(id,c)) =
  match recv (Conn(id,c)) with
    | Error(x,y) -> Error(x,y)
    | Correct(received) -> 
        let (c_recv,ct,rg,frag) = received in 
        let c_read = c.read in
        let history = Record.history id.id_in c_read.conn in
        let f = TLSFragment.contents id.id_in ct history rg frag in
        let c_read = {c_read with conn = c_recv} in
          match c_read.disp with
            | Closed -> Error(Dispatcher,InvalidState)
            | _ ->
                match (ct,c_read.disp) with 
                  | Handshake, x when x = Init || x = FirstHandshake || x = Finishing || x = Open ->
                      let c_hs = c.handshake in
                        match Handshake.recv_fragment id c_hs rg f with
                        | Handshake.InAck(hs) ->
                            let c = { c with read = c_read;
                                            //appdata = ad;
                                            handshake = hs} in
                            // KB: To Fix                                 
                            Pi.assume (GState(id,c));  
                            correct (RAgain, Conn(id,c))
                        | Handshake.InVersionAgreed(hs) ->
                            match c_read.disp with
                            | Init ->
                                (* Then, also c_write must be in Init state. It means this is the very first, unprotected handshake,
                                    and we just negotiated the version.
                                    Set the negotiated version in the current sinfo (read and write side), 
                                    and move to the FirstHandshake state, so that
                                    protocol version will be properly checked *)
                                let new_read = {c_read with disp = FirstHandshake} in
                                let c_write = c.write in
                                let new_write = {c_write with disp = FirstHandshake} in
                                let c = {c with handshake = hs;
                                                read = new_read;
                                                write = new_write} in
                                    // KB: To Fix                                 
                                    Pi.assume (GState(id,c));  
                                    correct (RAgain, Conn(id,c) )
                            | _ -> (* It means we are doing a re-negotiation. Don't alter the current version number, because it
                                        is perfectly valid. It will be updated after the next CCS, along with all other session parameters *)
                                let c = { c with read = c_read;
                                                    handshake = hs} in
                                    // KB: To Fix                           
                                    Pi.assume (GState(id,c));  
                                    (correct (RAgain, Conn(id, c) ))
                        | Handshake.InQuery(query,hs) ->
                                let c = {c with read = c_read;
                                                handshake = hs} in
                                    // KB: To Fix                           
                                    Pi.assume (GState(id,c));  
                                    correct(RQuery(query),Conn(id,c))
                        | Handshake.InFinished(hs) ->
                                (* Ensure we are in Finishing state *)
                                match x with
                                    | Finishing ->
                                        let c = {c with read = c_read;
                                                        handshake = hs} in
                                        (* Indeed, we should stop reading now!
                                            (Because, except for false start implementations, the other side is now
                                            waiting for us to send our finished message)
                                            However, if we say RHSDone, the library will report an early completion of HS
                                            (we still have to send our finished message).
                                            So, here we say ReadAgain, which will anyway first flush our output buffers,
                                            this sending our finished message, and thus letting us get the WHSDone event.
                                            I know, it's tricky and it sounds fishy, but that's the way it is now.*)
                                        // KB: To Fix                           
                                        Pi.assume (GState(id,c));  
                                        correct (RAgain,Conn(id,c))
                                    | _ -> let closed = closeConnection (Conn(id,{c with handshake = hs})) in Error(Dispatcher,InvalidState) // TODO: We might want to send some alert here
                        | Handshake.InComplete(hs) ->
                                let c = {c with read = c_read;
                                                handshake = hs} in
                                // KB: To Fix                        
                                Pi.assume (GState(id,c));  
                                (* Ensure we are in Finishing state *)
                                    match x with
                                    | Finishing ->
                                            (* Sanity check: in and out session infos should be the same *)
                                        if epochSI(id.id_in) = epochSI(id.id_out) then
                                            match moveToOpenState (Conn(id,c)) with
                                            | Correct(c) -> 
                                                correct(RHSDone, Conn(id,c))
                                            | Error(x,y) -> 
                                                let closed = closeConnection (Conn(id,c)) in Error(x,y) (* TODO: we might want to send an alert here *)
                                        else let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,CheckFailed) (* TODO: we might want to send an internal_error fatal alert here. *)
                                    | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) (* TODO: We might want to send some alert here. *)
                        | Handshake.InError(x,y,hs) -> let c = {c with handshake = hs} in Error(x,y) (* TODO: we might need to send some alerts *)

                  | Change_cipher_spec, x when x = FirstHandshake || x = Open ->
                        match Handshake.recv_ccs id c.handshake rg f with 
                          | InCCSAck(nextID,nextR,hs) ->
                              let nextRCS = Record.initConnState nextID.id_in nextR in
                              let new_read = {c_read with disp = Finishing; conn = nextRCS} in
                              let new_ad = AppDataStream.reset_incoming id c.appdata nextID in
                              let new_al = Alert.reset_incoming id c.alert nextID in
                              let c = { c with read = new_read;
                                               appdata = new_ad;
                                               alert = new_al;
                                               handshake = hs;
                                      }
                                // KB: To Fix                                 
                              Pi.assume (GState(nextID,c));  
                              correct (RAgain, Conn(nextID,c))
                          | InCCSError (x,y,hs) ->
                              let c = {c with handshake = hs} in
                              let closed = closeConnection (Conn(id,c)) in
                              Error (x,y) // TODO: We might want to send some alert here.

                  | Alert, x when x = Init || x = FirstHandshake || x = Open || x = Closing ->
                        match Alert.recv_fragment id c.alert rg f with
                          | Correct (Alert.ALAck(state)) ->
                             //let ad = AppDataStream.writeNonAppDataFragment id c.appdata in
                              let c_read = {c_read with disp = Closing} in
                              let c = {c with read = c_read;
                                            //appdata = ad;
                                              alert = state} in
                               // KB: To Fix                                 
                              Pi.assume (GState(id,c));  
                              correct (RAgain, Conn(id,c))
                          | Correct (Alert.ALClose_notify (state)) ->
                                 (* An outgoing close notify has already been buffered, if necessary *)
                                 (* Only close the reading side of the connection *)
                             //let ad = AppDataStream.writeNonAppDataFragment id c.appdata in
                             let new_read = {c_read with disp = Closed} in
                             let c = { c with read = new_read;
                                              alert = state;
                                           //appdata = ad;
                                     } in
                             // KB: To Fix                                 
                             Pi.assume (GState(id,c));  
                             correct (RClose, Conn(id,c))
                          | Correct (Alert.ALFatal (ad,state)) ->
                               (* Other fatal alert, we close both sides of the connection *)
                               //let ad = AppDataStream.writeNonAppDataFragment id c.appdata in
                             let c = {c with alert = state;
                                             read = c_read
                                        }
                           // KB: To Fix                                 
                             Pi.assume (GState(id,c));  
                             let closed = closeConnection (Conn(id,c)) in
                             correct (RFatal(ad), closed )
                          | Correct (Alert.ALWarning (ad,state)) ->
                                (* A warning alert, we carry on. The user will decide what to do *)
                             //let ad = AppDataStream.writeNonAppDataFragment id c.appdata in
                             // FIXME: it this warning was fragmented, we temporarily switched to the
                             // Closing state, we must now restore the previous state, and we're not doing it!
                             let c = {c with alert = state;
                                             read = c_read;
                                     }
                             // KB: To Fix                                 
                             Pi.assume (GState(id,c));  
                             correct (RWarning(ad), Conn(id,c) )
                          | Error (x,y) -> let closed = closeConnection(Conn(id,c)) in Error(x,y) // TODO: We might want to send some alert here.

                  | Application_data, Open ->
                      let appstate = AppDataStream.recv_fragment id c.appdata rg f in
                      let c = {c with appdata = appstate
                                      read = c_read} in
                      // KB: To Fix                                 
                      Pi.assume (GState(id,c));  
                      correct (RAppDataDone, Conn(id, c))
                  | _, _ -> let closed = closeConnection(Conn(id,c)) in Error(Dispatcher,InvalidState) // TODO: We might want to send some alert here.
  


let rec writeAll c =
    match writeOne c with
    | Correct (WriteAgain,c) -> writeAll c
    | other -> other
(*
let rec read c =
    let orig = c in
    let unitVal = () in
    match writeAll c with
    | Error(x,y) -> c,ReadError(EInternal(x,y)) // Internal error
    | Correct(res) ->
        let (outcome,c) = res in
        match outcome with
        | WAppDataDone ->
            // Nothing more to write. We can try to read now.
            // (Note: In fact, WAppDataDone here means "nothing sent",
            // because the output buffer is always empty)
            match readOne c with
            | Error(x,y) ->
                c,ReadError(EInternal(x,y)) // internal error
            | Correct(res) ->
                let (outcome,c) = res in
                match outcome with
                | RAgain ->
                    read c 
                | RAppDataDone ->    
                    // empty the appData internal buffer, and return its content to the user
                    let (Conn(id,conn)) = c in
                    match AppDataStream.readAppData id conn.appdata with
                    | (Some(b),appState) ->
                        let conn = {conn with appdata = appState} in
                        let c = Conn(id,conn) in
                        Pi.assume (GState(id,conn));
                        c,Read(c,b)
                    | (None,_) -> unexpectedError "[read] When RAppDataDone, some data should have been read."
                | RQuery(q) ->
                    c,CertQuery(c,q)
                | RHSDone ->
                    c,Handshaken(c)
                | RClose ->
                    let (Conn(id,conn)) = c in
                    match conn.write.disp with
                    | Closed ->
                        // we already sent a close_notify, tell the user it's over
                        c,Close conn.ns
                    | _ ->
                        match writeAll c with
                        | Correct(SentClose,c) ->
                            // clean shoutdown
                            c,Close conn.ns
                        | Correct(SentFatal(ad),c) ->
                            c,ReadError(EFatal(ad))
                        | Correct(_,c) ->
                            c,ReadError(EInternal(Dispatcher,Internal)) // internal error
                        | Error(x,y) ->
                            c,ReadError(EInternal(x,y)) // internal error
                | RFatal(ad) ->
                    c,Fatal(ad)
                | RWarning(ad) ->
                    c,Warning(c,ad)
        | WMustRead ->
            c,DontWrite(c)
        | WHSDone ->
            c,Handshaken (c)
        | SentFatal(ad) ->
            c,ReadError(EFatal(ad))
        | SentClose ->
            let (Conn(id,conn)) = c in
            match conn.read.disp with
            | Closed ->
                // we already received a close_notify, tell the user it's over
                c,Close conn.ns
            | _ ->
                // same as we got a MustRead
                c,DontWrite c
        | WriteAgain -> unexpectedError "[read] writeAll should never return WriteAgain"
*)
let rec read c =
    let orig = c in
    let unitVal = () in
    match writeAll c with
    | Error(x,y) -> c,WriteOutcome(WError(EInternal(x,y))),None
    | Correct(res) ->
        let (outcome,c) = res in
        match outcome with
        | WAppDataDone ->
            match readOne c with
            | Error(x,y) -> c,RError(EInternal(x,y)),None
            | Correct(res) ->
                let (outcome,c) = res in
                match outcome with
                | RAgain ->
                    read c 
                | RAppDataDone ->    
                    // empty the appData internal buffer, and return its content to the user
                    let (Conn(id,conn)) = c in
                    match AppDataStream.readAppData id conn.appdata with
                    | (Some(b),appState) ->
                        let conn = {conn with appdata = appState} in
                        let c = Conn(id,conn) in
                        Pi.assume (GState(id,conn));
                        c,RAppDataDone,Some(b)
                    | (None,_) -> unexpectedError "[read] When RAppDataDone, some data should have been read."
                | RQuery(q) ->
                    c,RQuery(q),None
                | RHSDone ->
                    c,RHSDone,None
                | RClose ->
                    let (Conn(id,conn)) = c in
                    match conn.write.disp with
                    | Closed ->
                        // we already sent a close_notify, tell the user it's over
                        c,RClose, None
                    | _ ->
                        match writeAll c with
                        | Correct(SentClose,c) ->
                            // clean shoutdown
                            c,RClose,None
                        | Correct(SentFatal(ad),c) ->
                            c,RError(EFatal(ad)),None
                        | Correct(_,c) ->
                            c,RError(EInternal(Dispatcher,Internal)),None // internal error
                        | Error(x,y) ->
                            c,RError(EInternal(x,y)),None // internal error
                | RFatal(ad) ->
                    c,RFatal(ad),None
                | RWarning(ad) ->
                    c,RWarning(ad),None
        | SentClose -> c,WriteOutcome(SentClose),None
        | WMustRead -> c,WriteOutcome(WMustRead),None
        | WHSDone -> c,WriteOutcome(WHSDone),None
        | SentFatal(ad) -> c,WriteOutcome(SentFatal(ad)),None
        | WriteAgain -> unexpectedError "[read] writeAll should never return WriteAgain"

let write (Conn(id,c)) msg =
  let (r,d) = msg in
  let new_appdata = AppDataStream.writeAppData id c.appdata r d in
  let c = {c with appdata = new_appdata} in 
  match writeAll (Conn(id,c)) with
    | Error(x,y) -> Conn(id,c),WError(EInternal(x,y)),None // internal
    | Correct(res) ->
        let (outcome,c) = res in
          match outcome with
            | WAppDataDone ->
                let (Conn(id,g)) = c in
                let (rdOpt,new_appdata) = AppDataStream.emptyOutgoingAppData id g.appdata in
                let g = {g with appdata = new_appdata} in
                  Conn(id,g),WAppDataDone,rdOpt
            | _ -> c,outcome,None
(*
let write (Conn(id,c)) msg =
  let (r,d) = msg in
  let new_appdata = AppDataStream.writeAppData id c.appdata r d in
  let c = {c with appdata = new_appdata} in 
  match writeAll (Conn(id,c)) with
    | Error(x,y) -> WError(EInternal(x,y)) // internal
    | Correct(res) ->
        let (outcome,c) = res in
        match outcome with
        | WAppDataDone ->
            let (Conn(id,c)) = c in
            let (rdOpt,new_appdata) = AppDataStream.emptyOutgoingAppData id c.appdata in
            let c = {c with appdata = new_appdata} in
            match rdOpt with
            | None -> WriteComplete (Conn(id,c))
            | Some(rd) -> WritePartial (Conn(id,c),rd)
        | WHSDone ->
            // A top-level write should never lead to HS completion.
            // Currently, we report this as an internal error.
            // Being more precise about the Dispatch state machine, we should be
            // able to prove that this case should never happen, and so use the
            // unexpectedError function.
            WriteError(EInternal(Dispatcher,Internal))
        | WMustRead | SentClose ->
            MustRead(c)
        | SentFatal(ad) ->
            WriteError(EFatal(ad))
        | WriteAgain ->
            unexpectedError "[write] writeAll should never return WriteAgain"
*)
let authorize (Conn(id,c)) q =
    let hs = Handshake.authorize id c.handshake q in
    let c = {c with handshake = hs} in
    Conn(id,c)

let refuse (Conn(id,c)) (q:query) =
    let al = Alert.send_alert id c.alert AD_unknown_ca in
    let c = {c with alert = al} in
    //ignore (writeAll (Conn(id,c))) // we might want to tell the user something about this
    let _ = writeAll (Conn(id,c)) in
    ()

let getEpochIn  (Conn(id,state)) = id.id_in
let getEpochOut (Conn(id,state)) = id.id_out
let getInStream  (Conn(id,state)) = AppDataStream.inStream  id state.appdata
let getOutStream (Conn(id,state)) = AppDataStream.outStream id state.appdata 
