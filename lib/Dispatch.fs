module Dispatch

open Bytes
open Formats
//open Record
open Tcp
open Error
open Handshake
open Alert
open TLSInfo
open TLSKey
open SessionDB

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
    seqn: int
    }

type preGlobalState = {
  poptions: protocolOptions;
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
//type SameConnection = Connection
type nextCn = Connection
type query = Certificate.cert
// FIXME: Put the following definitions close to range and delta, and use them
type msg_i = (DataStream.range * DataStream.delta)
type msg_o = (DataStream.range * DataStream.delta)

// Outcomes for top-level functions
type ioresult_i =
| ReadError of ErrorCause * ErrorKind
| Close     of Tcp.NetworkStream
| Fatal     of alertDescription
| Warning   of nextCn * alertDescription 
| CertQuery of nextCn * query
| Handshaken of Connection
| Read      of nextCn * msg_i

type ioresult_o =
| WriteError    of ErrorCause * ErrorKind
| WriteComplete of nextCn
| WritePartial  of nextCn * msg_o
| MustRead      of Connection

// Outcomes for internal, one-message-at-a-time functions
type writeOutcome =
    | WriteAgain (* Possibly more data to send *)
    | WAppDataDone (* No more data to send in the current state *)
    | WHSDone
    | MustRead (* Read until completion of Handshake *)
    | SentFatal of alertDescription
    | SentClose

type deliverOutcome =
    | RAgain
    | RAppDataDone
    | RHSDone
    | RClose
    | RFatal of alertDescription
    | RWarning of alertDescription


let init ns role poptions =
    let outDir =
        match role with
        | Client -> CtoS
        | Server -> StoC
    let outKI = null_KeyInfo outDir poptions.minVer in
    let inKI = dual_KeyInfo outKI in
    let index = {id_in = inKI; id_out = outKI} in
    let hs = Handshake.init_handshake index role poptions in // Equivalently, inKI.sinfo
    let (outCCS,inCCS) = (nullCCSData outKI, nullCCSData inKI) in
    let (send,recv) = (Record.initConnState outKI outCCS, Record.initConnState inKI inCCS) in
    let read_state = {disp = Init; conn = recv; seqn = 0} in
    let write_state = {disp = Init; conn = send; seqn = 0} in
    let al = Alert.init index in
    let app = AppDataStream.init index in
    Conn ( index,
      { poptions = poptions;
        handshake = hs;
        alert = al;
        appdata = app;
        read = read_state;
        write = write_state;
        ns=ns;})

let resume ns sid ops =
    (* Only client side, can never be server side *)

    (* Ensure the sid is in the SessionDB, and it is for a client *)
    match select ops sid with
    | None -> unexpectedError "[resume] requested session expired or never stored in DB"
    | Some (retrieved) ->
    let (retrievedSinfo,retrievedMS,retrievedRole) = retrieved in
    match retrievedRole with
    | Server -> unexpectedError "[resume] requested session is for server side"
    | Client ->
    let outKI = null_KeyInfo CtoS ops.minVer in
    let inKI = dual_KeyInfo outKI in
    let index = {id_in = inKI; id_out = outKI} in
    let hs = Handshake.resume_handshake index retrievedSinfo retrievedMS ops in // equivalently, inKI.sinfo
    let (outCCS,inCCS) = (nullCCSData outKI, nullCCSData inKI) in
    let (send,recv) = (Record.initConnState outKI outCCS, Record.initConnState inKI inCCS) in
    let read_state = {disp = Init; conn = recv; seqn = 0} in
    let write_state = {disp = Init; conn = send; seqn = 0} in
    let al = Alert.init index in
    let app = AppDataStream.init index in
    let res = Conn ( index,
                     { poptions = ops;
                       handshake = hs;
                       alert = al;
                       appdata = app;
                       read = read_state;
                       write = write_state;
                       ns = ns;}) in
    let unitVal = () in
    (correct (unitVal), res)

let rehandshake (Conn(id,conn)) ops =
    let new_hs = Handshake.start_rehandshake id conn.handshake ops in // Equivalently, id.id_in.sinfo
    Conn(id,{conn with handshake = new_hs;
                       poptions = ops})

let rekey (Conn(id,conn)) ops =
    let new_hs = Handshake.start_rekey id conn.handshake ops in // Equivalently, id.id_in.sinfo
    Conn(id,{conn with handshake = new_hs;
                       poptions = ops})

let request (Conn(id,conn)) ops =
    let new_hs = Handshake.start_hs_request id conn.handshake ops in // Equivalently, id.id_in.sinfo
    Conn(id,{conn with handshake = new_hs;
                       poptions = ops})

let shutdown (Conn(id,conn)) =
    let new_al = Alert.send_alert id conn.alert AD_close_notify in
    let conn = {conn with alert = new_al} in
    Conn(id,conn)

(*
let appDataAvailable conn =
    AppDataStream.retrieve_data_available conn.appdata
*)

let getSessionInfo (Conn(id,conn)) =
    id.id_out.sinfo // in Open and Closed state, this should be equivalent to id.id_in.sinfo

let checkCompatibleSessions s1 s2 poptions =
    // (isNullSessionInfo s1) || (s1 = s2) || (poptions.isCompatibleSession s1 s2)
    if isNullSessionInfo s1 then
        true
    else if s1 = s2 then
        true
    else
        let isComp = poptions.isCompatibleSession s1 s2 in
        isComp

let moveToOpenState (Conn(id,c)) new_storable_info =
    (* If appropriate, store this session in the DB *)
    let (storableSinfo,storableMS,storableDir) = new_storable_info in
    match storableSinfo.sessionID with
    | None -> (* This session should not be stored *) ()
    | Some (sid) -> (* SessionDB. *) insert c.poptions sid new_storable_info

    let read = c.read in
    match read.disp with
    | Finishing | Finished ->
        let new_read = {read with disp = Open} in
        let c_write = c.write in
        match c_write.disp with
        | Finishing | Finished ->
            let new_write = {c_write with disp = Open} in
            {c with read = new_read; write = new_write}
        | _ -> unexpectedError "[moveToOpenState] should only work on Finishing or Finished write states"
    | _ -> unexpectedError "[moveToOpenState] should only work on Finishing read states"

let reIndex_dState (oldKI:KeyInfo) newKI dState ccsD =
    let newConn = Record.initConnState newKI ccsD in
    {dState with conn = newConn}

let reIndex_dState_null oldKI newKI dState =
    let newConn = Record.reIndex_null oldKI newKI dState.conn in
    {dState with conn = newConn}

let reIndex_out oldID newID c ccsD =
    // Note: cannot factor out the next three lines in a single function,
    // because the returned Connection would have inconsistent index.
    // All indexes must be changed atomically inside one function
    let newHS =      Handshake.reIndex oldID newID c.handshake in
    let newAlert =   Alert.reIndex     oldID newID c.alert in
    let newAppData = AppDataStream.reIndex  oldID newID c.appdata in
    let newWrite =   reIndex_dState oldID.id_out newID.id_out c.write ccsD in
    { c with handshake = newHS;
             alert =     newAlert;
             appdata =   newAppData;
             write =     newWrite}

let reIndex_in oldID newID c ccsD =
    let newHS =      Handshake.reIndex oldID newID c.handshake in
    let newAlert =   Alert.reIndex     oldID newID c.alert in
    let newAppData = AppDataStream.reIndex oldID newID c.appdata in
    let newRead =   reIndex_dState oldID.id_in newID.id_in c.read ccsD in
    { c with handshake = newHS;
             alert =     newAlert;
             appdata =   newAppData;
             read =      newRead}

let reIndex_null oldID newID c =
    let newHS =      Handshake.reIndex oldID newID c.handshake in
    let newAlert =   Alert.reIndex     oldID newID c.alert in
    let newAppData = AppDataStream.reIndex  oldID newID c.appdata in
    let newRead =    reIndex_dState_null oldID.id_in  newID.id_in  c.read in
    let newWrite =   reIndex_dState_null oldID.id_out newID.id_out c.write in
    { c with handshake = newHS;
             alert =     newAlert;
             appdata =   newAppData;
             read =      newRead;
             write =     newWrite}

let closeConnection (Conn(id,c)) =
    let new_read = {c.read with disp = Closed} in
    let new_write = {c.write with disp = Closed} in
    let c = {c with read = new_read; write = new_write} in
    Conn(id,c)

(* Dispatch dealing with network sockets *)
let send ki ns dState tlen ct frag =
    let (conn,data) = Record.recordPacketOut ki dState.conn tlen dState.seqn ct frag in
    let new_seqn = dState.seqn+1 in
    let dState = {dState with conn = conn; seqn = new_seqn} in
    match Tcp.write ns data with
    | Error(x,y) -> Error(x,y)
    | Correct(_) -> 
        // printf "%s(%d) " (CTtoString ct) tlen // DEBUG
        correct(dState)

(* which fragment should we send next? *)
(* we must send this fragment before restoring the connection invariant *)
let writeOne (Conn(id,c)) : (writeOutcome * Connection) Result =
  let c_read = c.read in
  let c_write = c.write in
  match c_write.disp with
  | Closed -> Error (Dispatcher,InvalidState)
  | _ ->
      let state = c.alert in
      match Alert.next_fragment id state with
      | (Alert.EmptyALFrag,_) -> 
          let hs_state = c.handshake in
          match Handshake.next_fragment id hs_state with 
          | (Handshake.EmptyHSFrag, _) ->
            let app_state = c.appdata in
                match AppDataStream.readAppDataFragment id app_state with
                | None -> (correct (WAppDataDone,Conn(id,c)))
                | Some (next) ->
                          let (tlen,f,new_app_state) = next in
                          let c = {c with appdata = new_app_state} in
                          match c_write.disp with
                          | Open ->
                          (* we send some data fragment *)
                            match send id.id_out c.ns c_write (tlen) Application_data (TLSFragment.FAppData(f)) with
                            | Correct(new_write) ->
                                let c = { c with write = new_write }
                                (* Fairly, tell we're done, and we won't write more data *)
                                (correct (WAppDataDone, Conn(id,c)) )
                            | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
                          | _ ->
                            (* We have data to send, but we cannot now. It means we're finishing a handshake.
                               Force to read, so that we'll complete the handshake and we'll be able to send
                               such data. *)
                            (* NOTE: We just ate up a fragment, which was not sent. That's not a big deal,
                               because we'll return MustRead to the app, which indeed means that no data
                               have been sent (It doesn't really matter at this point how we internally messed up
                               with the buffer, as long as we did not send anything on the network. *)
                            (correct(MustRead, Conn(id,c)))   
          | (Handshake.CCSFrag(frag,newKeys),new_hs_state) ->
                    let (tlen,ccs) = frag in
                    let (newKiOUT,ccs_data) = newKeys in
                    (* we send a (complete) CCS fragment *)
                    match c_write.disp with
                    | x when x = FirstHandshake || x = Open ->
                        match send id.id_out c.ns c_write (tlen) Change_cipher_spec (TLSFragment.FCCS(ccs)) with
                        | Correct _ -> (* We don't care about next write state, because we're going to reset everything after CCS *)
                            if checkCompatibleSessions id.id_out.sinfo newKiOUT.sinfo c.poptions then
                                let c = {c with handshake = new_hs_state} in
                                (* Now:
                                    - update the index
                                    - move the outgoing state to Finishing, to signal we must not send appData now. *)
                                let newID = {id with id_out = newKiOUT } in
                                let c = reIndex_out id newID c ccs_data in
                                let new_write = {c.write with disp = Finishing; seqn = 0} in
                                let newad = AppDataStream.reset_outgoing newID c.appdata in
                                let c = { c with write = new_write; appdata = newad} in
                                (correct (WriteAgain, Conn(newID,c)) )
                            else
                                let closed = closeConnection (Conn(id,c)) in
                                Error(Dispatcher, UserAborted) (* TODO: we might want to send an "internal error" fatal alert *)
                        | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error (x,y) (* Unrecoverable error *)
                    | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher, InvalidState) (* TODO: we might want to send an "internal error" fatal alert *)
          | (Handshake.HSFrag(tlen,f),new_hs_state) ->     
                      (* we send some handshake fragment *)
                      match c_write.disp with
                      | x when x = Init || x = FirstHandshake ||
                               x = Finishing || x = Open ->
                          match send id.id_out c.ns c_write ( tlen) Handshake (TLSFragment.FHandshake(f)) with 
                          | Correct(new_write) ->
                            let c = { c with handshake = new_hs_state;
                                             appdata = AppDataStream.readNonAppDataFragment id c.appdata;
                                             write     = new_write }
                            (correct (WriteAgain, Conn(id,c)) )
                          | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
                      | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) (* TODO: we might want to send an "internal error" fatal alert *)
          | (Handshake.HSWriteSideFinished(tlen,lastFrag),new_hs_state) ->
                (* check we are in finishing state *)
                match c_write.disp with
                | Finishing ->
                    (* Send the last fragment *)
                    match send id.id_out c.ns c_write (tlen) Handshake (TLSFragment.FHandshake(lastFrag)) with 
                          | Correct(new_write) ->
                            (* Also move to the Finished state *)
                            let c_write = {new_write with disp = Finished} in
                            let c = { c with handshake = new_hs_state;
                                             appdata = AppDataStream.readNonAppDataFragment id c.appdata;
                                             write     = c_write }
                            (correct (MustRead, Conn(id,c)))
                          | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
                | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) (* TODO: we might want to send an "internal error" fatal alert *)
          | (Handshake.HSFullyFinished_Write((tlen,lastFrag),new_info),new_hs_state) ->
                match c_write.disp with
                | Finishing ->
                    (* Send the last fragment *)
                    match send id.id_out c.ns c_write (tlen) Handshake (TLSFragment.FHandshake(lastFrag)) with 
                    | Correct(new_write) ->
                        let c = { c with handshake = new_hs_state;
                                         appdata = AppDataStream.readNonAppDataFragment id c.appdata;
                                         write     = new_write }
                        (* Move to the new state *)
                        // Sanity check: in and out session infos should be the same
                        if id.id_in.sinfo = id.id_out.sinfo then
                            let c = moveToOpenState (Conn(id,c)) new_info in
                            (correct(WHSDone,Conn(id,c)))
                        else
                            let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,CheckFailed)
                    | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
                | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) (* TODO: we might want to send an "internal error" fatal alert *)
      | (Alert.ALFrag(tlen,f),new_al_state) ->        
        match send id.id_out c.ns c_write (tlen) Alert (TLSFragment.FAlert(f)) with 
        | Correct(new_write) ->
            let new_write = {new_write with disp = Closing} in
            let ad = AppDataStream.readNonAppDataFragment id c.appdata in
            let c = { c with alert   = new_al_state;
                             appdata = ad;
                             write   = new_write }
            (correct (WriteAgain, Conn(id,c )))
        | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
      | (Alert.LastALFrag(tlen,f),new_al_state) ->
        (* We're sending a fatal alert. Send it, then close both sending and receiving sides *)
        match send id.id_out c.ns c_write (tlen) Alert (TLSFragment.FAlert(f)) with 
        | Correct(new_write) ->
            let ad = AppDataStream.readNonAppDataFragment id c.appdata in
            let c = {c with alert = new_al_state;
                            appdata = ad;
                            write = new_write}
            let closed = closeConnection (Conn(id,c)) in
            // FIXME: we need to know here which alert has been sent!
            // Needs rewriting of the Alert interface
            let inventedAlert = AD_internal_error in
            correct (SentFatal(inventedAlert), closed)
        | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)
      | (Alert.LastALCloseFrag(tlen,f),new_al_state) ->
        (* We're sending a close_notify alert. Send it, then only close our sending side.
           If we already received the other close notify, then reading is already closed,
           otherwise we wait to read it, then close. But do not close here. *)
        match send id.id_out c.ns c_write (tlen) Alert (TLSFragment.FAlert(f)) with
        | Correct(new_write) ->
            let new_write = {new_write with disp = Closed} in
            let ad = AppDataStream.readNonAppDataFragment id c.appdata in
            let c = {c with alert = new_al_state;
                            appdata = ad;
                            write = new_write}
            correct (SentClose, Conn(id,c))
        | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in Error(x,y) (* Unrecoverable error *)

(* we have received, decrypted, and verified a record (ct,f); what to do? *)
let deliver (Conn(id,c)) ct tl frag: (deliverOutcome * Connection) Result = 
  let tlen = tl in
  let c_read = c.read in
  let c_write = c.read in
  match c_read.disp with
  | Closed -> Error(Dispatcher,InvalidState)
  | _ ->
  match (ct,frag,c_read.disp) with 

  | ContentType.Handshake, TLSFragment.FHandshake(f), x when x = Init || x = FirstHandshake || x = Finishing || x = Open ->
    let readSeqN = c_read.seqn in
    let c_hs = c.handshake in
    match Handshake.recv_fragment id c_hs tlen f with
    | (Correct(corr),hs) ->
        let ad = AppDataStream.writeNonAppDataFragment id c.appdata in
        let new_seqn = readSeqN+1 in
        let c_read = {c_read with seqn = new_seqn} in
        match corr with
        | Handshake.HSAck ->
            let c = { c with read = c_read; appdata = ad; handshake = hs} in
            correct (RAgain, Conn(id,c))
        | Handshake.HSVersionAgreed pv ->
            match c_read.disp with
            | Init ->
                (* Then, also c_write must be in Init state. It means this is the very first, unprotected handshake,
                   and we just negotiated the version.
                   Set the negotiated version in the current sinfo (read and write side), 
                   and move to the FirstHandshake state, so that
                   protocol version will be properly checked *)

                // Check we really are on a null session
                let id_in = id.id_in in
                let id_out = id.id_out in
                let old_in_sinfo = id_in.sinfo in
                let old_out_sinfo = id_out.sinfo in
                let c_write = c.write in
                if isNullSessionInfo old_out_sinfo && isNullSessionInfo old_in_sinfo then
                    // update the state
                    let new_read = {c_read with disp = FirstHandshake} in
                    let new_write = {c_write with disp = FirstHandshake} in
                    let c = {c with handshake = hs;
                                    appdata = ad;
                                    read = new_read;
                                    write = new_write} in
                    // reIndex everything
                    let new_sinfo = {old_out_sinfo with protocol_version = pv } in // equally with id.id_in.sinfo
                    let idIN = {id_in with sinfo = new_sinfo} in
                    let idOUT = {id_out with sinfo = new_sinfo} in
                    let newID = {id_in = idIN; id_out = idOUT} in
                    let c = reIndex_null id newID c in
                    correct (RAgain, Conn(newID,c) )
                else
                    let closed = closeConnection (Conn(id,c)) in
                    Error(Dispatcher,InvalidState)
            | _ -> (* It means we are doing a re-negotiation. Don't alter the current version number, because it
                     is perfectly valid. It will be updated after the next CCS, along with all other session parameters *)
                let c = { c with read = c_read; appdata = ad; handshake = hs} in
                (correct (RAgain, Conn(id, c) ))
        | Handshake.HSReadSideFinished ->
        (* Ensure we are in Finishing state *)
            match x with
            | Finishing ->
                let c = {c with read = c_read; appdata = ad; handshake = hs} in
                // Indeed, we should stop reading now!
                // (Because, except for false start implementations, the other side is now
                //  waiting for us to send our finished message)
                // However, if we say RHSDone, the library will report an early completion of HS
                // (we still have to send our finished message).
                // So, here we say ReadAgain, which will anyway first flush our output buffers,
                // this sending our finished message, and thus letting us get the WHSDone event.
                // I know, it's tricky and it sounds fishy, but that's the way it is now.
                correct (RAgain,Conn(id,c))
            | _ -> let closed = closeConnection (Conn(id,{c with handshake = hs})) in Error(Dispatcher,InvalidState) // TODO: We might want to send some alert here
        | Handshake.HSFullyFinished_Read(newSI,newMS,newDIR) ->
            let newInfo = (newSI,newMS,newDIR) in
            let c = {c with read = c_read; appdata = ad; handshake = hs} in
            (* Ensure we are in Finishing state *)
            match x with
            | Finishing ->
                // Sanity check: in and out session infos should be the same
                if id.id_in.sinfo = id.id_out.sinfo then
                    let c = moveToOpenState (Conn(id,c)) newInfo in
                    correct(RHSDone, Conn(id,c))
                else let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,CheckFailed) // TODO: we might want to send an internal_error fatal alert here.
            | _ -> let closed = closeConnection (Conn(id,c)) in Error(Dispatcher,InvalidState) // TODO: We might want to send some alert here.
    | (Error(x,y),hs) -> let c = {c with handshake = hs} in Error(x,y) (* TODO: we might need to send some alerts *)

  | Change_cipher_spec, TLSFragment.FCCS(f), x when x = FirstHandshake || x = Open -> 
    match Handshake.recv_ccs id c.handshake tlen f with 
    | (Correct(ccs),hs) ->
        let (newKiIN,ccs_data) = ccs in
        if checkCompatibleSessions id.id_in.sinfo newKiIN.sinfo c.poptions then
            let c = {c with handshake = hs} in
            let newID = {id with id_in = newKiIN} in
            let c = reIndex_in id newID c ccs_data in
            let new_read = {c.read with disp = Finishing; seqn = 0} in
            let newad = AppDataStream.reset_incoming newID c.appdata in
            let c = { c with read = new_read; appdata = newad}
            correct (RAgain, Conn(newID,c))
        else
            let closed = closeConnection (Conn(id,c)) in Error(Dispatcher, UserAborted) (* TODO: we might want to send an "internal error" fatal alert *)
    | (Error (x,y),hs) ->
        let c = {c with handshake = hs} in
        let closed = closeConnection (Conn(id,c)) in
        Error (x,y) // TODO: We might want to send some alert here.

  | Alert, TLSFragment.FAlert(f), _ ->
    match Alert.recv_fragment id c.alert tlen f with
    | Correct (Alert.ALAck(state)) ->
      let ad = AppDataStream.writeNonAppDataFragment id c.appdata in
      let new_seqn = c_read.seqn + 1 in
      let c_read = {c_read with seqn = new_seqn; disp = Closing} in
      let c = {c with read = c_read; appdata = ad; alert = state} in
      correct (RAgain, Conn(id,c))
    | Correct (Alert.ALClose_notify (state)) ->
        (* An outgoing close notify has already been buffered, if necessary *)
        (* Only close the reading side of the connection *)
        let ad = AppDataStream.writeNonAppDataFragment id c.appdata in
        let new_seqn = c_read.seqn + 1 in
        let new_read = {c_read with seqn = new_seqn; disp = Closed} in
        correct (RClose, Conn(id, { c with appdata = ad; read = new_read}))
    | Correct (Alert.ALClose (state)) ->
        (* Other fatal alert, we close both sides of the connection *)
        let ad = AppDataStream.writeNonAppDataFragment id c.appdata in
        let new_seqn = c_read.seqn + 1 in
        let new_read = {c_read with seqn = new_seqn} in
        let c = {c with read = new_read; appdata = ad; alert = state}
        let closed = closeConnection (Conn(id,c)) in
        // FIXME: We need to get some info about the alert we just received!
        let inventedAlert = AD_internal_error in
        correct (RFatal(inventedAlert), closed )
    | Error (x,y) -> let closed = closeConnection(Conn(id,c)) in Error(x,y) // TODO: We might want to send some alert here.

  | Application_data, TLSFragment.FAppData(f), Open -> 
    let appstate = AppDataStream.writeAppDataFragment id c.appdata (tlen) f in
    let new_seqn = c_read.seqn + 1;
    let new_read = {c_read with seqn = new_seqn} in
    let c = {c with read = new_read; appdata = appstate} in
    correct (RAppDataDone, Conn(id, c))
  | _, _, _ -> let closed = closeConnection(Conn(id,c)) in Error(Dispatcher,InvalidState) // TODO: We might want to send some alert here.
  
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
                // printf "%s[%d] " (Formats.CTtoString ct) len; 
                let c_read = c.read in
                let c_read_conn = c_read.conn in
                let c_read_seqn = c_read.seqn in
                match Record.recordPacketIn id.id_in c_read_conn c_read_seqn (header @| payload) with
                | Error(x,y) -> Error(x,y)
                | Correct(pack) -> 
                    let (c_recv,ct,pv,tl,f) = pack in
                    if c.read.disp = Init || pv = id.id_in.sinfo.protocol_version then
                        let c_read = {c_read with conn = c_recv} in
                        let c = {c with read = c_read} in
                        correct(Conn(id,c),ct,tl,f)
                    else
                        Error(RecordVersion,CheckFailed)

let readOne c =
    match recv c with
    | Error(x,y) -> Error(x,y)
    | Correct(received) -> let (c,ct,tl,f) = received in deliver c ct tl f

let rec writeAll c =
    match writeOne c with
    | Correct (WriteAgain,c) -> writeAll c
    | other -> other

let rec read c =
    let unitVal = () in
    match writeAll c with
    | Error(x,y) -> ReadError(x,y)
    | Correct(WAppDataDone,c) | Correct(MustRead,c) ->
        // Nothing more to write. We can try to read now.
        // (Note: In fact, WAppDataDone here means "nothing sent",
        // because the output buffer is always empty
        // TODO
        ReadError(Dispatcher,Unsupported)
    | Correct(WHSDone,c) ->
        Handshaken (c)
    | Correct(SentFatal(ad),c) ->
        Fatal(ad)
    | Correct(SentClose,c) ->
        let (Conn(id,conn)) = c in
        match conn.read.disp with
        | Closed ->
            // we already received a close_notify, tell the user it's over
            Close conn.ns
        | _ ->

    | (Correct(unitVal),c) ->
        match (readOne c, stopAt) with
        | ((Error(x,y),c),_) ->
            (Error(x,y),c)
        | ((Correct (ReadAgain)  ,c), _)
        | ((Correct (AppDataDone),c), StopAtHS)
        | ((Correct (HSDone)     ,c), StopAtAppData) ->
            read c stopAt
        | ((Correct (AppDataDone),c), StopAtAppData)
        | ((Correct (HSDone)     ,c), StopAtHS) ->
            writeFromRead c
        | ((Correct (Abort)      ,c), _) ->
            match writeFromRead c with
            | (Error(x,y),c) -> (Error(x,y),c)
            | (Correct(unitVal),c) -> (Error(TLS,ConnectionClosed),c)

let rec writeAppData c = 
    let unitVal = () in
    match writeOne c with
    | (Error (x,y),c) -> (Error(x,y),c)
    | (Correct (WriteAgain),c) -> writeAppData c
    | (Correct (Done)      ,c) -> (correct(unitVal),c)
    | (Correct (MustRead)  ,c) -> read c StopAtHS

    (* If available, read next data *)
    (* 
    let c_read = conn.read in
    match c_read.disp with
    | Closed -> writeOneAppFragment conn
    | _ ->
    match Tcp.dataAvailable conn.ns with
    | Error (x,y) -> (Error(x,y),conn)
    | Correct canRead ->
    if canRead then
        match recv conn.ns c_read conn.ds_info with
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
    *)

let writeDelta (Conn(id,c)) r d = 
  let new_appdata = AppDataStream.writeAppData id c.appdata r d in
  let c = {c with appdata = new_appdata} in 
  match  writeAppData (Conn(id,c))with
    | (Correct(_),(Conn(id,c))) ->
         let (rd,new_appdata) = AppDataStream.emptyOutgoingAppData id c.appdata in
         let c = {c with appdata = new_appdata} in 
           (Conn(id,c),correct (rd))
    | (Error(x,y),c) -> c,Error(x,y)

  

let commit (Conn(id,c)) ls b =
    let new_appdata = AppDataStream.writeAppData id c.appdata ls b in
    Conn(id,{c with appdata = new_appdata})

(*
let write_buffer_empty conn =
    AppDataStream.is_outgoing_empty conn.appdata
*)

let readAppData (Conn(id,c)) =
    let unitVal = () in
    let newConnRes =
        if AppDataStream.is_incoming_empty id c.appdata then
            read (Conn(id,c)) StopAtAppData    
        else
            (correct(unitVal),Conn(id,c))
    match newConnRes with
    | (Error(x,y),conn) -> (conn,Error(x,y))
    | (Correct(unitVal),Conn(id,c)) ->
        let (Some(b),appState) = AppDataStream.readAppData id c.appdata in
        let c = {c with appdata = appState} in
        (Conn(id,c),correct (b))

    (* Similar to the OpenSSL strategy *)
    (*
    let c_appdata = conn.appdata in
    if not (AppDataStream.is_incoming_empty c_appdata) then
        (* Read from the buffer *)
        let (read, new_appdata) = AppDataStream.retrieve_data c_appdata in
        let conn = {conn with appdata = new_appdata} in
        (correct (read),conn)
    else
        (* Read from the TCP socket *)
        match readNextAppFragment conn with
        | (Correct (x),conn) ->
            (* One fragment may have been put in the buffer *)
            let c_appdata = conn.appdata in
            let (read, new_appdata) = AppDataStream.retrieve_data c_appdata in
            let conn = {conn with appdata = new_appdata} in
            (correct (read),conn)
        | (Error (x,y),c) -> (Error(x,y),c)
    *)

let readDelta c = readAppData c


let readHS conn = read conn StopAtHS
