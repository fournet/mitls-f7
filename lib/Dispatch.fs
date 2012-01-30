module Dispatch

open Bytes
open Formats
//open Record
open Tcp
open Error
open Handshake
open AppData
open Alert
open TLSInfo
open TLSKey
open AppCommon
open SessionDB

type predispatchState =
  | Init (* of ProtocolVersion * ProtocolVersion *) (* min and max *)
  | FirstHandshake (* of ProtocolVersion *)             (* set by the ServerHello *) 
  | Finishing
  | Finished (* Only for Writing side, used to avoid sending data on a partially completed handshake *)
  | Open
  | Closing
  | Closed

type dispatchState = predispatchState

type dState = {
    disp: dispatchState;
    conn: Record.ConnectionState;
    seqn: int
    }

type index = {
    id_in: KeyInfo;
    id_out: KeyInfo}

type globalState = {
  poptions: protocolOptions;
  (* abstract protocol states for HS/CCS, AL, and AD *)
  handshake: Handshake.hs_state
  alert    : Alert.state
  appdata  : AppData.app_state    

  (* connection state for reading and writing *)
  read  : dState;
  write : dState;

  (* The actual socket *)
  ns: NetworkStream;
  }

type Connection = Conn of index * globalState
type SameConnection = Connection

(* Writing and reading have asymmetric outcomes, because writing is easier, and requires less care.
   We can always try to write "once more", and stop when we realize we have no data to send.
   When reading, we must be careful and only read when we know there must be more data, or we'll block
   in deadlock. *)
type writeOutcome =
    | WriteAgain (* Possibly more data to send *)
    | Done (* No more data to send in the current state *)
    | MustRead (* Read until completion of Handshake *)

type deliverOutcome =
    | ReadAgain
    | AppDataDone
    | HSDone
    | Abort

let init ns dir poptions =
    (* Direction "dir" is always the outgoing direction.
       So, if we are a Client, it will be CtoS, if we're a Server: StoC *)
    let outKI = null_KeyInfo dir poptions.minVer in
    let inKI = dual_KeyInfo outKI in
    let hs = Handshake.init_handshake outKI.sinfo dir poptions in // Equivalently, inKI.sinfo
    let (outCCS,inCCS) = (nullCCSData outKI, nullCCSData inKI) in
    let (send,recv) = (Record.initConnState outKI outCCS, Record.initConnState inKI inCCS) in
    let read_state = {disp = Init; conn = recv; seqn = 0} in
    let write_state = {disp = Init; conn = send; seqn = 0} in
    let al = Alert.init outKI.sinfo in
    let app = AppData.init outKI.sinfo in // or equivalently inKI.sinfo
    Conn ( {id_in = inKI; id_out = outKI},
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
    let (retrievedSinfo,retrievedMS,retrievedDir) = retrieved in
    match retrievedDir with
    | StoC -> unexpectedError "[resume] requested session is for server side"
    | CtoS ->
    let outKI = null_KeyInfo CtoS ops.minVer in
    let inKI = dual_KeyInfo outKI in
    let hs = Handshake.resume_handshake outKI.sinfo retrievedSinfo retrievedMS ops in // equivalently, inKI.sinfo
    let (outCCS,inCCS) = (nullCCSData outKI, nullCCSData inKI) in
    let (send,recv) = (Record.initConnState outKI outCCS, Record.initConnState inKI inCCS) in
    let read_state = {disp = Init; conn = recv; seqn = 0} in
    let write_state = {disp = Init; conn = send; seqn = 0} in
    let al = Alert.init outKI.sinfo in
    let app = AppData.init outKI.sinfo in // or equvalently inKI.sinfo
    let res = Conn ( {id_in = inKI; id_out = outKI},
                     { poptions = ops;
                       handshake = hs;
                       alert = al;
                       appdata = app;
                       read = read_state;
                       write = write_state;
                       ns = ns;}) in
    let unitVal = () in
    (correct (unitVal), res)

let ask_rehandshake (Conn(id,conn)) ops =
    let new_hs = Handshake.start_rehandshake id.id_out.sinfo conn.handshake ops in // Equivalently, id.id_in.sinfo
    Conn(id,{conn with handshake = new_hs;
                       poptions = ops})

let ask_rekey (Conn(id,conn)) ops =
    let new_hs = Handshake.start_rekey id.id_out.sinfo conn.handshake ops in // Equivalently, id.id_in.sinfo
    Conn(id,{conn with handshake = new_hs;
                       poptions = ops})

let ask_hs_request (Conn(id,conn)) ops =
    let new_hs = Handshake.start_hs_request id.id_out.sinfo conn.handshake ops in // Equivalently, id.id_in.sinfo
    Conn(id,{conn with handshake = new_hs;
                       poptions = ops})

(*
let appDataAvailable conn =
    AppData.retrieve_data_available conn.appdata
*)

let getSessionInfo (Conn(id,conn)) =
    id.id_out.sinfo // in Open and Closed state, this should be equivalent to id.id_in.sinfo

let checkCompatibleSessions s1 s2 poptions =
    (isNullSession s1) || 
    (s1 = s2) || 
    (poptions.isCompatibleSession s1 s2)

let moveToOpenState (Conn(id,c)) new_storable_info =
    (* If appropriate, store this session in the DB *)
    let (storableSinfo,storableMS,storableDir) = new_storable_info in
    match storableSinfo.sessionID with
    | None -> (* This session should not be stored *) ()
    | Some (sid) -> (* SessionDB. *) insert c.poptions sid new_storable_info

    // Sanity check: in and out session infos should be the same
    if id.id_in.sinfo = id.id_out.sinfo then
        let read = c.read in
        match read.disp with
        | Finishing | Finished ->
            let new_read = {read with disp = Open} in
            let c_write = c.write in
            match c_write.disp with
            | Finishing | Finished ->
                let new_write = {c_write with disp = Open} in
                correct({c with read = new_read; write = new_write})
            | _ -> unexpectedError "[moveToOpenState] should only work on Finishing or Finished write states"
        | _ -> unexpectedError "[moveToOpenState] should only work on Finishing read states"
    else
        Error(Dispatcher,CheckFailed)

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
let writeOne (Conn(id,c)) : (writeOutcome Result) * Connection =
  let c_write = c.write in
  match c_write.disp with
  | Closed -> (correct(Done), Conn(id,c))
  | _ ->
      let state = c.alert in
      match Alert.next_fragment id.id_out c_write.seqn state with
      | (Alert.EmptyALFrag,_) -> 
          let hs_state = c.handshake in
          match Handshake.next_fragment id.id_out c_write.seqn hs_state with 
          | (Handshake.EmptyHSFrag, _) ->
            let app_state = c.appdata in
                match AppData.next_fragment id.id_out c_write.seqn app_state with
                | None -> (* nothing to do (tell the caller) *)
                          (correct (Done),Conn(id,c))
                | Some (next) ->
                          let ((tlen,f),new_app_state) = next in
                          match c_write.disp with
                          | Open ->
                          (* we send some data fragment *)
                            match send id.id_out c.ns c_write tlen Application_data (TLSFragment.FAppData(f)) with
                            | Correct(new_write) ->
                                let c = { c with appdata = new_app_state;
                                                 write = new_write }
                                (* Eagerly write more appdata now, if available *)
                                (correct (WriteAgain), Conn(id,c) )
                            | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in (Error(x,y), closed) (* Unrecoverable error *)
                          | _ ->
                            (* We have data to send, but we cannot now. It means we're finishing a handshake.
                               Force to read, so that we'll complete the handshake and we'll be able to send
                               such data. *)
                            (* NOTE: here we do not use the new_app_state! Instead, on purpose we use the old
                                     app_state, where the fragment had not been consumed, so, next time we ask
                                     for a fragment we get back the same one and we can send it on the network.
                                     With linear types in mind, this means that "sending" a fragment consumes it,
                                     not retrieving a fragment from its upper protocol (and so makes the state
                                     of the protocol not completely linear...) *)
                            (Correct(MustRead), Conn(id,c))   
          | (Handshake.CCSFrag(frag,newKeys),new_hs_state) ->
                    let (tlen,ccs) = frag in
                    let (newKiOUT,ccs_data) = newKeys in
                    (* we send a (complete) CCS fragment *)
                    match c_write.disp with
                    | x when x = FirstHandshake || x = Open ->
                        match send id.id_out c.ns c_write tlen Change_cipher_spec (TLSFragment.FCCS(ccs)) with
                        | Correct _ -> (* We don't care about next write state, because we're going to reset everything after CCS *)
                            if checkCompatibleSessions id.id_out.sinfo newKiOUT.sinfo c.poptions then
                                (* Now:
                                    - update the outgoing index in Dispatch
                                    - update the outgoing keys in Record
                                    - move the outgoing state to Finishing, to signal we must not send appData now. *)
                                let id = {id with id_out = newKiOUT } in
                                let ss = Record.initConnState id.id_out ccs_data in
                                let new_write = {disp = Finishing; conn = ss; seqn = 0} in
                                let c = { c with handshake = new_hs_state;
                                                             write = new_write }
                                (correct (WriteAgain), Conn(id,c) )
                            else
                                (Error(Dispatcher, UserAborted), closeConnection (Conn(id,c))) (* TODO: we might want to send an "internal error" fatal alert *)
                        | Error (x,y) -> (Error (x,y), closeConnection (Conn(id,c))) (* Unrecoverable error *)
                    | _ -> (Error(Dispatcher, InvalidState), closeConnection (Conn(id,c))) (* TODO: we might want to send an "internal error" fatal alert *)
          | (Handshake.HSFrag(tlen,f),new_hs_state) ->     
                      (* we send some handshake fragment *)
                      match c_write.disp with
                      | x when x = Init || x = FirstHandshake ||
                               x = Finishing || x = Open ->
                          match send id.id_out c.ns c_write tlen Handshake (TLSFragment.FHandshake(f)) with 
                          | Correct(new_write) ->
                            let c = { c with handshake = new_hs_state;
                                             write     = new_write }
                            (correct (WriteAgain), Conn(id,c) )
                          | Error (x,y) -> (Error(x,y), closeConnection (Conn(id,c))) (* Unrecoverable error *)
                      | _ -> (Error(Dispatcher,InvalidState), closeConnection (Conn(id,c))) (* TODO: we might want to send an "internal error" fatal alert *)
          | (Handshake.HSWriteSideFinished(tlen,lastFrag),new_hs_state) ->
                (* check we are in finishing state *)
                match c_write.disp with
                | Finishing ->
                    (* Send the last fragment *)
                    match send id.id_out c.ns c_write tlen Handshake (TLSFragment.FHandshake(lastFrag)) with 
                          | Correct(new_write) ->
                            (* Also move to the Finished state *)
                            let c_write = {new_write with disp = Finished} in
                            let c = { c with handshake = new_hs_state;
                                             write     = c_write }
                            (correct (WriteAgain), Conn(id,c))
                          | Error (x,y) -> (Error(x,y), closeConnection (Conn(id,c))) (* Unrecoverable error *)
                | _ -> (Error(Dispatcher,InvalidState), closeConnection (Conn(id,c))) (* TODO: we might want to send an "internal error" fatal alert *)
          | (Handshake.HSFullyFinished_Write((tlen,lastFrag),new_info),new_hs_state) ->
                match c_write.disp with
                | Finishing ->
                    (* Send the last fragment *)
                    match send id.id_out c.ns c_write tlen Handshake (TLSFragment.FHandshake(lastFrag)) with 
                    | Correct(new_write) ->
                        let c = { c with handshake = new_hs_state;
                                         write     = new_write }
                        (* Move to the new state *)
                        match moveToOpenState (Conn(id,c)) new_info with
                        | Error(x,y) -> (Error(x,y),closeConnection (Conn(id,c))) // do not send alerts! We are on a new session, and the user does not like it. Just close everything!
                        | Correct(c) -> (correct(WriteAgain),Conn(id,c))
                    | Error (x,y) -> (Error(x,y), closeConnection (Conn(id,c))) (* Unrecoverable error *)
                | _ -> (Error(Dispatcher,InvalidState), closeConnection (Conn(id,c))) (* TODO: we might want to send an "internal error" fatal alert *)
      | (Alert.ALFrag(tlen,f),new_al_state) ->        
        match send id.id_out c.ns c_write tlen Alert (TLSFragment.FAlert(f)) with 
        | Correct(new_write) ->
            let new_write = {new_write with disp = Closing} in
            (correct (WriteAgain), Conn(id,{ c with alert = new_al_state;
                                                    write   = new_write } ))
        | Error (x,y) -> (Error(x,y), closeConnection (Conn(id,c))) (* Unrecoverable error *)
      | (Alert.LastALFrag(tlen,f),new_al_state) ->
        (* We're sending a fatal alert. Send it, then close both sending and receiving sides *)
        match send id.id_out c.ns c_write tlen Alert (TLSFragment.FAlert(f)) with 
        | Correct(new_write) ->
            let c = {c with alert = new_al_state;
                            write = new_write}
            (correct (Done), closeConnection (Conn(id,c)))
        | Error (x,y) -> (Error(x,y), closeConnection (Conn(id,c))) (* Unrecoverable error *)
      | (Alert.LastALCloseFrag(tlen,f),new_al_state) ->
        (* We're sending a close_notify alert. Send it, then only close our sending side.
           If we already received the other close notify, then reading is already closed,
           otherwise we wait to read it, then close. But do not close here. *)
        match send id.id_out c.ns c_write tlen Alert (TLSFragment.FAlert(f)) with
        | Correct(new_write) ->
            let new_write = {new_write with disp = Closed} in
            let c = {c with alert = new_al_state;
                            write = new_write}
            (correct (Done), Conn(id,c))
        | Error (x,y) -> (Error(x,y), closeConnection (Conn(id,c))) (* Unrecoverable error *)

(* we have received, decrypted, and verified a record (ct,f); what to do? *)
let deliver (Conn(id,c)) ct tlen frag = 
  let c_read = c.read in
  match c_read.disp with
  | Closed -> (correct(Abort),Conn(id,c))
  | _ ->
  match (ct,frag,c_read.disp) with 

  | Handshake, TLSFragment.FHandshake(f), x when x = Init || x = FirstHandshake || x = Finishing || x = Open ->
    match Handshake.recv_fragment id.id_in c_read.seqn c.handshake tlen f with
    | (Correct(corr),hs) ->
        let new_seqn = c_read.seqn+1 in
        let c_read = {c_read with seqn = new_seqn} in
        match corr with
        | Handshake.HSAck ->
            (correct (ReadAgain), Conn(id,{ c with read = c_read; handshake = hs}) )
        | Handshake.HSVersionAgreed pv ->
            match c_read.disp with
            | Init ->
                (* Then, also c_write must be in Init state. It means this is the very first, unprotected handshake,
                   and we just negotiated the version.
                   Set the negotiated version in the current sinfo (read and write side), 
                   and move to the FirstHandshake state, so that
                   protocol version will be properly checked *)
                let new_sinfo = {id.id_out.sinfo with protocol_version = pv } in // equally with id.id_in.sinfo
                let idIN = {id.id_in with sinfo = new_sinfo} in
                let idOUT = {id.id_out with sinfo = new_sinfo} in
                let id = {id_in = idIN; id_out = idOUT} in
                let new_read = {c_read with disp = FirstHandshake} in
                let new_write = {c.write with disp = FirstHandshake} in
                (correct (ReadAgain), Conn(id, { c with handshake = hs;
                                                        read = new_read;
                                                        write = new_write}) )
            | _ -> (* It means we are doing a re-negotiation. Don't alter the current version number, because it
                     is perfectly valid. It will be updated after the next CCS, along with all other session parameters *)
                ((correct (ReadAgain), Conn(id, { c with read = c_read; handshake = hs}) ))
        | Handshake.HSReadSideFinished ->
        (* Ensure we are in Finishing state *)
            match x with
            | Finishing ->
                (correct (HSDone),Conn(id,{c with read = c_read; handshake = hs}))
            | _ -> (Error(Dispatcher,InvalidState), closeConnection (Conn(id,{c with handshake = hs})) ) // TODO: We might want to send some alert here
        | Handshake.HSFullyFinished_Read(new_info) ->
            let c = {c with read = c_read; handshake = hs} in
            (* Ensure we are in Finishing state *)
            match x with
            | Finishing ->
                match moveToOpenState (Conn(id,c)) new_info with
                | Error(x,y) -> (Error(x,y), closeConnection (Conn(id,c))) // do not send alerts! We are on a new session, and the user does not like it. Just close everything!
                | Correct(c) -> (correct(HSDone), Conn(id,c))
            | _ -> (Error(Dispatcher,InvalidState), closeConnection (Conn(id,c))) // TODO: We might want to send some alert here.
    | (Error(x,y),hs) -> (Error(x,y),Conn(id,{c with handshake = hs})) (* TODO: we might need to send some alerts *)

  | Change_cipher_spec, TLSFragment.FCCS(f), x when x = FirstHandshake || x = Open -> 
    match Handshake.recv_ccs id.id_in c_read.seqn c.handshake tlen f with 
    | (Correct(ccs),hs) ->
        let (newKiIN,ccs_data) = ccs in
        if checkCompatibleSessions id.id_in.sinfo newKiIN.sinfo c.poptions then
            let id = {id with id_in = newKiIN} in
            let new_recv = Record.initConnState id.id_in ccs_data in
            let new_read = {disp = Finishing; conn = new_recv; seqn = 0} in
            let c = { c with handshake = hs;
                             read = new_read}
            (correct (ReadAgain), Conn(id,c))
        else
            (Error(Dispatcher, UserAborted), closeConnection (Conn(id,c))) (* TODO: we might want to send an "internal error" fatal alert *)
    | (Error (x,y),hs) -> (Error (x,y), closeConnection (Conn(id,{c with handshake = hs}))) // TODO: We might want to send some alert here.

  | Alert, TLSFragment.FAlert(f), _ ->
    match Alert.recv_fragment id.id_in c_read.seqn c.alert tlen f with
    | Correct (Alert.ALAck(state)) ->
      let new_seqn = c_read.seqn + 1 in
      let c_read = {c_read with seqn = new_seqn; disp = Closing} in
      let c = {c with read = c_read; alert = state} in
      (correct (ReadAgain), Conn(id,c))
    | Correct (Alert.ALClose_notify (state)) ->
        (* An outgoing close notify has already been buffered, if necessary *)
        (* Only close the reading side of the connection *)
        let new_seqn = c_read.seqn + 1 in
        let new_read = {c_read with seqn = new_seqn; disp = Closed} in
        (correct (Abort), Conn(id, { c with read = new_read}))
    | Correct (Alert.ALClose (state)) ->
        (* Other fatal alert, we close both sides of the connection *)
        let new_seqn = c_read.seqn + 1 in
        let new_read = {c_read with seqn = new_seqn} in
        let c = {c with read = new_read; alert = state}
        (correct (Abort), closeConnection (Conn(id,c)))
    | Error (x,y) -> (Error(x,y),closeConnection(Conn(id,c))) // TODO: We might want to send some alert here.

  | Application_data, TLSFragment.FAppData(f), Open -> 
    let appstate = AppData.recv_fragment id.id_in c_read.seqn c.appdata tlen f in
    let new_seqn = c_read.seqn + 1;
    let new_read = {c_read with seqn = new_seqn} in
    let c = {c with read = new_read; appdata = appstate} in
    (correct (AppDataDone), Conn(id, c))
  | _, _, _ -> (Error(Dispatcher,InvalidState),closeConnection(Conn(id,c))) // TODO: We might want to send some alert here.
  
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
                match Record.recordPacketIn id.id_in c.read.conn c.read.seqn (header @| payload) with
                | Error(x,y) -> Error(x,y)
                | Correct(pack) -> 
                    let (c_recv,ct,pv,tl,f) = pack in
                    if c.read.disp = Init || pv = id.id_in.sinfo.protocol_version then
                        let c_read = {c.read with conn = c_recv} in
                        let c = {c with read = c_read} in
                        correct(Conn(id,c),ct,tl,f)
                    else
                        Error(RecordVersion,CheckFailed)

let readOne c =
    match recv c with
    | Error(x,y) -> (Error(x,y),c)
    | Correct(received) -> let (c,ct,tl,f) = received in deliver c ct tl f

let rec writeFromRead c =
    let unitVal = () in
    match writeOne c with
    | (Error (x,y),c) -> (Error(x,y),c)
    | (Correct (WriteAgain),c) -> writeFromRead c
    | (Correct (Done)      ,c) -> (correct(unitVal),c)
    | (Correct (MustRead)  ,c) -> (correct(unitVal),c)

type preReadInvocation =
    | StopAtHS
    | StopAtAppData

type readInvocation = preReadInvocation

let rec read c stopAt =
    let unitVal = () in
    match writeFromRead c with
    | (Error(x,y),c) -> (Error(x,y),c)
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

let commit (Conn(id,c)) ls b =
    let new_appdata = AppData.send_data id.id_out.sinfo c.appdata ls b in
    Conn(id,{c with appdata = new_appdata})

(*
let write_buffer_empty conn =
    AppData.is_outgoing_empty conn.appdata
*)

let readAppData (Conn(id,c)) =
    let unitVal = () in
    let newConnRes =
        if AppData.is_incoming_empty id.id_in.sinfo c.appdata then
            read (Conn(id,c)) StopAtAppData    
        else
            (correct(unitVal),Conn(id,c))
    match newConnRes with
    | (Error(x,y),conn) -> (Error(x,y),conn)
    | (Correct(unitVal),Conn(id,c)) ->
        let (b,appState) = AppData.retrieve_data id.id_in.sinfo c.appdata in
        let c = {c with appdata = appState} in
        (correct (b),Conn(id,c))

    (* Similar to the OpenSSL strategy *)
    (*
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
    *)

let readHS conn = read conn StopAtHS
