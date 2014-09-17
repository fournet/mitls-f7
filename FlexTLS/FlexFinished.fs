#light "off"

module FlexFinished

open Bytes
open Error
open TLSInfo
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake
open FlexSecrets

type FlexFinished = 
    class

    (* Receive an expected Finished message from the network stream and check log on demand *)
    static member receive (st:state, ?log:bytes) : state * FFinished = 
        let log = defaultArg log empty_bytes in
        let checkLog = not (log = empty_bytes) in

        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_finished  -> 
            if length payload <> 12 then
                failwith (perror __SOURCE_FILE__ __LINE__ "unexpected payload length")
            else
                let ff = {  verify_data = payload; 
                            payload = to_log;
                } in
                if checkLog then
                    if not (log = payload) then failwith "Log message received doesn't match" else st,ff
                else
                    st,ff
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "message type is not HT_finished")

    static member send (st:state, ff:FFinished, ?fp:fragmentationPolicy) : state * FFinished =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        FlexFinished.send(st,ff.verify_data,fp=fp)

    (* Prepare Finished message bytes *)
    static member prepare (st:state, ?verify_data:bytes, ?logRoleNSC:bytes * Role * nextSecurityContext) : bytes * state * FFinished =
        let verify_data =
            match logRoleNSC with
            | Some(log,role,nsc) -> FlexSecrets.makeVerifyData nsc.si nsc.keys.ms role log
            | None ->
                match verify_data with
                | None -> failwith (perror __SOURCE_FILE__ __LINE__ "One of verify_data or (log, role, nextSecurityContext) must be provided")
                | Some(vd) -> vd
        in
        let payload = HandshakeMessages.messageBytes HT_finished verify_data in
        let ff = { verify_data = verify_data;
                   payload = payload;
                 } in
        payload,st,ff

    (* Send Finished message to the network stream *)
    static member send (st:state, ?verify_data:bytes, ?logRoleNSC:bytes * Role * nextSecurityContext, ?fp:fragmentationPolicy) : state * FFinished =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let verify_data =
            match logRoleNSC with
            | Some(log,role,nsc) -> FlexSecrets.makeVerifyData nsc.si nsc.keys.ms role log
            | None ->
                match verify_data with
                | None -> failwith (perror __SOURCE_FILE__ __LINE__ "One of verify_data or (log, role, nextSecurityContext) must be provided")
                | Some(vd) -> vd
        in
        let payload = HandshakeMessages.messageBytes HT_finished verify_data in
        let st = FlexHandshake.send(st,payload,fp) in
        let ff = { verify_data = verify_data;
                   payload = payload;
                 } in
        st,ff

    end
    