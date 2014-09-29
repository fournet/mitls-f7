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

    //BB : Should we reverse priority between logRoleNSC and verify_data ?

    /// <summary>
    /// Receive a Finished message from the network stream and check the verify_data on demand
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="verify_data"> Optional verify_data that will be checked if provided </param>
    /// <returns> Updated state * FFinished message record </returns>
    static member receive (st:state, ?verify_data:bytes, ?logRoleNSC:bytes * Role * nextSecurityContext) : state * FFinished = 
        let verify_data =
            match logRoleNSC with
            | Some(log,role,nsc) -> FlexSecrets.makeVerifyData nsc.si nsc.keys.ms role log
            | None ->
                match verify_data with
                | None -> failwith (perror __SOURCE_FILE__ __LINE__ "One of verify_data or (log, role, nextSecurityContext) must be provided")
                | Some(vd) -> vd
        in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_finished  -> 
            if length payload <> 12 then
                failwith (perror __SOURCE_FILE__ __LINE__ "unexpected payload length")
            else
                // Check the verify data value
                if not (verify_data = payload) then failwith "Log message received doesn't match" else
                let ff = {  verify_data = payload; 
                            payload = to_log;
                } in
                st,ff
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "message type is not HT_finished")

    /// <summary>
    /// Prepare a Finished message from the network stream and check the verify_data on demand
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="verify_data"> Optional verify_data that will be checked if provided </param>
    /// <param name="logRoleNSC"> Optional triplet that includes the log the role and the next security context and that compute the verify data if provided </param>
    /// <returns> Finished message bytes * Updated state * FFinished message record </returns>
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

    /// <summary>
    /// Overload : Send a Finished message from the network stream and check the verify_data on demand
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="ff"> Optional finished message record including the payload to be used </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FFinished message record </returns>
    static member send (st:state, ff:FFinished, ?fp:fragmentationPolicy) : state * FFinished =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        FlexFinished.send(st,ff.verify_data,fp=fp)


    /// <summary>
    /// Send a Finished message from the network stream and check the verify_data on demand
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="verify_data"> Optional verify_data that will be checked if provided </param>
    /// <param name="logRoleNSC"> Optional triplet that includes the log the role and the next security context and that compute the verify data if provided </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FFinished message record </returns>
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
    