#light "off"

module FlexTLS.FlexFinished

open NLog

open Bytes
open Error
open TLSInfo
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexState
open FlexHandshake
open FlexSecrets




/// <summary>
/// Module receiving, sending and forwarding TLS Finished messages.
/// </summary>
type FlexFinished = 
    class

    /// <summary>
    /// Receive a Finished message from the network stream and check the verify_data on demand
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="verify_data"> Optional expected verify_data that will be checked if provided </param>
    /// <param name="logRoleNSC"> Optional log, role, and next security context used to compute an expected verify data (has priority over the verify_data optional parameter) </param>
    /// <returns> Updated state * FFinished message record </returns>
    static member receive (st:state, ?verify_data:bytes, ?logRoleNSC:bytes * Role * nextSecurityContext) : state * FFinished = 
        LogManager.GetLogger("file").Info("# FINISHED : FlexFinished.receive");
        let verify_data =
            match logRoleNSC with
            | Some(log,role,nsc) -> Some(FlexSecrets.makeVerifyData nsc.si nsc.keys.ms role log)
            | None -> verify_data
        in
        let st,hstype,payload,to_log = FlexHandshake.receive(st) in
        match hstype with
        | HT_finished  -> 
            LogManager.GetLogger("file").Debug(sprintf "--- Verify data: %A" (Bytes.hexString(payload)));
            if length payload <> 12 then
                (failwith (perror __SOURCE_FILE__ __LINE__ "unexpected payload length"))
            else
                // check the verify_data if the user provided one; then store what we received
                (match verify_data with
                | None -> ()
                | Some(verify_data) ->
                    if not (verify_data = payload) then
                    (LogManager.GetLogger("file").Debug(sprintf "--- Expected verify data : %A" (Bytes.hexString(verify_data)));
                    failwith "Verify data do not match"));
                let st = FlexState.updateIncomingVerifyData st payload in
                let ff = {  verify_data = payload; 
                            payload = to_log;
                } in
                LogManager.GetLogger("file").Info(sprintf "--- Payload : %A" (Bytes.hexString(ff.payload)));
                st,ff
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected handshake type: %A" hstype))

    /// <summary>
    /// Prepare a Finished message from the verify_data that will not be sent to the network
    /// </summary>
    /// <param name="verify_data"> Verify_data that will be used to generate the finished message </param>
    /// <returns> Finished message bytes *  FFinished message record </returns>
    static member prepare (verify_data:bytes) : bytes * FFinished =
        let payload = HandshakeMessages.messageBytes HT_finished verify_data in
        let ff = { verify_data = verify_data;
                   payload = payload;
                 } 
        in
        payload,ff

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
        LogManager.GetLogger("file").Info("# FINISHED : FlexFinished.send");
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let verify_data =
            match logRoleNSC with
            | Some(log,role,nsc) -> FlexSecrets.makeVerifyData nsc.si nsc.keys.ms role log
            | None ->
                match verify_data with
                | None -> failwith (perror __SOURCE_FILE__ __LINE__ "One of verify_data or (log, role, nextSecurityContext) must be provided")
                | Some(vd) -> vd
        in
        let payload,ff = FlexFinished.prepare verify_data in
        let st = FlexState.updateOutgoingVerifyData st verify_data in
        let st = FlexHandshake.send(st,payload,fp) in

        LogManager.GetLogger("file").Debug(sprintf "--- Expected data : %A" (Bytes.hexString(verify_data)));
        LogManager.GetLogger("file").Debug(sprintf "--- Verify data : %A" (Bytes.hexString(ff.verify_data)));
        st,ff

    end
    