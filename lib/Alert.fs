module Alert

open Bytes
open Error
open Formats
open TLSInfo

type pre_al_state = {
  al_incoming: bytes (* incomplete incoming message *)
  al_outgoing: bytes (* emptybstr if nothing to be sent *) 
}

type state = pre_al_state

type fragment = {b:bytes}
let repr (ki:KeyInfo) (i:int) (seqn:int) f = f.b
let fragment (ki:KeyInfo) (i:int) (seqn:int) b = {b=b}
let makeFragment ki (seqn:int) b =
    let (tl,f,r) = FragCommon.splitInFrag ki b in
    ((tl,{b=f}),r)

let init (ci:ConnectionInfo) = {al_incoming = [||]; al_outgoing = [||]}

type ALFragReply =
    | EmptyALFrag
    | ALFrag of int * fragment
    | LastALFrag of int * fragment
    | LastALCloseFrag of int * fragment

type alert_reply =
    | ALAck of state
    | ALClose of state
    | ALClose_notify of state

(* Conversions *)

let alertBytes ad =
  (* Severity (warning or fatal) is hardcoded,
     as specified in sec. 7.2.2 *)
  match ad with
    | AD_close_notify ->                       [|1uy;   0uy|]
    | AD_unexpected_message ->                 [|2uy;  10uy|]
    | AD_bad_record_mac ->                     [|2uy;  20uy|]
    | AD_decryption_failed ->                  [|2uy;  21uy|]
    | AD_record_overflow ->                    [|2uy;  22uy|]
    | AD_decompression_failure ->              [|2uy;  30uy|]
    | AD_handshake_failure ->                  [|2uy;  40uy|]
    | AD_no_certificate ->                     [|1uy;  41uy|]
    | AD_bad_certificate_warning ->            [|1uy;  42uy|]
    | AD_bad_certificate_fatal ->              [|2uy;  42uy|]
    | AD_unsupported_certificate_warning ->    [|1uy;  43uy|]
    | AD_unsupported_certificate_fatal ->      [|2uy;  43uy|]
    | AD_certificate_revoked_warning ->        [|1uy;  44uy|]
    | AD_certificate_revoked_fatal ->          [|2uy;  44uy|]
    | AD_certificate_expired_warning ->        [|1uy;  45uy|]
    | AD_certificate_expired_fatal ->          [|2uy;  45uy|]
    | AD_certificate_unknown_warning ->        [|1uy;  46uy|]
    | AD_certificate_unknown_fatal ->          [|2uy;  46uy|]
    | AD_illegal_parameter ->                  [|2uy;  47uy|]
    | AD_unknown_ca ->                         [|2uy;  48uy|]
    | AD_access_denied ->                      [|2uy;  49uy|]
    | AD_decode_error ->                       [|2uy;  50uy|]
    | AD_decrypt_error ->                      [|1uy;  51uy|]
    | AD_export_restriction ->                 [|2uy;  60uy|]
    | AD_protocol_version ->                   [|2uy;  70uy|]
    | AD_insufficient_security ->              [|2uy;  71uy|]
    | AD_internal_error ->                     [|2uy;  80uy|]
    | AD_user_cancelled_warning ->             [|1uy;  90uy|]
    | AD_user_cancelled_fatal ->               [|2uy;  90uy|]
    | AD_no_renegotiation ->                   [|1uy; 100uy|]
    | AD_unsupported_extension ->              [|2uy; 110uy|]

let parseAlert b =
    match b with
    | [|1uy;   0uy|] -> correct(AD_close_notify                         )
    | [|2uy;  10uy|] -> correct(AD_unexpected_message                   )
    | [|2uy;  20uy|] -> correct(AD_bad_record_mac                       )
    | [|2uy;  21uy|] -> correct(AD_decryption_failed                    )
    | [|2uy;  22uy|] -> correct(AD_record_overflow                      )
    | [|2uy;  30uy|] -> correct(AD_decompression_failure                )
    | [|2uy;  40uy|] -> correct(AD_handshake_failure                    )
    | [|1uy;  41uy|] -> correct(AD_no_certificate                       )
    | [|1uy;  42uy|] -> correct(AD_bad_certificate_warning              )
    | [|2uy;  42uy|] -> correct(AD_bad_certificate_fatal                )
    | [|1uy;  43uy|] -> correct(AD_unsupported_certificate_warning      )
    | [|2uy;  43uy|] -> correct(AD_unsupported_certificate_fatal        )
    | [|1uy;  44uy|] -> correct(AD_certificate_revoked_warning          )
    | [|2uy;  44uy|] -> correct(AD_certificate_revoked_fatal            )
    | [|1uy;  45uy|] -> correct(AD_certificate_expired_warning          )
    | [|2uy;  45uy|] -> correct(AD_certificate_expired_fatal            )
    | [|1uy;  46uy|] -> correct(AD_certificate_unknown_warning          )
    | [|2uy;  46uy|] -> correct(AD_certificate_unknown_fatal            )
    | [|2uy;  47uy|] -> correct(AD_illegal_parameter                    )
    | [|2uy;  48uy|] -> correct(AD_unknown_ca                           )
    | [|2uy;  49uy|] -> correct(AD_access_denied                        )
    | [|2uy;  50uy|] -> correct(AD_decode_error                         )
    | [|1uy;  51uy|] -> correct(AD_decrypt_error                        )
    | [|2uy;  60uy|] -> correct(AD_export_restriction                   )
    | [|2uy;  70uy|] -> correct(AD_protocol_version                     )
    | [|2uy;  71uy|] -> correct(AD_insufficient_security                )
    | [|2uy;  80uy|] -> correct(AD_internal_error                       )
    | [|1uy;  90uy|] -> correct(AD_user_cancelled_warning               )
    | [|2uy;  90uy|] -> correct(AD_user_cancelled_fatal                 )
    | [|1uy; 100uy|] -> correct(AD_no_renegotiation                     )
    | [|2uy; 110uy|] -> correct(AD_unsupported_extension                )
    | _ -> Error(Parsing,WrongInputParameters)

let isFatal ad =
    match ad with       
    | AD_unexpected_message   
    | AD_bad_record_mac       
    | AD_decryption_failed    
    | AD_record_overflow      
    | AD_decompression_failure
    | AD_handshake_failure    
    | AD_bad_certificate_fatal
    | AD_unsupported_certificate_fatal    
    | AD_certificate_revoked_fatal         
    | AD_certificate_expired_fatal      
    | AD_certificate_unknown_fatal      
    | AD_illegal_parameter
    | AD_unknown_ca       
    | AD_access_denied    
    | AD_decode_error     
    | AD_export_restriction   
    | AD_protocol_version     
    | AD_insufficient_security
    | AD_internal_error   
    | AD_user_cancelled_fatal 
    | AD_unsupported_extension -> true
    | _ -> false
  
let send_alert (ci:ConnectionInfo) state alertDesc =
    (* FIXME: We should only send fatal alerts. Right now we'll interpret any sent alert
       as fatal, and so will close the connection afterwards. *)
    (* Note: we only support sending one alert in the whole protocol execution
       (because we'll tell dispatch an alert has been sent when the buffer gets empty)
       So we only add an alert on an empty buffer (we don't enqueue more alerts) *)
    if equalBytes state.al_outgoing [||] then
        {state with al_outgoing = alertBytes alertDesc}
    else
        state (* Just ignore the request *)

let next_fragment ci (seqn:int) state =
    match state.al_outgoing with
    | [||] ->
        (EmptyALFrag, state)
    | d ->
        let (frag,rem) = makeFragment ci.id_out seqn d in
        let state = {state with al_outgoing = rem} in
        match rem with
        | [||] ->
            (* We now need to know which alert we're sending, in order to return the proper
               constructor to Dispatch. *)
            match parseAlert d with
            | Error(x,y) -> unexpectedError "[next_fragment] This invocation of parseAlertDescription should never fail"
            | Correct(ad) ->
                match ad with
                | AD_close_notify -> (LastALCloseFrag(frag),state)
                | _ -> (LastALFrag(frag),state)
        | _ -> (ALFrag(frag),state)

let handle_alert ci state alDesc =
    match alDesc with
    | AD_close_notify ->
        (* we possibly send a close_notify back *)
        let state = send_alert ci state AD_close_notify in
        ALClose_notify (state)
    | _ ->
        if isFatal alDesc then
            ALClose (state)
        else
            ALAck   (state)

let recv_fragment ci seqn state tlen (data:fragment) =
    let fragment = repr ci.id_in tlen seqn data in
    match state.al_incoming with
    | [||] ->
        (* Empty buffer *)
        match length fragment with
        | 0 -> Error(Parsing,WrongInputParameters) (* Empty alert fragments are invalid *)
        | 1 -> Correct (ALAck ({state with al_incoming = fragment})) (* Buffer this partial alert *)
        | _ -> (* Full alert received *)
            let (al,rem) = split fragment 2 in
            if length rem <> 0 then (* Check there are no more data *)
                Error(Parsing,WrongInputParameters)
            else
                match parseAlert al with
                | Error(x,y) -> Error(x,y)
                | Correct(alert) -> let res = handle_alert ci state alert in correct(res)
    | inc ->
        match length fragment with
        | 0 -> Error(Parsing,WrongInputParameters) (* Empty alert fragments are invalid *)
        | _ -> 
            let (part2,rem) = split fragment 1 in
            if length rem <> 0 then (* Check there are no more data *)
                Error(Parsing,WrongInputParameters)
            else
                let bmsg = inc @| part2 in
                match parseAlert bmsg with
                | Error(x,y) -> Error(x,y)
                | Correct(alert) ->
                    let state = {state with al_incoming = [||] } in
                    let res = handle_alert ci state alert in
                    correct(res)

let reIndex (oldCI:ConnectionInfo) (newCI:ConnectionInfo) (state:state) = state