module Alert

open Bytes
open Error
open Formats
open TLSInfo

type alertLevel = 
    | AL_warning
    | AL_fatal

type alert = {level: alertLevel; description: alertDescription}

type pre_al_state = {
  al_incoming: bytes (* incomplete incoming message *)
  al_outgoing: bytes (* emptybstr if nothing to be sent *) 
}

type state = pre_al_state

type fragment = {b:bytes}
let repr (ki:KeyInfo) (i:int) (seqn:int) f = f.b
let fragment (ki:KeyInfo) (i:int) (seqn:int) b = {b=b}
let makeFragment ki b =
    let (tl,f,r) = FragCommon.splitInFrag ki b in
    ((tl,{b=f}),r)

let init (ci:ConnectionInfo) = {al_incoming = [||]; al_outgoing = [||]}

type ALFragReply =
    | EmptyALFrag
    | ALFrag of (int * fragment)
    | LastALFrag of (int * fragment)
    | LastALCloseFrag of (int * fragment)

type alert_reply =
    | ALAck of state
    | ALClose of state
    | ALClose_notify of state

(* Conversions *)

let alertBytes ad =
  (* Severity (warning or fatal) is hardcoded,
     as specified in sec. 7.2.2 *)
  match ad with
    | AD_close_notify ->            [|1uy;   0uy|]
    | AD_unexpected_message ->      [|2uy;  10uy|]
    | AD_bad_record_mac ->          [|2uy;  20uy|]
    | AD_decryption_failed ->       [|2uy;  21uy|]
    | AD_record_overflow ->         [|2uy;  22uy|]
    | AD_decompression_failure ->   [|2uy;  30uy|]
    | AD_handshake_failure ->       [|2uy;  40uy|]
    | AD_no_certificate ->          [|1uy;  41uy|]
    | AD_bad_certificate ->         [|1uy;  42uy|]
    | AD_unsupported_certificate -> [|1uy;  43uy|]
    | AD_certificate_revoked ->     [|1uy;  44uy|]
    | AD_certificate_expired ->     [|1uy;  45uy|]
    | AD_certificate_unknown ->     [|1uy;  46uy|]
    | AD_illegal_parameter ->       [|2uy;  47uy|]
    | AD_unknown_ca ->              [|2uy;  48uy|]
    | AD_access_denied ->           [|2uy;  49uy|]
    | AD_decode_error ->            [|2uy;  50uy|]
    | AD_decrypt_error ->           [|1uy;  51uy|]
    | AD_export_restriction ->      [|2uy;  60uy|]
    | AD_protocol_version ->        [|2uy;  70uy|]
    | AD_insufficient_security ->   [|2uy;  71uy|]
    | AD_internal_error ->          [|2uy;  80uy|]
    | AD_user_cancelled ->          [|1uy;  90uy|]
    | AD_no_renegotiation ->        [|1uy; 100uy|]
    | AD_unsupported_extension ->   [|2uy; 110uy|]

let parseLevel l =
    match l with
    | [|1uy|] -> correct(AL_warning)
    | [|2uy|] -> correct(AL_fatal)
    | _ -> Error(Parsing,WrongInputParameters)

let parseAlertDescription d =
    match d with
    | [|  0uy|] -> correct(AD_close_notify             )
    | [| 10uy|] -> correct(AD_unexpected_message       )
    | [| 20uy|] -> correct(AD_bad_record_mac           )
    | [| 21uy|] -> correct(AD_decryption_failed        )
    | [| 22uy|] -> correct(AD_record_overflow          )
    | [| 30uy|] -> correct(AD_decompression_failure    )
    | [| 40uy|] -> correct(AD_handshake_failure        )
    | [| 41uy|] -> correct(AD_no_certificate           )
    | [| 42uy|] -> correct(AD_bad_certificate          )
    | [| 43uy|] -> correct(AD_unsupported_certificate  )
    | [| 44uy|] -> correct(AD_certificate_revoked      )
    | [| 45uy|] -> correct(AD_certificate_expired      )
    | [| 46uy|] -> correct(AD_certificate_unknown      )
    | [| 47uy|] -> correct(AD_illegal_parameter        )
    | [| 48uy|] -> correct(AD_unknown_ca               )
    | [| 49uy|] -> correct(AD_access_denied            )
    | [| 50uy|] -> correct(AD_decode_error             )
    | [| 51uy|] -> correct(AD_decrypt_error            )
    | [| 60uy|] -> correct(AD_export_restriction       )
    | [| 70uy|] -> correct(AD_protocol_version         )
    | [| 71uy|] -> correct(AD_insufficient_security    )
    | [| 80uy|] -> correct(AD_internal_error           )
    | [| 90uy|] -> correct(AD_user_cancelled           )
    | [|100uy|] -> correct(AD_no_renegotiation         )
    | [|110uy|] -> correct(AD_unsupported_extension    )
    |     _     -> Error(Parsing,WrongInputParameters  )

let parseAlert (b:bytes) =
  let (levelB,descB) = split b 1 in
  match parseLevel levelB with
  | Error(x,y) -> Error(x,y)
  | Correct(level) ->
  match parseAlertDescription descB with
  | Error(x,y) -> Error(x,y)
  | Correct(desc) ->
  correct({level = level; description = desc })
  
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
        let (frag,rem) = makeFragment ci.id_out state.al_outgoing in
        let state = {state with al_outgoing = rem} in
        match rem with
        | [||] ->
            (* We now need to know which alert we're sending, in order to return the proper
               constructor to Dispatch.
               We're going to use many of the invariants on the output buffer,
               and anyway, as it is implemented now, it looks like an hack... *)
            let (adBytes,_) =
                match length d with
                | 1 -> split d 1
                | _ -> let (b,_) = split d 2 in let (_,b) = split b 1 in (b,[||])
            match parseAlertDescription adBytes with
            | Error(x,y) -> unexpectedError "[next_fragment] This invocation of parseAlertDescription should never fail"
            | Correct(ad) ->
                match ad with
                | AD_close_notify -> (LastALCloseFrag(frag),state)
                | _ -> (LastALFrag(frag),state)
        | _ -> (ALFrag(frag),state)

let handle_alert ci state al =
    match al.description with
    | AD_close_notify ->
        (* This must be fatal: check it *)
        if al.level <> AL_fatal then
            Error (AlertProto,Unsupported)
        else
            (* we possibly send a close_notify back *)
            let state = send_alert ci state AD_close_notify in
            correct ( ALClose_notify (state) )
    | _ ->
        match al.level with
        | AL_fatal ->   correct (ALClose (state))
        | AL_warning -> correct (ALAck   (state))

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
                | Correct(alert) -> handle_alert ci state alert
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
                    handle_alert ci state alert

let reIndex (oldCI:ConnectionInfo) (newCI:ConnectionInfo) (state:state) = state