module Alert

open Formats
open Data
open Bytearray
open Error
//open Record
open TLSInfo
open TLSPlain

type alertLevel = 
    | AL_warning
    | AL_fatal
    | AL_unknown_level of byte

type alert = {level: alertLevel; description: alertDescription}

type pre_al_state = {
  al_info: SessionInfo;
  al_incoming: bytes (* incomplete incoming message *)
  al_outgoing: bytes (* emptybstr if nothing to be sent *) 
}

type al_state = pre_al_state

let init info = {al_info = info; al_incoming = empty_bstr; al_outgoing = empty_bstr}

type ALFragReply =
    | EmptyALFrag
    | ALFrag of (int * fragment)
    | LastALFrag of (int *fragment)

type alert_reply =
    | ALAck of al_state
    | ALClose of al_state
    | ALClose_notify of al_state

(* Conversions *)

let bytes_of_alertDesc ad =
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
    | AD_unknown_description x ->   unexpectedError "Unknown alert description value"


let level_of_byte l =
    match l with
    | 1uy -> AL_warning
    | 2uy -> AL_fatal
    | x -> (AL_unknown_level x)

let desc_of_byte d =
    match d with
    |   0uy -> AD_close_notify 
    |  10uy -> AD_unexpected_message 
    |  20uy -> AD_bad_record_mac 
    |  21uy -> AD_decryption_failed 
    |  22uy -> AD_record_overflow 
    |  30uy -> AD_decompression_failure 
    |  40uy -> AD_handshake_failure 
    |  41uy -> AD_no_certificate 
    |  42uy -> AD_bad_certificate 
    |  43uy -> AD_unsupported_certificate 
    |  44uy -> AD_certificate_revoked 
    |  45uy -> AD_certificate_expired 
    |  46uy -> AD_certificate_unknown 
    |  47uy -> AD_illegal_parameter 
    |  48uy -> AD_unknown_ca 
    |  49uy -> AD_access_denied 
    |  50uy -> AD_decode_error 
    |  51uy -> AD_decrypt_error 
    |  60uy -> AD_export_restriction 
    |  70uy -> AD_protocol_version 
    |  71uy -> AD_insufficient_security 
    |  80uy -> AD_internal_error 
    |  90uy -> AD_user_cancelled 
    | 100uy -> AD_no_renegotiation
    | 110uy -> AD_unsupported_extension
    |   x   -> (AD_unknown_description x)

let alert_of_bytes (b:bytes) = 
  let level = level_of_byte b.[0] in
  let desc = desc_of_byte b.[1] in   
  {level = level; description = desc }

let alert_of_alertDesc a =
    alert_of_bytes (bytes_of_alertDesc a)
  
let send_alert state alertDesc =
    (* Check it's a fatal alert *)
    let alert = alert_of_alertDesc alertDesc in
    match alert.level with
    | AL_unknown_level x -> Error (AlertProto,Unsupported)
    | AL_warning -> Error(AlertProto,Unsupported)
    | AL_fatal ->
    let out = state.al_outgoing in
    (* We only handle fatal alert, so at most one will be sent.
       Check we are not sending another alert. *)
    (* FIXME: The next check is not enough in isolation: it relies on the fact
    that the dispacther will not send aything more after the first alert.
    If we want to be independent of this, we need to track the status more
    properly*)
    match out with
    | x when x = empty_bstr ->
        let out = bytes_of_alertDesc alertDesc in
        Correct { state with al_outgoing = out }
    | _ ->
        Error (AlertAlreadySent, Internal)

let next_fragment state =
    match state.al_outgoing with
    | x when equalBytes x empty_bstr ->
        (EmptyALFrag, state)
    | d ->
        let (frag,rem) = pub_fragment state.al_info state.al_outgoing in
        let state = {state with al_outgoing = rem} in
        match rem with
        | x when equalBytes x empty_bstr -> (LastALFrag(frag),state)
        | _ -> (ALFrag(frag),state)

let handle_alert state al =
    match al.description with
    | AD_unknown_description x -> Error (AlertProto,Unsupported)
    | AD_close_notify ->
        (* This must be fatal: check it *)
        if al.level <> AL_fatal then
            Error (AlertProto,Unsupported)
        else
            (* we possibly send a close_notify back *)
            match send_alert state AD_close_notify with
            | Correct (state) ->
                Correct ( ALClose_notify (state) )
            | Error (x,y) -> (* we don't care if we could not send the close_notify back. Close the connection anyway *)
                Correct ( ALClose_notify (state) )
    | _ ->
        match al.level with
        | AL_fatal -> Correct (ALClose (state))
        | AL_warning -> Correct (ALAck (state))
        | AL_unknown_level x -> Error (AlertProto,Unsupported)

let recv_fragment state tlen (fragment:fragment) =
    let fragment = pub_fragment_to_bytes state.al_info tlen fragment in
    match state.al_incoming with
    | x when x = empty_bstr ->
        (* Empty buffer *)
        if length fragment = 1 then
            Correct (ALAck ({state with al_incoming = fragment}))
        else
            let (al,_) = split fragment 2 in
            let alert = alert_of_bytes al in
            let state = {state with al_incoming = empty_bstr} in (* empty the buffer *)
            handle_alert state alert
    | inc ->
        let (part2,_) = split fragment 1 in
        let bmsg = append inc part2 in
        let alert = alert_of_bytes bmsg in
        let state = {state with al_incoming = empty_bstr } in
        handle_alert state alert