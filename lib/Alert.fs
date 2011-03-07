module Alert

open Formats
open Data
open Bytearray
open Error_handling
open Record
open Sessions

type alertLevel = 
    | AL_warning
    | AL_fatal
    | AL_unknown_level of int

type alertDescription = 
    | AD_close_notify
    | AD_unexpected_message
    | AD_bad_record_mac
    | AD_decryption_failed
    | AD_record_overflow
    | AD_decompression_failure
    | AD_handshake_failure
    | AD_no_certificate
    | AD_bad_certificate
    | AD_unsupported_certificate
    | AD_certificate_revoked
    | AD_certificate_expired
    | AD_certificate_unknown
    | AD_illegal_parameter
    | AD_unknown_ca
    | AD_access_denied
    | AD_decode_error
    | AD_decrypt_error
    | AD_export_restriction
    | AD_protocol_version
    | AD_insufficient_security
    | AD_internal_error
    | AD_user_cancelled
    | AD_no_renegotiation
    | AD_unknown_description of int

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
    | ALFrag of bytes
    | LastALFrag of bytes

type alert_reply =
    | ALAck of al_state
    | ALClose of al_state
    | ALClose_notify of al_state

(* Conversions *)

let intpair_of_alertDesc ad =
  (* Severity (warning or fatal) is hardcoded,
     as specified in sec. 7.2.2 *)
  match ad with
    | AD_close_notify ->            (1, 0)
    | AD_unexpected_message ->      (2,10)
    | AD_bad_record_mac ->          (2,20)
    | AD_decryption_failed ->       (2,21)
    | AD_record_overflow ->         (2,22)
    | AD_decompression_failure ->   (2,30)
    | AD_handshake_failure ->       (2,40)
    | AD_no_certificate ->          (1,41)
    | AD_bad_certificate ->         (1,42)
    | AD_unsupported_certificate -> (1,43)
    | AD_certificate_revoked ->     (1,44)
    | AD_certificate_expired ->     (1,45)
    | AD_certificate_unknown ->     (1,46)
    | AD_illegal_parameter ->       (2,47)
    | AD_unknown_ca ->              (2,48)
    | AD_access_denied ->           (2,49)
    | AD_decode_error ->            (2,50)
    | AD_decrypt_error ->           (1,51)
    | AD_export_restriction ->      (2,60)
    | AD_protocol_version ->        (2,70)
    | AD_insufficient_security ->   (2,71)
    | AD_internal_error ->          (2,80)
    | AD_user_cancelled ->          (1,90)
    | AD_no_renegotiation ->        (1,100)
    | AD_unknown_description x ->   failwith "Unknown alert description value"


let level_of_int l =
    match l with
    | 1 -> AL_warning
    | 2 -> AL_fatal
    | x -> (AL_unknown_level x)

let desc_of_int d =
    match d with
    |  0 -> AD_close_notify 
    | 10 -> AD_unexpected_message 
    | 20 -> AD_bad_record_mac 
    | 21 -> AD_decryption_failed 
    | 22 -> AD_record_overflow 
    | 30 -> AD_decompression_failure 
    | 40 -> AD_handshake_failure 
    | 41 -> AD_no_certificate 
    | 42 -> AD_bad_certificate 
    | 43 -> AD_unsupported_certificate 
    | 44 -> AD_certificate_revoked 
    | 45 -> AD_certificate_expired 
    | 46 -> AD_certificate_unknown 
    | 47 -> AD_illegal_parameter 
    | 48 -> AD_unknown_ca 
    | 49 -> AD_access_denied 
    | 50 -> AD_decode_error 
    | 51 -> AD_decrypt_error 
    | 60 -> AD_export_restriction 
    | 70 -> AD_protocol_version 
    | 71 -> AD_insufficient_security 
    | 80 -> AD_internal_error 
    | 90 -> AD_user_cancelled 
    | 100 -> AD_no_renegotiation 
    | x -> (AD_unknown_description x)

let alert_of_intpair (l,d) = 
  let level = level_of_int l in
  let desc = desc_of_int d in   
  {level = level; description = desc }

let alert_of_bytes msg = alert_of_intpair (intpair_of_bytes msg)

let bytes_of_alertDesc ad = 
  bytes_of_intpair (intpair_of_alertDesc ad)
  
let send_alert state alertDesc =
    (* Check it's a fatal alert *)
    let (l,d) = intpair_of_alertDesc alertDesc in
    let level = level_of_int l in
    match level with
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

let next_fragment state len =
    match state.al_outgoing with
    | x when equalBytes x empty_bstr ->
        (EmptyALFrag, state)
    | d ->
        let (f,rem) = split state.al_outgoing len in
        let state = {state with al_outgoing = rem} in
        match rem with
        | x when equalBytes x empty_bstr -> (LastALFrag(f),state)
        | _ -> (ALFrag(f),state)

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

let recv_fragment state (fragment:fragment) =
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