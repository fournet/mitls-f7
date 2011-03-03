(* Alert protocol *)

(* We do not support sending warnings, as there is no good reason to do so *)

module Alert
open Data
open Error_handling
open Record
open Sessions

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

type al_state

type ALFragReply =
    | EmptyALFrag
    | ALFrag of bytes
    | LastALFrag of bytes

type alert_reply =
    | ALAck of al_state
    | ALClose of al_state
    | ALClose_notify of al_state

val init: SessionInfo -> al_state

val send_alert: al_state -> alertDescription -> al_state Result

val next_fragment: al_state -> int -> (ALFragReply * al_state) 

val recv_fragment: al_state -> fragment -> alert_reply Result 

val updateSessionInfo: al_state -> SessionInfo -> al_state