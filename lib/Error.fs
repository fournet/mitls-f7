module Error_handling

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
    | AD_unsupported_extension
    | AD_unknown_description of int

type ErrorCause =
    | Tcp
    | MAC
    | Hash
    | Encryption
    | Protocol
    | Record
    | RecordPadding
    | RecordFragmentation
    | RecordCompression
    | RecordVersion
    | AlertAlreadySent
    | AlertProto
    | HSError of alertDescription
    | CertificateParsing
    | Dispatcher
    | TLS
    | NewSessionInfo
    | MustRead
    | Other of string

type ErrorKind =
    | Unsupported
    | CheckFailed
    | WrongInputParameters
    | InvalidState
    | Internal
    | Notification
    | HSSendAlert

type 'a Result =
    | Error of ErrorCause * ErrorKind
    | Correct of 'a

let correct x = Correct x

let unexpectedError info = failwith info