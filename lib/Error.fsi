module Error_handling

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
    | HandshakeProto
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

type 'a Result =
    | Error of ErrorCause * ErrorKind
    | Correct of 'a

val correct: 'a -> 'a Result
val unexpectedError: string -> 'a