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
    | Other of string

type ErrorKind =
    | Unsupported
    | CheckFailed
    | WrongInputParameters
    | InvalidState
    | Internal

type 'a Result =
    | Error of ErrorCause * ErrorKind
    | Correct of 'a

let correct x = Correct x

let unexpectedError info = failwith info