module Sessions

open Data

type prerole =
    | ClientRole
    | ServerRole

type role = prerole

type sessionID = bytes

type SessionInfo

val init_sessionInfo: role -> SessionInfo

val getSessionRole: SessionInfo -> role
val getSessionID: SessionInfo -> sessionID option