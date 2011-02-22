module Sessions

open Data

type role =
    | ClientRole
    | ServerRole

type sessionID = bytes

type SessionInfo

val init_sessionInfo: role -> SessionInfo

val getSessionRole: SessionInfo -> role
val getSessionID: SessionInfo -> sessionID option