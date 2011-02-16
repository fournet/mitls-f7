module Sessions

open Data

type role =
    | ClientRole
    | ServerRole

type Direction =
    | InDir
    | OutDir

type sessionID = bytes

type SessionInfo

val init_sessionInfo: role -> Direction -> SessionInfo

val getSessionRole: SessionInfo -> role
val getSessionID: SessionInfo -> sessionID option