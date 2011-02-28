module Sessions

open Data

type role =
    | ClientRole
    | ServerRole

type sessionID = bytes

type SessionInfo = {
    role: role;
    clientID: string option;
    serverID: string option;
    sessionID: sessionID option;
    null_algs: bool
    }

let init_sessionInfo role =
    { role = role;
      clientID = None;
      serverID = None;
      sessionID = None;
      null_algs = true}

let getSessionRole info =
    info.role

let getSessionID info =
    info.sessionID