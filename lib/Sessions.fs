module Sessions

open Data

type role =
    | ClientRole
    | ServerRole

type Direction =
    | InDir
    | OutDir

type sessionID = bytes

type SessionInfo = {
    role: role;
    dir: Direction;
    clientID: string option;
    serverID: string option;
    sessionID: sessionID option;
    }

let init_sessionInfo role dir =
    { role = role;
      dir = dir;
      clientID = None;
      serverID = None;
      sessionID = None}

let getSessionRole info =
    info.role

let getSessionID info =
    info.sessionID