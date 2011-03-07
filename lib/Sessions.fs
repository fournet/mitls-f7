module Sessions

open Data

type prerole =
    | ClientRole
    | ServerRole

type role = prerole

type sessionID = bytes

type SessionInfo = {
    role: role;
    clientID: string option;
    serverID: string option;
    sessionID: sessionID option
    }

let init_sessionInfo role =
    { role = role;
      clientID = None;
      serverID = None;
      sessionID = None;}

let getSessionRole info =
    info.role

let getSessionID info =
    info.sessionID