module SessionDB

open TLSInfo

// FIXME: in the DB a session must be identified by sessionID and host!
type StorableSession = SessionInfo * PRFs.masterSecret * Role

val create: config -> unit
val select: config -> sessionID -> StorableSession option
val insert: config -> sessionID -> StorableSession -> unit
val remove: config -> sessionID -> unit
val getAllStoredIDs: config -> sessionID list