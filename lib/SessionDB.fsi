module SessionDB

open TLSInfo

// FIXME: in the DB a session must be identified by sessionID and host!
type StorableSession = SessionInfo * PRFs.masterSecret * Role

type SessionDB

val create: config -> SessionDB
val select: SessionDB -> sessionID -> StorableSession option
val insert: SessionDB -> sessionID -> StorableSession -> SessionDB
val remove: SessionDB -> sessionID -> SessionDB
val getAllStoredIDs: SessionDB -> sessionID list