module SessionDB

open TLSInfo
open AppCommon

// FIXME: in the DB a session must be identified by sessionID and host!
type StorableSession = SessionInfo * PRFs.masterSecret * Direction

val create: protocolOptions -> unit
val select: protocolOptions -> sessionID -> StorableSession option
val insert: protocolOptions -> sessionID -> StorableSession -> unit
val remove: protocolOptions -> sessionID -> unit
val getAllStoredIDs: protocolOptions -> sessionID list