module SessionDB

open TLSInfo
open Data
open AppCommon

type StoredSession =
    {sinfo: SessionInfo
     ms: bytes}

val create: protocolOptions -> unit
val select: protocolOptions -> sessionID -> StoredSession Option
val insert: protocolOptions -> sessionID -> StoredSession -> unit
val remove: protocolOptions -> sessionID -> unit
val getAllStoredIDs: protocolOptions -> sessionID list