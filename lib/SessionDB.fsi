module SessionDB

open TLSInfo
open Data
open AppCommon

type StorableSession =
    {sinfo: SessionInfo
     ms: bytes
     dir: Direction}

val create: protocolOptions -> unit
val select: protocolOptions -> sessionID -> StorableSession Option
val insert: protocolOptions -> sessionID -> StorableSession -> unit
val remove: protocolOptions -> sessionID -> unit
val getAllStoredIDs: protocolOptions -> sessionID list