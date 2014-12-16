#light "off"

module SessionDB

open TLSInfo
open Date

//CF type SessionIndex = sessionID * Role * Cert.hint
//CF flattened for simpler refinements 

type StorableSession = SessionInfo * PRF.masterSecret * epoch
type SessionIndex = sessionID * Role * Cert.hint

#if ideal
type entry = sessionID * Role * Cert.hint * StorableSession 
type t = list<entry> 
#else
type t
#endif

val create: config -> t
val select: t -> sessionID -> Role -> Cert.hint -> option<StorableSession>
val insert: t -> sessionID -> Role -> Cert.hint -> StorableSession -> t
val remove: t -> sessionID -> Role -> Cert.hint -> t

val getAllStoredIDs: t -> list<SessionIndex>
