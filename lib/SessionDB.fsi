module SessionDB

open Sessions
open AppCommon

val create: protocolOptions -> unit
val select: protocolOptions -> sessionID -> SessionInfo Option
val insert: protocolOptions -> sessionID -> SessionInfo -> unit
val remove: protocolOptions -> sessionID -> unit