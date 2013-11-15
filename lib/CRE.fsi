module CRE

open Bytes
open TLSConstants
open TLSInfo
open Error
open TLSError
open PMS

type log = bytes

val extract: SessionInfo -> pms -> PRF.masterSecret
val extract_extended: SessionInfo -> pms -> PRF.masterSecret

