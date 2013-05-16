module CRE

open Bytes
open TLSConstants
open TLSInfo
open Error
open TLSError
open PMS

val extract: SessionInfo -> pms -> PRF.masterSecret

