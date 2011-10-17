﻿module TLSInfo

open Data
open Principal
open HS_ciphersuites

type sessionID = bytes

type preDirection =
    | CtoS
    | StoC

type Direction = preDirection

type SessionInfo = {
    clientID: pri_cert option
    serverID: pri_cert option
    sessionID: sessionID option
    protocol_version: ProtocolVersionType
    cipher_suite: cipherSuite
    compression: Compression
    init_crand: bytes
    init_srand: bytes
    }

type KeyInfo = {
    sinfo: SessionInfo
    dir: Direction
    crand: bytes
    srand: bytes
 (* cVerifyData: bytes
    sVerifyData: bytes *)
    }