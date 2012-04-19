module TLSInfo

open Bytes
open Certificate
open CipherSuites

type sessionID = bytes

type preDirection =
  | CtoS
  | StoC
type Direction = preDirection

type preRole =
    | Client
    | Server
type Role = preRole

let dualDirection dir =
    match dir with
    | CtoS -> StoC
    | StoC -> CtoS

type SessionInfo = {
    clientID: cert option
    serverID: cert option
    sessionID: sessionID option
    protocol_version: ProtocolVersion
    cipher_suite: cipherSuite
    compression: Compression
    init_crand: bytes
    init_srand: bytes
    }

let null_sessionInfo minPV =
    { clientID = None;
      serverID = None;
      sessionID = None;
      protocol_version = minPV;
      cipher_suite = nullCipherSuite;
      compression = NullCompression;
      init_crand = [||]
      init_srand = [||]
      }

let isNullSessionInfo s =
  s.clientID = None && s.serverID = None && s.sessionID = None &&
  isNullCipherSuite s.cipher_suite && s.compression = NullCompression &&
  s.init_crand = [||] && s.init_srand = [||]

type KeyInfo = {
    sinfo: SessionInfo
    dir: Direction
    crand: bytes
    srand: bytes
    }

let null_KeyInfo dir minPV =
  let si = null_sessionInfo minPV in
    {sinfo = si;
     dir = dir;
     crand = [||];
     srand = [||];
    }

let dual_KeyInfo ki = 
  let d = dualDirection(ki.dir) in
  {ki with dir = d}

type ConnectionInfo = {
    id_in: KeyInfo;
    id_out: KeyInfo}

// Application configuration
type helloReqPolicy =
    | HRPIgnore
    | HRPFull
    | HRPResume

type protocolOptions = {
    minVer: ProtocolVersion
    maxVer: ProtocolVersion
    ciphersuites: cipherSuites
    compressions: Compression list

    (* Handshake specific options *)
    (* Client side *)
    honourHelloReq: helloReqPolicy
    allowAnonCipherSuite: bool
    (* Server side *)
    request_client_certificate: bool
    check_client_version_in_pms_for_old_tls: bool
    server_cert_file: string (* FIXME: certificates should be found in a better way. To be fixed *)
    (* Common *)
    certificateValidationPolicy: cert list -> bool
    safe_renegotiation: bool
    
    (* Sessions database *)
    sessionDBFileName: string
    sessionDBExpiry: TimeSpan
    }

let defaultCertificateValidationPolicy certList = true
let defaultGoodSession (si:SessionInfo) = true

let defaultProtocolOptions ={
    minVer = SSL_3p0
    maxVer = TLS_1p2
    ciphersuites = cipherSuites_of_nameList
                    [ TLS_RSA_WITH_AES_128_CBC_SHA;
                      TLS_RSA_WITH_3DES_EDE_CBC_SHA;
                    ]
    compressions = [ NullCompression ]

    honourHelloReq = HRPResume
    allowAnonCipherSuite = false
    request_client_certificate = false
    check_client_version_in_pms_for_old_tls = true
    server_cert_file = "server"
    certificateValidationPolicy = defaultCertificateValidationPolicy
    safe_renegotiation = true

    sessionDBFileName = "sessionDBFile.bin"
    sessionDBExpiry = newTimeSpan 2 0 0 0 (* two days *)
    }