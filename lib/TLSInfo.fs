module TLSInfo

open Bytes
open Certificate
open CipherSuites

type sessionID = bytes
type preRole =
    | Client
    | Server
type Role = preRole

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

let null_sessionInfo pv =
    { clientID = None;
      serverID = None;
      sessionID = None;
      protocol_version = pv;
      cipher_suite = nullCipherSuite;
      compression = NullCompression;
      init_crand = [||]
      init_srand = [||]
      }

let isNullSessionInfo s =
  s.clientID = None && s.serverID = None && s.sessionID = None &&
  isNullCipherSuite s.cipher_suite && s.compression = NullCompression &&
  s.init_crand = [||] && s.init_srand = [||]

type preEpoch =
    | InitEpoch of Role * (* ourRand *) bytes
    | SuccEpoch of (* crand *) bytes * (* srand *) bytes * SessionInfo * preEpoch // * cVerifyData:bytes * sVerifyData:bytes
type epoch = preEpoch

let epochSI e =
    match e with
    | InitEpoch (d,b) -> null_sessionInfo SSL_3p0 //FIXME: fake value
    | SuccEpoch (b1,b2,si,pe) -> si

let epochSRand e =
    match e with
    | InitEpoch (d,b) -> Error.unexpectedError "[epochSRand] invoked on initial epoch."
    | SuccEpoch (b1,b2,si,pe) -> b2

let epochCRand e =
    match e with
    | InitEpoch (d,b) -> Error.unexpectedError "[epochSRand] invoked on initial epoch."
    | SuccEpoch (b1,b2,si,pe) -> b1

type ConnectionInfo = {
    role: Role;
    id_in: epoch;
    id_out: epoch}

let connectionRole ci = ci.role

let initConnection role rand =
    let ctos = InitEpoch (Client,rand) in
    let stoc = InitEpoch (Server,rand) in
    match role with
    | Client -> {role = Client; id_in = stoc; id_out = ctos}
    | Server -> {role = Server; id_in = ctos; id_out = stoc}

let nextConnection ci crand srand si =
    let incoming = SuccEpoch (crand, srand, si, ci.id_in ) in
    let outgoing = SuccEpoch (crand, srand, si, ci.id_out) in
    { role = ci.role;
      id_in = incoming;
      id_out = outgoing}

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