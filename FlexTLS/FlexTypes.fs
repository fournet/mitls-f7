#light "off"

module FlexTypes

open Bytes
open TLSInfo
open TLSConstants




/// <summary>
/// Fragmentation policy union type,
/// The constructor represents the number of fragments that will be sent to the network
/// The value represents the length of the fragments that will be sent
/// </summary>
type fragmentationPolicy =
    | All of int
    | One of int

/// <summary>
/// DH key exchange parameters record,
/// Contains both public and secret values associated of Diffie Hellman parameters
/// </summary>
/// <param name="pg"> Tuple (p,g) that contains both p and g public DH parameters </param>
/// <param name="x"> Local secret value of the DH exchange </param>
/// <param name="gx"> Local public value (g^x mod p) of the DH exchange </param>
/// <param name="gy"> Local public value (g^y mod p) of the DH exchange </param>
type kexDH = { 
    pg: bytes * bytes;
    x:  bytes;
    gx: bytes;
    gy: bytes
}

/// <summary>
/// Key exchange union type,
/// The constructor represents the type of Key Exchange Mechanism used in the Handshake
/// The value for RSA is a PreMasterSecret as bytes
/// The value for DH is a record containing all DH parameters known to a peer
/// </summary>
type kex =
    | RSA of bytes
    | DH of kexDH
    | DH13 of HandshakeMessages.tls13kex
 // | ECDH of kexECDH // TODO

(* ------------------------------------------------------------------------------------- *)
(* EXPERIMENTAL TLS 1.3 *)

/// <summary>
/// EXPERIMENTAL TLS 1.3 Handshake Message record type for Client Key Exchange
/// </summary>
/// <param name="offers"> List of Key Exchange mechanisms informations </param>
/// <param name="payload"> Real message bytes </param>
type FClientKeyExchangeTLS13 = {
    offers:list<HandshakeMessages.tls13kex>;
    payload:bytes;
}

/// <summary>
/// EXPERIMENTAL TLS 1.3 Handshake Message record type for Server Key Exchange
/// </summary>
/// <param name="kex"> Key Exchange mechanism information </param>
/// <param name="payload"> Real message bytes </param>
type FServerKeyExchangeTLS13 = {
    kex:kex;
    payload:bytes;
}

(* ------------------------------------------------------------------------------------- *)

/// <summary>
/// Session Keys record,
/// This structure contains all secret information of a Handshake
/// </summary>
/// <param name="kex"> Type of Key Exchange Mechanism </param>
/// <param name="pms"> Pre Master Secret bytes of the current session </param>
/// <param name="ms"> Master Secret bytes of the current Epoch </param>
/// <param name="epoch_keys"> Keys bytes of the current Epoch as a tuple (reading keys, writing keys) </param>
type keys = {
    kex: kex;
    pms: bytes;
    ms: bytes;
    epoch_keys: bytes * bytes;
       (* read  , write *)
}

/// <summary>
/// Channel record,
/// Keep track of the Record state and the associated Epoch of an I/O channel
/// </summary>
/// <param name="record"> Record connection state that embed the encryption status, etc... </param>
/// <param name="epoch"> Epoch connection state </param>
/// <param name="keys"> Keys of the designated Handshake </param>
/// <param name="epoch_init_pv"> Initially choosen protocol version before negociation </param>
/// <param name="hs_buffer"> Buffer for packets with the Handshake content type </param>
/// <param name="alert_buffer"> Buffer for packets with the Alert content type </param>
/// <param name="appdata_buffer"> Buffer for packets with the ApplicationData content type </param>
/// <remarks> There is no CCS buffer because those are only one byte </remarks>
type channel = {
    record: Record.ConnectionState;
    epoch:  TLSInfo.epoch;
    keys: keys;
    epoch_init_pv: ProtocolVersion;
    hs_buffer: bytes;
    alert_buffer: bytes;
    appdata_buffer: bytes
}

/// <summary>
/// Global state of the application for the designated Handshake separated as input/output channels
/// </summary>
/// <param name="read"> Reading channel state (Incoming) </param>
/// <param name="write"> Writing channel state (Outcoming) </param>
/// <param name="ns"> Network stream where the data is exchanged with the other peer </param>
type state = {
    read: channel;
    write: channel;
    ns: Tcp.NetworkStream;
}

(* Next security context record used to generate a new channel epoch *)
/// <summary>
/// Elements required to build the new state of epoch for a channel
/// </summary>
/// <param name="si"> Next session informations (for the future epoch/record state) </param>
/// <param name="crand"> Current client random bytes that will be used to generate new keys </param>
/// <param name="srand"> Current server random bytes that will be used to generate new keys </param>
/// <param name="keys"> New keys associated to the next epoch, to be generated and/or installed into state </param>
type nextSecurityContext = {
    si: SessionInfo;
    crand: bytes;
    srand: bytes;
    keys: keys;
}

/// <summary>
/// Handshake Message record type for Hello Request
/// </summary>
/// <param name="payload"> Contains the entire message (without fragments headers) </param>
type FHelloRequest = {
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Client Hello
/// </summary>
/// <param name="pv"> Protocol version </param>
/// <param name="rand"> Current client random bytes </param>
/// <param name="sid"> Session identification number bytes that are not empty if the client wants a resumption </param>
/// <param name="suites"> List of ciphersuite names supported by the client </param>
/// <param name="comps"> List of compression mechanisms supported by the client </param>
/// <param name="ext"> List of extensions supported by the client (unparsed, as bytes) </param>
/// <param name="payload"> Real message bytes </param>
type FClientHello = {
    pv: ProtocolVersion;
    rand: bytes;
    sid: bytes;
    suites: list<cipherSuiteName>;
    comps: list<Compression>;
    ext: bytes;
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Server Hello
/// </summary>
/// <param name="pv"> Protocol version </param>
/// <param name="rand"> Current server random bytes </param>
/// <param name="sid"> Session identification number bytes that are not empty if the server grants a resumption </param>
/// <param name="suite"> Ciphersuite selected by the server </param>
/// <param name="comp"> Compression selected by the server </param>
/// <param name="ext"> List of extensions agreed by the client (unparsed, as bytes) </param>
/// <param name="payload"> Real message bytes </param>
type FServerHello = {
    pv: ProtocolVersion;
    rand: bytes;
    sid: bytes;
    suite: cipherSuiteName;
    comp: Compression;
    ext: bytes;
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Certificate
/// </summary>
/// <param name="chain"> Full certificate chain bytes </param>
/// <param name="payload"> Real message bytes </param>
type FCertificate = {
    chain: Cert.chain;
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Server Key Exchange
/// </summary>
/// <param name="sigAlg"> Signature algorithm </param>
/// <param name="signature"> Signature </param>
/// <param name="kex"> Key Exchange Information </param>
/// <param name="payload"> Real message bytes </param>
type FServerKeyExchange = {
    sigAlg: Sig.alg;
    signature: bytes;
    kex: kex;
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Certificate Request
/// </summary>
/// <param name="certTypes"> List of certificate types </param>
/// <param name="sigAlgs"> List of Signature algorithms </param>
/// <param name="names"> List of user provided cert names </param>
/// <param name="payload"> Real message bytes </param>
type FCertificateRequest = {
    certTypes: list<certType>;
    sigAlgs: list<Sig.alg>;
    names: list<string>;
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Server Hello Done
/// </summary>
/// <param name="payload"> Real message bytes </param>
type FServerHelloDone = {
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Certificate Verify
/// </summary>
/// <param name="sigAlg"> Signature algorithm </param>
/// <param name="signature"> Signature </param>
/// <param name="payload"> Real message bytes </param>
type FCertificateVerify = {
    sigAlg: Sig.alg;
    signature: bytes;
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Client Key Exchange
/// </summary>
/// <param name="kex"> Key Exchange mechanism information </param>
/// <param name="payload"> Real message bytes </param>
type FClientKeyExchange = {
    kex:kex;
    payload:bytes;
}


/// <summary>
/// CCS Message record type
/// </summary>
/// <param name="payload"> Real message bytes </param>
type FChangeCipherSpecs = {
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Client Key Exchange
/// </summary>
/// <param name="verify_data"> Signature over a hash of the log of the handshake </param>
/// <param name="payload"> Real message bytes </param>
type FFinished = {
    verify_data: bytes;
    payload: bytes;
}
