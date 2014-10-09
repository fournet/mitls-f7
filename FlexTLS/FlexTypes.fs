#light "off"

module FlexTLS.FlexTypes

open Bytes
open TLSInfo
open TLSConstants
open TLSExtensions




/// <summary>
/// Fragmentation policy union type,
/// The constructor represents the number of fragments that will be sent to the network
/// The value represents the length of the fragments that will be sent
/// </summary>
type fragmentationPolicy =
    /// <summary> Will send All fragments of LEN bytes of a payload </summary>
    | All of int
    /// <summary> Will send One fragments of LEN bytes of a payload </summary>
    | One of int

/// <summary>
/// DH key exchange parameters record,
/// Contains both public and secret values associated of Diffie Hellman parameters
/// </summary>
type kexDH = { 
    /// <summary> Tuple (p,g) that contains both p and g public DH parameters </summary>
    pg: bytes * bytes;
    /// <summary> Local secret value of the DH exchange </summary>
    x:  bytes;
    /// <summary> Local public value (g^x mod p) of the DH exchange </summary>
    gx: bytes;
    /// <summary> Local public value (g^y mod p) of the DH exchange </summary>
    gy: bytes
}

/// <summary>
/// DH key exchange parameters record,
/// Contains both public and secret values associated of Diffie Hellman parameters
/// </summary>
type kexDHTLS13 = { 
    /// <summary> DH group negociated </summary>
    group: dhGroup;
    /// <summary> Local secret value of the DH exchange </summary>
    x:  bytes;
    /// <summary> Local public value (g^x mod p) of the DH exchange </summary>
    gx: bytes;
    /// <summary> Local public value (g^y mod p) of the DH exchange </summary>
    gy: bytes;
}

/// <summary>
/// Key exchange union type,
/// The constructor represents the type of Key Exchange Mechanism used in the Handshake
/// The value for RSA is a PreMasterSecret as bytes
/// The value for DH is a record containing all DH parameters known to a peer
/// </summary>
type kex =
    /// <summary> Key Exchange Type is RSA and the constructor holds an Encrypted PreMasterSecret </summary>
    | RSA of bytes
    /// <summary> Key Exchange Type is Diffie-Hellman and the constructor holds all DH parameters </summary>
    | DH of kexDH
    /// <summary> Key Exchange Type is Diffie-Hellman for TLS 1.3 and the constructor holds all DH parameters </summary>
    | DH13 of kexDHTLS13
 // | ECDH of kexECDH // TODO

/// <summary>
/// EXPERIMENTAL TLS 1.3 Handshake Message record type for Client Key Share
/// </summary>
type FClientKeyShare = {
    /// <summary> List of Key Exchange mechanisms informations </summary>
    offers:list<HandshakeMessages.tls13kex>;
    /// <summary> Message bytes</summary>
    payload:bytes;
}

/// <summary>
/// EXPERIMENTAL TLS 1.3 Handshake Message record type for Server Key Share
/// </summary>
type FServerKeyShare = {
    /// <summary> Key Exchange mechanism information </summary>
    kex:HandshakeMessages.tls13kex;
    /// <summary> Message bytes </summary>
    payload:bytes;
}

/// <summary>
/// Session Keys record,
/// This structure contains all secret information of a Handshake
/// </summary>
type keys = {
    /// <summary> Type of Key Exchange Mechanism </summary>
    kex: kex;
    /// <summary> Pre Master Secret bytes of the current session </summary>
    pms: bytes;
    /// <summary> Master Secret bytes of the current Epoch </summary>
    ms: bytes;
    /// <summary> Keys bytes of the current Epoch as a tuple (reading keys, writing keys) </summary>
    epoch_keys: bytes * bytes;
       (* read  , write *)
}

/// <summary>
/// Channel record,
/// Keep track of the Record state and the associated Epoch of an I/O channel
/// </summary>
/// <remarks> There is no CCS buffer because those are only one byte </remarks>
type channel = {
    /// <summary> Record connection state that embed the encryption status, etc... </summary>
    record: Record.ConnectionState;
    /// <summary> Epoch connection state </summary>
    epoch:  TLSInfo.epoch;
    /// <summary> Keys of the designated Handshake </summary>
    keys: keys;
    /// <summary> Initially choosen protocol version before negociation </summary>
    epoch_init_pv: ProtocolVersion;
    /// <summary> Buffer for packets with the Handshake content type </summary>
    hs_buffer: bytes;
    /// <summary> Buffer for packets with the Alert content type </summary>
    alert_buffer: bytes;
    /// <summary> Buffer for packets with the ApplicationData content type </summary>
    appdata_buffer: bytes
}

/// <summary>
/// Global state of the application for the designated Handshake separated as input/output channels
/// </summary>
type state = {
    /// <summary> Reading channel state (Incoming) </summary>
    read: channel;
    /// <summary> Writing channel state (Outcoming) </summary>
    write: channel;
    /// <summary> Network stream where the data is exchanged with the other peer </summary>
    ns: Tcp.NetworkStream;
}

/// <summary>
/// Next security context record used to generate a new channel epoch
/// </summary>
type nextSecurityContext = {
    /// <summary> Next session informations (for the future epoch/record state) </summary>
    si: SessionInfo;
    /// <summary> Current client random bytes that will be used to generate new keys </summary>
    crand: bytes;
    /// <summary> Current server random bytes that will be used to generate new keys </summary>
    srand: bytes;
    /// <summary> New keys associated to the next epoch, to be generated and/or installed into state </summary>
    keys: keys;
    /// <summary> Offers of DH groups and public keys from the client for TLS 1.3 </summary>
    offers: list<kex>;
}

/// <summary>
/// Handshake Message record type for Hello Request
/// </summary>
type FHelloRequest = {
    /// <summary> Message Bytes </summary>
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Client Hello
/// </summary>
type FClientHello = {
    /// <summary> Protocol version </summary>
    pv: ProtocolVersion;
    /// <summary> Current client random bytes </summary>
    rand: bytes;
    /// <summary> Session identification number bytes that are not empty if the client wants a resumption </summary>
    sid: bytes;
    /// <summary> List of ciphersuite names supported by the client </summary>
    suites: list<cipherSuiteName>;
    /// <summary> List of compression mechanisms supported by the client </summary>
    comps: list<Compression>;
    /// <summary> List of extensions supported by the client (unparsed, as bytes)</summary>
    ext: list<clientExtension>;
    /// <summary> Message Bytes </summary>
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Server Hello
/// </summary>
type FServerHello = {
/// <summary> Protocol version </summary>
    pv: ProtocolVersion;
    /// <summary> Current server random bytes </summary>
    rand: bytes;
    /// <summary> Session identification number bytes that are not empty if the server grants a resumption </summary>
    sid: bytes;
    /// <summary> Ciphersuite selected by the server </summary>
    suite: cipherSuiteName;
    /// <summary> Compression selected by the server </summary>
    comp: Compression;
    /// <summary> List of extensions agreed by the client (unparsed, as bytes) </summary>
    ext: list<serverExtension>;
    /// <summary> Message bytes </summary>
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Certificate
/// </summary>
type FCertificate = {
    /// <summary> Full certificate chain bytes </summary>
    chain: Cert.chain;
    /// <summary> Message bytes</summary>
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Server Key Exchange
/// </summary>
type FServerKeyExchange = {
    /// <summary> Signature algorithm </summary>
    sigAlg: Sig.alg;
    /// <summary> Signature </summary>
    signature: bytes;
    /// <summary> Key Exchange Information </summary>
    kex: kex;
    /// <summary> Message bytes </summary>
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Certificate Request
/// </summary>
type FCertificateRequest = {
    /// <summary> List of certificate types </summary>
    certTypes: list<certType>;
    /// <summary> List of Signature algorithms </summary>
    sigAlgs: list<Sig.alg>;
    /// <summary> List of user provided cert names </summary>
    names: list<string>;
    /// <summary> Message bytes </summary>
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Server Hello Done
/// </summary>
type FServerHelloDone = {
    /// <summary> Message Bytes</summary>
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Certificate Verify
/// </summary>
type FCertificateVerify = {
    /// <summary> Signature algorithm </summary>
    sigAlg: Sig.alg;
    /// <summary> Signature </summary>
    signature: bytes;
    /// <summary> Message bytes </summary>
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Client Key Exchange
/// </summary>
type FClientKeyExchange = {
    /// <summary> Key Exchange mechanism information </summary>
    kex:kex;
    /// <summary> Message bytes </summary>
    payload:bytes;
}


/// <summary>
/// CCS Message record type
/// </summary>
type FChangeCipherSpecs = {
    /// <summary> Message bytes </summary>
    payload: bytes;
}

/// <summary>
/// Handshake Message record type for Finished
/// </summary>
type FFinished = {
    /// <summary> Signature over a hash of the log of the handshake </summary>
    verify_data: bytes;
    /// <summary> Message bytes </summary>
    payload: bytes;
}
