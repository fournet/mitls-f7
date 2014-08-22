#light "off"

module FlexTypes

open Bytes
open System
open TLSError
open TLSInfo
open TLSConstants




(* Fragmentation policy union type *)
type fragmentationPolicy =
    | All of int
    | One of int

(* Keep track of the Record state and the associated Epoch of an I/O channel *)
type channel = {
    record: Record.ConnectionState;
    epoch:  TLSInfo.epoch;
    hs_buffer: bytes;
    alert_buffer: bytes;
}

(* Global state of the application for Handshake and both input/output channels of a network stream *)
type state = {
    read: channel;
    write: channel;
    ns: Tcp.NetworkStream;
}

(* Next security context record used to generate a new channel epoch *)
type nextSecurityContext = {
    si: SessionInfo;
}

(* Record associated to a HelloRequest message *)
type FHelloRequest = {
    payload: bytes;
}

(* Record associated to a ClientHello message *)
type FClientHello = {
    pv: ProtocolVersion;
    rand: bytes;
    sid: bytes;
    suites: cipherSuites;
    comps: list<Compression>;
    ext: bytes;
    payload: bytes;
}

(* Record associated to a ServerHello message *)
type FServerHello = {
    pv: ProtocolVersion;
    rand: bytes;
    sid: bytes;
    suite: cipherSuite;
    comp: Compression;
    ext: bytes;
    payload: bytes;
}

(* Record associated to a Certificate message *)
type FCertificate = {
    chain: Cert.chain;
}

(* Record associated to a ServerKeyExchange message *)
(* Record associated to a CertificateRequest message *)

(* Record associated to a ServerHelloDone message *)
type FServerHelloDone = {
    payload: bytes;
}

(* Record associated to a CertificateVerify message *)
(* Record associated to a ClientKeyExchange message *)

(* Record associated to a Finished message *)
type FFinished = {
    verify_data: bytes;
    payload: bytes;
}

(* Record associated with conservation of all HS messages *)
type FHSMessages = {
    helloRequest: FHelloRequest;
    clientHello: FClientHello;
    serverHello: FServerHello;
    serverCertificate: FCertificate;
    clientCertificate: FCertificate;
    //serverKeyExchange: FServerKeyExchange;
    //certificateRequest: FCertificateRequest;
    serverHelloDone: FServerHelloDone;
    //certificateVerify: FCertificateVerify;
    //clientKeyExchange: FClientKeyExchange;
    clientFinished: FFinished;
    serverFinished: FFinished
}
