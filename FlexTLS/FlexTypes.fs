#light "off"

module FlexTypes

open Bytes
open System
open TLSInfo
open TLSConstants


(* Define prefered version for TLS *)
let pv = TLS_1p2


(* Keep track of the Record state and the associated Epoch of an I/O channel *)
type channel = {
    record: Record.ConnectionState;
    (* hs:     Handshake.hs_state; *)
    epoch:  TLSInfo.epoch;
}

(* Global state of the application for Handshake and both input/output channels of a network stream *)
type state = {
    read_s: channel;
    write_s: channel;
    ns: Tcp.NetworkStream;
}

(* Record associated to a HelloRequest message *)
type FHelloRequest = {
    null_payload: bytes;
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
(* TODO : complete this !!
type FCertificateRequest = {
    sign: bool;
}
*)

(* Record associated to a ServerHelloDone message *)
(* Record associated to a CertificateVerify message *)
(* Record associated to a ClientKeyExchange message *)
(* Record associated to a Finished message *)


(* Record associated with conservation of all HS messages *)
type FHSMessages = {
    helloRequest: FHelloRequest;
    clientHello: FClientHello;
    serverHello: FServerHello;
    serverCertificate: FCertificate;
    clientCertificate: FCertificate;
    //serverKeyExchange: FServerKeyExchange;
    //certificateRequest: FCertificateRequest;
    //serverHelloDone: FServerHelloDone;
    //certificateVerify: FCertificateVerify;
    //clientKeyExchange: ClientKeyExchange;
    //finished: Finished;
}


(* Define a null FHelloRequest record *)
let nullFHelloRequest = {   null_payload = empty_bytes;
                        }

(* Define a null FClientHello record *)
let nullFClientHello  = {   pv = pv;
                            rand = empty_bytes; 
                            sid = empty_bytes;
                            suites = [];
                            comps = [];
                            ext = empty_bytes;
                            payload = empty_bytes;
                        }


(* Define a null FServerHello record *)
let nullFServerHello  = {   pv = pv;
                            rand = empty_bytes; 
                            sid = empty_bytes;
                            suite = nullCipherSuite;
                            comp = NullCompression;
                            ext = empty_bytes;
                            payload = empty_bytes;
                        }

(* Define a null FCertificate record *)
let nullFCertificate =  {   chain = [];
                        }


(* Define a null FHSMessages record *)
let nullFHSMessages = {   helloRequest = nullFHelloRequest;
                          clientHello = nullFClientHello;
                          serverHello = nullFServerHello;
                          clientCertificate = nullFCertificate;
                          serverCertificate = nullFCertificate;
                      }


(* Define a null SessionInfo record *)
let nullFSessionInfo = {    clientID = [];
                            clientSigAlg = (SA_RSA,SHA);
                            serverSigAlg = (SA_RSA,SHA);
                            client_auth = false;
                            serverID = [];
                            sessionID = empty_bytes;
                            protocol_version = TLS_1p2;
                            cipher_suite = nullCipherSuite;
                            compression = NullCompression;
                            extensions = [];
                            init_crand = empty_bytes;
                            init_srand = empty_bytes;
                            session_hash = empty_bytes;
                            pmsId = noPmsId;
                       }
