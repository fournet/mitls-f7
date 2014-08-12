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
    epoch:  TLSInfo.epoch;
}

(* Global state of the application for Handshake and both input/output channels of a network stream *)
type state = {
    read_s: channel;
    write_s: channel;
    ns: Tcp.NetworkStream;
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

(* Record associated with conservation of all HS messages *)
type FHSMessages = {
    clientHello: FClientHello;
    serverHello: FServerHello;
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

(* Define a null FHSMessages record *)
let nullFHSMessages = {   clientHello = nullFClientHello;
                          serverHello = nullFServerHello;
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
