#light "off"

module FlexConstants

open Bytes
open System
open TLSError
open TLSInfo
open TLSConstants

open FlexTypes




(* Define a default ProtocolVersion *)
let defaultProtocolVersion = TLS_1p2

(* Define a default fragmentationPolicy *)
let defaultFragmentationPolicy = All(fragmentLength)

(* Define a null FHelloRequest record *)
let nullFHelloRequest : FHelloRequest = {   payload = empty_bytes;
                                        }

(* Define a null FClientHello record *)
let nullFClientHello : FClientHello = {   pv = defaultConfig.maxVer;
                                          rand = empty_bytes; 
                                          sid = empty_bytes;
                                          suites = defaultConfig.ciphersuites;
                                          comps = defaultConfig.compressions;
                                          ext = empty_bytes;
                                          payload = empty_bytes;
                                      }


(* Define a null FServerHello record *)
let nullFServerHello : FServerHello = {   pv = defaultConfig.maxVer;
                                          rand = empty_bytes; 
                                          sid = empty_bytes;
                                          suite = defaultConfig.ciphersuites.Head;
                                          comp = defaultConfig.compressions.Head;
                                          ext = empty_bytes;
                                          payload = empty_bytes;
                                      }

(* Define a null FCertificate record *)
let nullFCertificate : FCertificate = {   chain = [];
                                      }

(* Define a null FServerHelloDone record *)
let nullFServerHelloDone : FServerHelloDone =  {   payload = empty_bytes;
                                               }

(* Define a null FFinished record *)
let nullFFinished : FFinished = {   verify_data = empty_bytes;
                                    payload = empty_bytes;
                                }

(* Define a null FHSMessages record *)
let nullFHSMessages = {   helloRequest = nullFHelloRequest;
                          clientHello = nullFClientHello;
                          serverHello = nullFServerHello;
                          clientCertificate = nullFCertificate;
                          serverCertificate = nullFCertificate;
                          (* TODO : complete this *)
                          serverHelloDone = nullFServerHelloDone;
                          clientFinished = nullFFinished;
                          serverFinished = nullFFinished;
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

(* Define a null nextSecurityContext record *)
let nullNextSecurityContext = {   si = nullFSessionInfo
                              }
