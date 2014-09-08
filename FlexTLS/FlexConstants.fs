#light "off"

module FlexConstants

open Bytes
open System
open Error
open TLSError
open TLSInfo
open TLSConstants

open FlexTypes


(* Default TCP port to connect to *)
let defaultTCPPort = 443

(* Define a default ProtocolVersion *)
let defaultProtocolVersion = TLS_1p2

(* Define a default fragmentationPolicy *)
let defaultFragmentationPolicy = All(fragmentLength)

(* Algorithms for RSA ciphersuites *)
let calgs_RSA = [(SA_RSA, SHA256);(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL)]

(* Algorithms for DHx ciphersuites *)
let calgs_DHx = []




(* Redefine TLSConstants name parsing to handle SCSV ciphersuites *)
let rec names_of_cipherSuites css =
    match css with
    | [] -> correct []
    | h::t ->
        let hl = h::[] in
        if contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV hl then
            match names_of_cipherSuites t with
            | Error(x,y) -> Error(x,y)
            | Correct(rem) -> correct(rem)
        else
            match name_of_cipherSuite h with
            | Error(x,y) -> Error(x,y)
            | Correct(n) ->
                match names_of_cipherSuites t with
                | Error(x,y) -> Error(x,y)
                | Correct(rem) -> correct (n::rem)

(* Define a default DH key exchange parameters structure where x,gx are the local values and gy is the remote public value *)
let nullKexDH = { gp = (let dhparams = CoreDH.load_default_params() in (dhparams.g,dhparams.p));
                  x = empty_bytes; gx = empty_bytes; gy = empty_bytes;
                }

(* Define a null FHelloRequest record *)
let nullFHelloRequest : FHelloRequest = {   payload = empty_bytes;
                                        }

(* Define a null FClientHello record *)
let nullFClientHello : FClientHello = {   pv = defaultConfig.maxVer;
                                          rand = empty_bytes; 
                                          sid = empty_bytes;
                                          suites = (match names_of_cipherSuites defaultConfig.ciphersuites with
                                            | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
                                            | Correct(s) -> s);
                                          comps = defaultConfig.compressions;
                                          ext = empty_bytes;
                                          payload = empty_bytes;
                                      }


(* Define a null FServerHello record *)
let nullFServerHello : FServerHello = {   pv = defaultConfig.maxVer;
                                          rand = empty_bytes; 
                                          sid = empty_bytes;
                                          suite = (match name_of_cipherSuite defaultConfig.ciphersuites.Head with
                                            | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
                                            | Correct(cs) -> cs);
                                          comp = defaultConfig.compressions.Head;
                                          ext = empty_bytes;
                                          payload = empty_bytes;
                                      }

(* Define a null FCertificate record *)
let nullFCertificate : FCertificate = {   chain = [];
                                          payload = empty_bytes;
                                      }

(* Define a null FCertificateRequest record *)
// FIXME: We may find better defaults for this, once CertificateRequest generation is improved
let nullFCertificateRequest : FCertificateRequest = { certTypes = [RSA_sign; DSA_sign];
                                                      sigAlgs = [];
                                                      names = [];
                                                      payload = empty_bytes;
                                                    }

(* Define a null FCertificateVerify record *)
let nullFCertificateVerify : FCertificateVerify = { sigAlg = calgs_RSA.Head;
                                                    signature = empty_bytes;
                                                    payload = empty_bytes;
                                                  }

(* Define a null FServerKeyExchange record for all DH key exchange mechanisms *)
let nullFServerKeyExchangeDHx : FServerKeyExchange = { sigAlg = calgs_DHx.Head;
                                                          signature = empty_bytes;
                                                          kex = DH(nullKexDH);
                                                          payload = empty_bytes;
                                                        }

(* Define a null FServerHelloDone record *)
let nullFServerHelloDone : FServerHelloDone =  { payload = empty_bytes;
                                               }

(* Define a null FClientKeyExchange record for RSA *)
let nullFClientKeyExchangeRSA : FClientKeyExchange = { kex = RSA(empty_bytes);
                                                          payload = empty_bytes;
                                                        }

(* Define a null FClientKeyExchange record for DHx *)
let nullFClientKeyExchangeDHx : FClientKeyExchange = { kex = DH(nullKexDH);
                                                          payload = empty_bytes;
                                                        }

(* Define a null FChangeCipherSpecs record *)
let nullFChangeCipherSpecs : FChangeCipherSpecs = { payload = HandshakeMessages.CCSBytes;
                                                  }

(* Define a null FFinished record *)
let nullFFinished : FFinished = {   verify_data = empty_bytes;
                                    payload = empty_bytes;
                                }

(* Define a null FHSMessages record *)
let nullFHSMessages = {   helloRequest = nullFHelloRequest;
                          clientHello = nullFClientHello;
                          serverHello = nullFServerHello;
                          serverCertificate = nullFCertificate;
                          certificateRequest = nullFCertificateRequest;
                          clientCertificate = nullFCertificate;
                          serverKeyExchange = nullFServerKeyExchangeDHx;
                          serverHelloDone = nullFServerHelloDone;
                          certificateVerify = nullFCertificateVerify;
                          clientKeyExchange = nullFClientKeyExchangeRSA; //could be DHx
                          clientChangeCipherSpecs = nullFChangeCipherSpecs;
                          serverChangeCipherSpecs = nullFChangeCipherSpecs;
                          clientFinished = nullFFinished;
                          serverFinished = nullFFinished;
                      }

(* Define a null SessionInfo record *)
let nullSessionInfo = {    clientID = [];
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
let nullNextSecurityContext = {   si = nullSessionInfo;
                                  crand = empty_bytes;
                                  srand = empty_bytes;
                                  kex = RSA(empty_bytes);
                                  pms = empty_bytes;
                                  ms = empty_bytes;
                                  keys = empty_bytes,empty_bytes;
                              }

