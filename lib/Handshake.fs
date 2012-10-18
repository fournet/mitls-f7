(* Handshake protocol *) 
module Handshake

open Bytes
open Error
open TLSConstants
open TLSConstants

open TLSInfo
open PRFs

// BEGIN HS_msg

// This section is from the legacy HS_msg module, now merged with Handshake. 
// Still, there are some redundancies that should be eliminated, 
// by semantically merge the two.

(*** Following RFC5246 A.4 *)

type HandshakeType =
    | HT_hello_request
    | HT_client_hello
    | HT_server_hello
    | HT_certificate
    | HT_server_key_exchange
    | HT_certificate_request
    | HT_server_hello_done
    | HT_certificate_verify
    | HT_client_key_exchange
    | HT_finished

let htBytes t =
    match t with
    | HT_hello_request       -> [|  0uy |] 
    | HT_client_hello        -> [|  1uy |]
    | HT_server_hello        -> [|  2uy |]
    | HT_certificate         -> [| 11uy |]
    | HT_server_key_exchange -> [| 12uy |]
    | HT_certificate_request -> [| 13uy |]
    | HT_server_hello_done   -> [| 14uy |]
    | HT_certificate_verify  -> [| 15uy |]
    | HT_client_key_exchange -> [| 16uy |]
    | HT_finished            -> [| 20uy |]

let parseHt (b:bytes) = 
    match b with
    | [|  0uy |] -> correct(HT_hello_request      )
    | [|  1uy |] -> correct(HT_client_hello       )
    | [|  2uy |] -> correct(HT_server_hello       )
    | [| 11uy |] -> correct(HT_certificate        )
    | [| 12uy |] -> correct(HT_server_key_exchange)
    | [| 13uy |] -> correct(HT_certificate_request)
    | [| 14uy |] -> correct(HT_server_hello_done  )
    | [| 15uy |] -> correct(HT_certificate_verify )
    | [| 16uy |] -> correct(HT_client_key_exchange)
    | [| 20uy |] -> correct(HT_finished           )
    | _   -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

/// Handshake message format 

let messageBytes ht data = htBytes ht @| vlbytes 3 data 

let parseMessage buf =
    (* Somewhat inefficient implementation:
       we repeatedly parse the first 4 bytes of the incoming buffer until we have a complete message;
       we then remove that message from the incoming buffer. *)
    if length buf < 4 then None (* not enough data to start parsing *)
    else
        let (hstypeb,rem) = Bytes.split buf 1 in
        let (lenb,rem) = Bytes.split rem 3 in
        let len = int_of_bytes lenb in
        if length rem < len then None (* not enough payload, try next time *)
        else
            let (payload,rem) = Bytes.split rem len in
            let to_log = hstypeb @| lenb @| payload in //$
            Some(rem,hstypeb,payload,to_log)


// We implement locally fragmentation, not hiding any length
let makeFragment ki b =
    let (b0,rem) = if length b < DataStream.max_TLSCipher_fragment_length then (b,[||])
                   else Bytes.split b DataStream.max_TLSCipher_fragment_length
    let r0 = (length b0, length b0) in
    let f = Fragment.fragmentPlain ki r0 b0 in
    ((r0,f),rem)

// we need something more general for parsing lists, e.g.
// let rec parseList parseOne b =
//     if length b = 0 then correct([])
//     else 
//     match parseOne b with
//     | Correct(x,b) -> 
//         match parseList parseOne b with 
//         | Correct(xs) -> correct(x::xs)
//         | Error(x,y)  -> Error(x,y)
//     | Error(x,y)      -> Error(x,y)


(* Extension handling *)

// missing some details, e.g. ExtensionType/Data
type extensionType =
    | HExt_renegotiation_info
    | HExt_unsupported of bytes

let extensionTypeBytes hExt =
    match hExt with
    | HExt_renegotiation_info -> [|0xFFuy; 0x01uy|]
    | HExt_unsupported (_)    -> unexpectedError "Unknown extension type"

let parseExtensionType b =
    match b with
    | [|0xFFuy; 0x01uy|] -> HExt_renegotiation_info
    | _                  -> HExt_unsupported b

let extensionBytes extType data =
    let extTBytes = extensionTypeBytes extType in
    let payload = vlbytes 2 data in
    extTBytes @| payload

let extensionListBytes el =
    let flat = List.fold (@|) [||] el in
    vlbytes 2 flat

let rec parseExtensionList_int data list =
    match length data with
    | 0 -> correct (list)
    | x when x < 4 ->
        (* This is a parsing error, or a malformed extension *)
        Error (AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | _ ->
        let (extTypeBytes,rem) = Bytes.split data 2 in
        let extType = parseExtensionType extTypeBytes in
        match vlsplit 2 rem with
        | Error(x,y) -> Error (x,y) (* Parsing error *)
        | Correct (payload,rem) -> parseExtensionList_int rem ([(extType,payload)] @ list)

let parseExtensionList data =
    match length data with
    | 0 -> correct ([])
    | 1 -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | _ ->
        match vlparse 2 data with
        | Error(x,y)    -> Error(x,y)
        | Correct(exts) -> 
            match parseExtensionList_int exts [] with
            | Error(x,y) -> Error(x,y)
            | Correct(extList) ->
                (* Check there is at most one renegotiation_info extension *)
                let ren_ext_list = List.filter (fun (ext,_) -> ext = HExt_renegotiation_info) extList in
                if ren_ext_list.Length > 1 then
                    Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Same extension received more than once")
                else
                    correct(extList)
                // FIXME: Check that each extension appears only once


(* Renegotiation Info extension -- RFC 5746 *)
let renegotiationInfoExtensionBytes verifyData =
    let payload = vlbytes 1 verifyData in
    extensionBytes HExt_renegotiation_info payload

let check_reneg_info payload expected =
    // We also check there were no more data in this extension.
    match vlparse 1 payload with
    | Error(x,y)     -> false
    | Correct (recv) -> equalBytes recv expected

let checkClientRenegotiationInfoExtension (ren_ext_list:(extensionType * bytes) list) ch_cipher_suites expected =
    let has_SCSV = contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV ch_cipher_suites in
    if equalBytes expected [||] 
    then  
        (* First handshake *)
        if ren_ext_list.Length = 0 
        then has_SCSV
            (* either client gave SCSV and no extension; this is OK for first handshake *)
            (* or the client doesn't support this extension and we fail *)
        else
            let ren_ext = ren_ext_list.Head in
            let (extType,payload) = ren_ext in
            check_reneg_info payload expected
    else
        (* Not first handshake *)
        if has_SCSV || (ren_ext_list.Length = 0) then false
        else
            let ren_ext = ren_ext_list.Head in
            let (extType,payload) = ren_ext in
            check_reneg_info payload expected

// FIXME: Like function above!!!
let inspect_ServerHello_extensions recvExt expected =
    (* Code is ad-hoc for the only extension we support now: renegotiation_info *)
    match parseExtensionList recvExt with
    | Error (x,y) -> Error (x,y)
    | Correct (extList) ->
        (* We expect to find exactly one extension *)
        match extList.Length with
        | 0 -> Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Not enough extensions given")
        | x when not (x = 1) -> Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Too many extensions given")
        | _ ->
            let (extType,payload) = extList.Head in
            match extType with
            | HExt_renegotiation_info ->
                (* Check its content *)
                if check_reneg_info payload expected then
                    let unitVal = () in
                    correct (unitVal)
                else
                    (* RFC 5746, sec 3.4: send a handshake failure alert *)
                    Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Wrong renegotiation information")
            | _ -> Error(AD_unsupported_extension, perror __SOURCE_FILE__ __LINE__ "The server gave an unknown extension")

(* TODO:
- remove type for all messages.
- uniform names for parse*, *Bytes functions
- 
*)

(** A.4.1 Hello Messages *)

type helloRequest = bytes  // empty bitstring 

type clientHello = (ProtocolVersion * bytes * sessionID * cipherSuites * Compression list * bytes)

type serverHello = (ProtocolVersion * bytes * sessionID * cipherSuite * Compression * bytes)

let parseClientHello data =
    // pre: Length(data) > 34
    // correct post: something like data = ClientHelloBytes(...) 
    let (clVerBytes,cr,data) = split2 data 2 32 in
    match parseVersion clVerBytes with
    | Error(x,y) -> Error(x,y)
    | Correct(cv) ->
    match vlsplit 1 data with
    | Error(x,y) -> Error(x,y)
    | Correct (sid,data) ->
    match vlsplit 2 data with
    | Error(x,y) -> Error(x,y)
    | Correct (clCiphsuitesBytes,data) ->
    match parseCipherSuites clCiphsuitesBytes with
    | Error(x,y) -> Error(x,y) 
    | Correct(clientCipherSuites) ->
    match vlsplit 1 data with
    | Error(x,y) -> Error(x,y)
    | Correct (cmBytes,extensions) ->
    let cm = parseCompressions cmBytes
    correct(cv,cr,sid,clientCipherSuites,cm,extensions)
     
    
let makeRandom() = //$ crypto abstraction? timing guarantees local disjointness
    let time = makeTimestamp () in
    let timeb = bytes_of_int 4 time in
    let rnd = mkRandom 28 in
    timeb @| rnd

let makeClientHelloBytes poptions crand session cVerifyData =
    let ext =
        if poptions.safe_renegotiation 
        then
            let renInfoB = renegotiationInfoExtensionBytes cVerifyData in
            extensionListBytes [renInfoB]
        else [||] in
    let cVerB      = versionBytes poptions.maxVer in
    let random     = crand in
    let csessB     = vlbytes 1 session in
    let ccsuitesB  = vlbytes 2 (cipherSuitesBytes poptions.ciphersuites) in
    let ccompmethB = vlbytes 1 (compressionMethodsBytes poptions.compressions) in
    let data = cVerB @| random @| csessB @| ccsuitesB @| ccompmethB @| ext in
    messageBytes HT_client_hello data

let makeServerHelloBytes sinfo srand ext = 
    let verB = versionBytes sinfo.protocol_version in
    let sidB = vlbytes 1 sinfo.sessionID
    let csB = cipherSuiteBytes sinfo.cipher_suite in
    let cmB = compressionBytes sinfo.compression in
    let data = verB @| srand @| sidB @| csB @| cmB @| ext in
    messageBytes HT_server_hello data

let parseServerHello data =
    let (serverVerBytes,serverRandomBytes,data) = split2 data 2 32 
    match parseVersion serverVerBytes with
    | Error(x,y) -> Error(x,y)
    | Correct(serverVer) ->
    match vlsplit 1 data with
    | Error(x,y) -> Error (x,y)
    | Correct (sid,data) ->
    let (csBytes,cmBytes,data) = split2 data 2 1 
    match parseCipherSuite csBytes with
    | Error(x,y) -> Error(x,y)
    | Correct(cs) ->
    match parseCompression cmBytes with
    | Error(x,y) -> Error(x,y)
    | Correct(cm) ->
    correct(serverVer,serverRandomBytes,sid,cs,cm,data)

/// Hello Request 
let makeHelloRequestBytes () = messageBytes HT_hello_request [||]

let CCSBytes = [| 1uy |]


(** A.4.2 Server Authentication and Key Exchange Messages *)


type serverHelloDone = bytes // empty bitstring

let serverHelloDoneBytes = messageBytes HT_server_hello_done [||] 

let certificatesBytes certs =
    vlbytes 3 (List.foldBack (fun c a -> vlbytes 3 c @| a) certs [||])

let makeCertificateBytes cl = messageBytes HT_certificate (certificatesBytes cl)
    
let makeCertificateBytes_sign cs =
    match cs with
    | None -> makeCertificateBytes []
    | Some(certList,_,_) -> makeCertificateBytes certList

let rec parseCertificate_int toProcess list =
    if equalBytes toProcess [||] then
        correct(list)
    else
        match vlsplit 3 toProcess with
        | Error(x,y) -> Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ (""+y))
        | Correct (nextCert,toProcess) ->
            let list = list @ [nextCert] in
            parseCertificate_int toProcess list

let parseCertificate data =
    match vlparse 3 data with
    | Error(x,y) -> Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ (""+y))
    | Correct (certList) ->
        match parseCertificate_int certList [] with
        | Error(x,y) -> Error(x,y)
        | Correct(certs) -> correct(certs)

let rec parseCertificateTypeList data =
    if length data = 0 then Correct([])
    else
        let (thisByte,data) = Bytes.split data 1 in
        match TLSConstants.parseCertType thisByte with
        | Correct(ct) ->
            match parseCertificateTypeList data with
            | Correct(ctList) -> Correct(ct :: ctList)
            | Error(x,y) -> Error(x,y)
        | Error(x,y) -> Error(x,y)

let rec distNamesList_of_bytes data res =
    if length data = 0 then
        correct (res)
    else
        if length data < 2 then (* FIXME: maybe at least 3 bytes, because we don't want empty names... *)
            Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
        else
            match vlsplit 2 data with
            | Error(x,y) -> Error(x,y)
            | Correct (nameBytes,data) ->
            let name = iutf8 nameBytes in (* FIXME: I have no idea wat "X501 represented in DER-encoding format" (RFC 5246, page 54) is. I assume UTF8 will do. *)
            let res = [name] @ res in
            distNamesList_of_bytes data res

(* SignatureAndHashAlgorithm parsing functions *)
let sigHashAlgBytes (alg:Sig.alg) =
    // pre: we're in TLS 1.2, so hashL contains exactly one element
    let (sign,hashL) = alg in
    let hash = hashL.Head in
    let signB = sigAlgBytes sign in
    let hashB = hashAlgBytes hash in
    hashB @| signB

let parseSigHashAlg b =
    let (hashB,signB) = Bytes.split b 1 in
    match parseSigAlg signB with
    | Error(x,y) -> Error(x,y)
    | Correct(sign) ->
        match parseHashAlg hashB with
        | Error(x,y) -> Error(x,y)
        | Correct(hash) -> correct(sign,[hash])

let rec sigHashAlgListBytes_int algL =
    match algL with
    | [] -> [||]
    | h::t -> (sigHashAlgBytes h) @| sigHashAlgListBytes_int t

let sigHashAlgListBytes algL =
    let payload = sigHashAlgListBytes_int algL in
    vlbytes 2 payload

let rec parseSigHashAlgList_int b : (Sig.alg list Result)=
    if length b = 0 then correct([])
    elif length b = 1 then Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else
        let (thisB,remB) = Bytes.split b 2 in
        match parseSigHashAlg thisB with
        | Error(x,y) -> Error(x,y)
        | Correct(this) ->
            match parseSigHashAlgList_int remB with
            | Error(x,y) -> Error(x,y)
            | Correct(rem) -> correct(this :: rem)

let parseSigHashAlgList b =
    match vlparse 2 b with
    | Error(x,y) -> Error(x,y)
    | Correct(b) -> parseSigHashAlgList_int b

let default_sigHashAlg_fromSig pv sigAlg=
    match sigAlg with
    | SA_RSA ->
        match pv with
        | TLS_1p2 -> [(SA_RSA, [SHA])]
        | TLS_1p0 | TLS_1p1 | SSL_3p0 -> [(SA_RSA,[MD5;SHA])]
        //| SSL_3p0 -> [(SA_RSA,[])]
    | SA_DSA ->
        [(SA_DSA,[SHA])]
        //match pv with
        //| TLS_1p0| TLS_1p1 | TLS_1p2 -> [(SA_DSA, [SHA])]
        //| SSL_3p0 -> [(SA_DSA,[])]
    | _ -> unexpectedError "[makeCertificateRequest] invoked on an invalid ciphersuite"

let default_sigHashAlg pv cs =
    default_sigHashAlg_fromSig pv (sigAlg_of_ciphersuite cs)

let sigHashAlg_contains (algList:Sig.alg list) (alg:Sig.alg) =
    List.exists (fun a -> a = alg) algList

let sigHashAlg_bySigList (algList:Sig.alg list) (sigAlgList:sigAlg list) =
    List.choose (fun alg -> let (sigA,_) = alg in if (List.exists (fun a -> a = sigA) sigAlgList) then Some(alg) else None) algList

let cert_type_to_SigHashAlg ct pv =
    match ct with
    | TLSConstants.DSA_fixed_dh | TLSConstants.DSA_sign -> default_sigHashAlg_fromSig pv SA_DSA
    | TLSConstants.RSA_fixed_dh | TLSConstants.RSA_sign -> default_sigHashAlg_fromSig pv SA_RSA

let rec cert_type_list_to_SigHashAlg ctl pv =
    // FIXME: Generates a list with duplicates!
    match ctl with
    | [] -> []
    | h::t -> (cert_type_to_SigHashAlg h pv) @ (cert_type_list_to_SigHashAlg t pv)

let cert_type_to_SigAlg ct =
    match ct with
    | TLSConstants.DSA_fixed_dh | TLSConstants.DSA_sign -> SA_DSA
    | TLSConstants.RSA_fixed_dh | TLSConstants.RSA_sign -> SA_RSA

let rec cert_type_list_to_SigAlg ctl =
    // FIXME: Generates a list with duplicates!
    match ctl with
    | [] -> []
    | h::t -> (cert_type_to_SigAlg h) :: (cert_type_list_to_SigAlg t)


let makeCertificateRequest sign cs version =
    let certTypes = 
        if sign then
            match sigAlg_of_ciphersuite cs with
            | SA_RSA -> vlbytes 1 (certTypeBytes TLSConstants.RSA_sign)
            | SA_DSA -> vlbytes 1 (certTypeBytes TLSConstants.DSA_sign)
            | _ -> unexpectedError "[makeCertificateRequest] invoked on an invalid ciphersuite"
        else 
            match sigAlg_of_ciphersuite cs with
            | SA_RSA -> vlbytes 1 (certTypeBytes TLSConstants.RSA_fixed_dh)
            | SA_DSA -> vlbytes 1 (certTypeBytes TLSConstants.DSA_fixed_dh)
            | _ -> unexpectedError "[makeCertificateRequest] invoked on an invalid ciphersuite"
    let sigAndAlg =
        match version with
        | TLS_1p2 ->
            sigHashAlgListBytes (default_sigHashAlg version cs)
        | _ -> [||]
    (* We specify no cert auth *)
    let distNames = vlbytes 2 [||] in
    let data = certTypes 
            @| sigAndAlg 
            @| distNames in
    messageBytes HT_certificate_request data

let parseCertificateRequest version data =
    match vlsplit 1 data with
    | Error(x,y) -> Error(x,y)
    | Correct (certTypeListBytes,data) ->
    match parseCertificateTypeList certTypeListBytes with
    | Error(x,y) -> Error(x,y)
    | Correct(certTypeList) ->
    let sigAlgsAndData = (
        if version = TLS_1p2 then
            match vlsplit 2 data with
            | Error(x,y) -> Error(x,y)
            | Correct (sigAlgsBytes,data) ->
            match parseSigHashAlgList sigAlgsBytes with
            | Error(x,y) -> Error(x,y)               
            | Correct (sigAlgsList) -> correct (Some(sigAlgsList),data)
        else
            correct (None,data)) in
    match sigAlgsAndData with
    | Error(x,y) -> Error(x,y)
    | Correct ((sigAlgs,data)) ->
    match vlparse 2 data with
    | Error(x,y) -> Error(x,y)
    | Correct  (distNamesBytes) ->
    match distNamesList_of_bytes distNamesBytes [] with
    | Error(x,y) -> Error(x,y)
    | Correct distNamesList ->
    correct (certTypeList,sigAlgs,distNamesList)


(** A.4.3 Client Authentication and Key Exchange Messages *) 

let makeClientKEX_RSA si config =
    let pms = RSAPlain.genPMS si config.maxVer in
    if si.serverID.IsEmpty then
        unexpectedError "[makeClientKEX_RSA] Server certificate should always be present with a RSA signing cipher suite."
    else
        match Cert.get_chain_public_encryption_key si.serverID with
        | Error(x,y) -> Error(x,y)
            | Correct(pubKey) ->
            let encpms = RSAEnc.encrypt pubKey si pms in
            let encpms = if si.protocol_version = SSL_3p0 then encpms else vlbytes 2 encpms 
            correct((messageBytes HT_client_key_exchange encpms),pms)

let makeClientKEX_DH_explicit y =
    let yb = vlbytes 2 y in
    messageBytes HT_client_key_exchange yb

let makeClientKEX_DH_implicit = messageBytes HT_client_key_exchange [||]

let parseClientKEX_RSA si skey cv config data =
    if si.serverID.IsEmpty then
        unexpectedError "[parseClientKEX_RSA] when the ciphersuite can encrypt the PMS, the server certificate should always be set"
    else
        let encrypted = (* parse the message *)
            match si.protocol_version with
            | SSL_3p0 -> correct (data)
            | TLS_1p0 | TLS_1p1| TLS_1p2 ->
                    match vlparse 2 data with
                    | Correct (encPMS) -> correct(encPMS)
                    | Error(x,y) -> Error(x,y)
        match encrypted with
        | Correct(encPMS) ->
            let res = RSAEnc.decrypt skey si cv config.check_client_version_in_pms_for_old_tls encPMS in
            correct(res)
        | Error(x,y) -> Error(x,y)

let parseClientKEX_DH_implict data =
    if length data = 0 then
        correct ( () )
    else
        Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let parseClientKEX_DH_explicit data = vlparse 2 data

(* Digitally signed struct *)

let digitallySignedBytes alg data pv =
    let sign = vlbytes 2 data in
    match pv with
    | TLS_1p2 ->
        let sigHashB = sigHashAlgBytes alg in
        sigHashB @| sign
    | SSL_3p0 | TLS_1p0 | TLS_1p1 -> sign

let parseDigitallySigned expectedAlgs payload pv =
    match pv with
    | TLS_1p2 ->
        let (recvAlgsB,sign) = Bytes.split payload 2 in
        match parseSigHashAlg recvAlgsB with
        | Error(x,y) -> Error(x,y)
        | Correct(recvAlgs) ->
            if sigHashAlg_contains expectedAlgs recvAlgs then
                match vlparse 2 sign with
                | Error(x,y) -> Error(x,y)
                | Correct(sign) -> correct(recvAlgs,sign)
            else
                Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "")
    | SSL_3p0 | TLS_1p0 | TLS_1p1 ->
        match vlparse 2 payload with
        | Error(x,y) -> Error(x,y)
        | Correct(sign) ->
        // assert: expectedAlgs contains exactly one element
        correct(expectedAlgs.Head,sign)

(* Server Key exchange *)

let dheParamBytes p g y = (vlbytes 2 p) @| (vlbytes 2 g) @| (vlbytes 2 y)
let parseDHEParams payload =
    match vlsplit 2 payload with
    | Error(x,y) -> Error(x,y)
    | Correct(p,payload) ->
    match vlsplit 2 payload with
    | Error(x,y) -> Error(x,y)
    | Correct(g,payload) ->
    match vlsplit 2 payload with
    | Error(x,y) -> Error(x,y)
    | Correct(y,payload) ->
    correct(p,g,y,payload)

let serverKeyExchange_DHE crand srand p g y alg skey pv =
    let dheb = dheParamBytes p g y in
    let toSign = crand @| srand @| dheb in
    let sign = Sig.sign alg skey toSign in
    let sign = digitallySignedBytes alg sign pv in
    let payload = dheb @| sign in
    messageBytes HT_server_key_exchange payload

let checkServerKeyExchange_DHE crand srand cert pv cs payload =
    match parseDHEParams payload with
    | Error(x,y) -> Error(x,y)
    | Correct(p,g,y,payload) ->
        let dheb = dheParamBytes p g y in
        let expected = crand @| srand @| dheb in
        let allowedAlgs = default_sigHashAlg pv cs in
        match parseDigitallySigned allowedAlgs payload pv with
        | Error(x,y) -> Error(x,y)
        | Correct(alg,signature) ->
            match Cert.get_chain_public_signing_key cert alg with
            | Error(x,y) -> Error(x,y)
            | Correct(vkey) ->
            if Sig.verify alg vkey expected signature then
                correct(p,g,y)
            else
                Error(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "")

let serverKeyExchange_DH_anon p g y =
    let dehb = dheParamBytes p g y in
    messageBytes HT_server_key_exchange dehb

let parseServerKeyExchange_DH_anon payload =
    match parseDHEParams payload with
    | Error(x,y) -> Error(x,y)
    | Correct(p,g,y,rem) ->
        if equalBytes rem [||] then
            correct(p,g,y)
        else
            Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(* Certificate Verify *)

type certificateVerify = bytes (* digital signature of all messages exchanged until now *)

let makeCertificateVerifyBytes si ms alg skey data =
    let (alg,toSign) =
        match si.protocol_version with
        | TLS_1p2 | TLS_1p1 | TLS_1p0 -> (alg,data)
        | SSL_3p0 ->
            let (sigAlg,_) = alg in
            let toSign = PRFs.ssl_certificate_verify si ms sigAlg data in
            ((sigAlg,[]),toSign)
    let signed = Sig.sign alg skey toSign in
    let payload = digitallySignedBytes alg signed si.protocol_version in
    messageBytes HT_certificate_verify payload
    
let certificateVerifyCheck si ms algs cert log payload =
    match parseDigitallySigned algs payload si.protocol_version with
    | Error(x,y) -> false
    | Correct(alg,signature) ->
        let (alg,expected) =
            match si.protocol_version with
            | TLS_1p2 | TLS_1p1 | TLS_1p0 -> (alg,log)
            | SSL_3p0 -> 
                let (sigAlg,_) = alg in
                let expected = PRFs.ssl_certificate_verify si ms sigAlg log in
                ((sigAlg,[]),expected)
        match Cert.get_chain_public_signing_key cert alg with
        | Error(x,y) -> false
        | Correct(vkey) ->
        Sig.verify alg vkey expected signature


(** A.4.4 Handshake Finalization Message *)

type finished = bytes

// State machine begins
type log = bytes
type cVerifyData = bytes
type sVerifyData = bytes

type serverState =  (* note that the CertRequest bits are determined by the config *) 
                    (* we may omit some ProtocolVersion, mostly a ghost variable *)
   | ClientHello             of cVerifyData * sVerifyData

   | ClientCertificateRSA    of SessionInfo * ProtocolVersion * RSAKeys.sk * log 
   | ClientKeyExchangeRSA    of SessionInfo * ProtocolVersion * RSAKeys.sk * log

   | ClientCertificateDH     of SessionInfo * log 
   | ClientKeyExchangeDH     of SessionInfo * log 

   | ClientCertificateDHE    of SessionInfo * DHE.g * DHE.p * DHE.x * log
   | ClientKeyExchangeDHE    of SessionInfo * DHE.g * DHE.p * DHE.x * log

   | ClientKeyExchangeDH_anon of SessionInfo * DHE.g * DHE.p * DHE.x * log

   | CertificateVerify       of SessionInfo * masterSecret * log 
   | ClientCCS               of SessionInfo * masterSecret * log
   | ClientFinished          of SessionInfo * masterSecret * epoch * StatefulAEAD.writer * log
   (* by convention, the parameters are named si, cv, cr', sr', ms, log *)
   | ServerWritingCCS        of SessionInfo * masterSecret * epoch * StatefulAEAD.writer * cVerifyData * log
   | ServerWritingFinished   of SessionInfo * masterSecret * cVerifyData * sVerifyData

   | ServerWritingCCSResume  of epoch * StatefulAEAD.writer * epoch * StatefulAEAD.reader * masterSecret * log
   | ClientCCSResume         of epoch * StatefulAEAD.reader * sVerifyData * masterSecret * log
   | ClientFinishedResume    of SessionInfo * masterSecret * sVerifyData * log

   | ServerIdle              of cVerifyData * sVerifyData
   (* the ProtocolVersion is the highest TLS version proposed by the client *)

type clientState = 
   | ServerHello            of crand * sessionID (* * bytes for extensions? *) * cVerifyData * sVerifyData * log

   | ServerCertificateRSA   of SessionInfo * log
   | CertificateRequestRSA  of SessionInfo * log (* In fact, CertReq or SHelloDone will be accepted *)
   | ServerHelloDoneRSA     of SessionInfo * Cert.sign_cert * log

   | ServerCertificateDH    of SessionInfo * log
   | CertificateRequestDH   of SessionInfo * log (* We pick our cert and store it in sessionInfo as soon as the server requests it.
                                                    We put None if we don't have such a certificate, and we know whether to send
                                                    the Certificate message or not based on the state when we receive the Finished message *)
   | ServerHelloDoneDH      of SessionInfo * log

   | ServerCertificateDHE   of SessionInfo * log
   | ServerKeyExchangeDHE   of SessionInfo * log
   | CertificateRequestDHE  of SessionInfo * DHE.g * DHE.p * DHE.y * log
   | ServerHelloDoneDHE     of SessionInfo * Cert.sign_cert * DHE.g * DHE.p * DHE.y * log

   | ServerKeyExchangeDH_anon of SessionInfo * log (* Not supported yet *)
   | ServerHelloDoneDH_anon of SessionInfo * DHE.g * DHE.p * DHE.y * log

   | ClientWritingCCS       of SessionInfo * masterSecret * log
   | ServerCCS              of SessionInfo * masterSecret * epoch * StatefulAEAD.reader * cVerifyData * log
   | ServerFinished         of SessionInfo * masterSecret * cVerifyData * log

   | ServerCCSResume        of epoch * StatefulAEAD.writer * epoch * StatefulAEAD.reader * masterSecret * log
   | ServerFinishedResume   of epoch * StatefulAEAD.writer * masterSecret * log
   | ClientWritingCCSResume of epoch * StatefulAEAD.writer * masterSecret * sVerifyData * log
   | ClientWritingFinishedResume of cVerifyData * sVerifyData

   | ClientIdle             of cVerifyData * sVerifyData

type protoState = // Cannot use Client and Server, otherwise clashes with Role
  | PSClient of clientState
  | PSServer of serverState

type KIAndCCS = (epoch * StatefulAEAD.state)

type pre_hs_state = {
  (* I/O buffers *)
  hs_outgoing    : bytes;                  (* outgoing data *)
  hs_incoming    : bytes;                  (* partial incoming HS message *)
  (* local configuration *)
  poptions: config; 
  sDB: SessionDB.SessionDB;
  (* current handshake & session we are establishing *) 
  pstate: protoState;
}

type hs_state = pre_hs_state
type nextState = hs_state

/// Initiating Handshakes, mostly on the client side. 

let init (role:Role) poptions =
    (* Start a new session without resumption, as the first epoch on this connection. *)
    let sid = [||] in
    let rand = makeRandom() in
    let ci = initConnection role rand in
    match role with
    | Client ->
        // FIXME: extensions should not be handled within makeClientHelloBytes!
        let cHelloBytes = makeClientHelloBytes poptions rand sid [||] in
        let state = {hs_outgoing = cHelloBytes
                     hs_incoming = [||]
                     poptions = poptions
                     sDB = SessionDB.create poptions
                     pstate = PSClient (ServerHello (rand, sid, [||], [||], cHelloBytes))
                    }
        (ci,state)
    | Server ->
        let state = {hs_outgoing = [||]
                     hs_incoming = [||]
                     poptions = poptions
                     sDB = SessionDB.create poptions
                     pstate = PSServer (ClientHello([||],[||]))
                    }
        (ci,state)

let resume next_sid poptions =
    (* Resume a session, as the first epoch on this connection.
       Set up our state as a client. Servers cannot resume *)

    (* Search a client sid in the DB *)
    let sDB = SessionDB.create poptions in
    match SessionDB.select sDB (next_sid,Client,poptions.server_name) with
    | None -> init Client poptions
    | Some (retrieved) ->
    let (retrievedSinfo,retrievedMS) = retrieved in
    match retrievedSinfo.sessionID with
    | [||] -> unexpectedError "[resume_handshake] a resumed session should always have a valid sessionID"
    | sid ->
    let rand = makeRandom () in
    let ci = initConnection Client rand in
    let cHelloBytes = makeClientHelloBytes poptions rand sid [||] in
    let state = {hs_outgoing = cHelloBytes
                 hs_incoming = [||]
                 poptions = poptions
                 sDB = SessionDB.create poptions
                 pstate = PSClient (ServerHello (rand, sid, [||], [||], cHelloBytes))
                } in
    (ci,state)

let rehandshake (ci:ConnectionInfo) (state:hs_state) (ops:config) =
    (* Start a non-resuming handshake, over an existing epoch.
       Only client side, since a server can only issue a HelloRequest *)
    match state.pstate with
    | PSClient (cstate) ->
        match cstate with
        | ClientIdle(cvd,svd) ->
            let rand = makeRandom () in
            let sid = [||] in
            let cHelloBytes = makeClientHelloBytes ops rand sid cvd in
            let state = {hs_outgoing = cHelloBytes
                         hs_incoming = [||]
                         poptions = ops
                         sDB = SessionDB.create ops
                         pstate = PSClient (ServerHello (rand, sid, cvd,svd, cHelloBytes))
                        } in
            (true,state)
        | _ -> (* handshake already happening, ignore this request *)
            (false,state)
    | PSServer (_) -> unexpectedError "[start_rehandshake] should only be invoked on client side connections."

let rekey (ci:ConnectionInfo) (state:hs_state) (ops:config) =
    (* Start a (possibly) resuming handshake over an existing epoch *)
    let si = epochSI(ci.id_out) in // or equivalently ci.id_in
    let sidOp = si.sessionID in
    match sidOp with
    | [||] -> (* Non resumable session, let's do a full handshake *)
        rehandshake ci state ops
    | sid ->
        let sDB = SessionDB.create ops in
        (* Ensure the sid is in the SessionDB *)
        match SessionDB.select sDB (sid,Client,ops.server_name) with
        | None -> (* Maybe session expired, or was never stored. Let's not resume *)
            rehandshake ci state ops
        | Some (retrievedSinfo,retrievedMS) ->
            match state.pstate with
            | PSClient (cstate) ->
                match cstate with
                | ClientIdle(cvd,svd) ->
                    let rand = makeRandom () in
                    let cHelloBytes = makeClientHelloBytes ops rand sid cvd in
                    let state = {hs_outgoing = cHelloBytes
                                 hs_incoming = [||]
                                 poptions = ops
                                 sDB = sDB
                                 pstate = PSClient (ServerHello (rand, sid, cvd, svd, cHelloBytes))
                                } in
                    (true,state)
                | _ -> (* Handshake already ongoing, ignore this request *)
                    (false,state)
            | PSServer (_) -> unexpectedError "[start_rekey] should only be invoked on client side connections."

let request (ci:ConnectionInfo) (state:hs_state) (ops:config) =
    match state.pstate with
    | PSClient _ -> unexpectedError "[start_hs_request] should only be invoked on server side connections."
    | PSServer (sstate) ->
        match sstate with
        | ServerIdle(cvd,svd) ->
            (* Put HelloRequest in outgoing buffer (and do not log it), and move to the ClientHello state (so that we don't send HelloRequest again) *)
            (true, { hs_outgoing = makeHelloRequestBytes ()
                     hs_incoming = [||]
                     poptions = ops
                     sDB = SessionDB.create ops
                     pstate = PSServer(ClientHello(cvd,svd))
                    })
        | _ -> (* Handshake already ongoing, ignore this request *)
            (false,state)

let invalidateSession ci state =
    let si = epochSI(ci.id_in) // FIXME: which epoch to choose? Here it matters since they could be mis-aligned
    match si.sessionID with
    | [||] -> state
    | sid ->
        let hint =
            match ci.role with
            | Client -> state.poptions.server_name
            | Server -> state.poptions.client_name
        let sDB = SessionDB.remove state.sDB (sid,ci.role,hint) in
        {state with sDB=sDB}

let getNextEpochs ci si crand srand =
    let id_in  = nextEpoch ci.id_in  crand srand si in
    let id_out = nextEpoch ci.id_out crand srand si in
    {ci with id_in = id_in; id_out = id_out}

type outgoing =
  | OutIdle of hs_state
  | OutSome of DataStream.range * Fragment.fragment * hs_state
  | OutCCS of  DataStream.range * Fragment.fragment (* the unique one-byte CCS *) *
               ConnectionInfo * StatefulAEAD.state * hs_state
  | OutFinished of DataStream.range * Fragment.fragment * hs_state
  | OutComplete of DataStream.range * Fragment.fragment * hs_state

let next_fragment ci state =
    match state.hs_outgoing with
    | [||] ->
        match state.pstate with
        | PSClient(cstate) ->
            match cstate with
            | ClientWritingCCS (si,ms,log) ->
                let next_ci = getNextEpochs ci si si.init_crand si.init_srand in
                let (writer,reader) = PRFs.keyGen next_ci ms in
                let cvd = makeVerifyData si Client ms log in
                let cFinished = messageBytes HT_finished cvd in
                let log = log @| cFinished in
                let state = {state with hs_outgoing = cFinished 
                                        pstate = PSClient(ServerCCS(si,ms,next_ci.id_in,reader,cvd,log))} in
                let ((rg,f),_) = makeFragment ci.id_out CCSBytes in
                let ci = {ci with id_out = next_ci.id_out} in 
                OutCCS(rg,f,ci,writer,state)
            | ClientWritingCCSResume(e,w,ms,svd,log) ->
                let cvd = makeVerifyData (epochSI e) Client ms log in
                let cFinished = messageBytes HT_finished cvd in
                let state = {state with hs_outgoing = cFinished
                                        pstate = PSClient(ClientWritingFinishedResume(cvd,svd))} in
                let ((rg,f),_) = makeFragment ci.id_out CCSBytes in
                let ci = {ci with id_out = e} in
                OutCCS(rg,f,ci,w,state)
            | _ -> OutIdle(state)
        | PSServer(sstate) ->
            match sstate with
            | ServerWritingCCS (si,ms,e,w,cvd,log) ->
                let svd = makeVerifyData si Server ms log in
                let sFinished = messageBytes HT_finished svd in
                let state = {state with hs_outgoing = sFinished
                                        pstate = PSServer(ServerWritingFinished(si,ms,cvd,svd))}
                let ((rg,f),_) = makeFragment ci.id_out CCSBytes in
                let ci = {ci with id_out = e} in
                OutCCS(rg,f,ci,w,state)
            | ServerWritingCCSResume(we,w,re,r,ms,log) ->
                let svd = makeVerifyData (epochSI we) Server ms log in
                let sFinished = messageBytes HT_finished svd in
                let log = log @| sFinished in
                let state = {state with hs_outgoing = sFinished
                                        pstate = PSServer(ClientCCSResume(re,r,svd,ms,log))}
                let ((rg,f),_) = makeFragment ci.id_out CCSBytes in
                let ci = {ci with id_out = we} in 
                OutCCS(rg,f,ci,w,state)
            | _ -> OutIdle(state)
    | outBuf ->
        let ((rg,f),remBuf) = makeFragment ci.id_out outBuf in
        let state = {state with hs_outgoing = remBuf} in
        match remBuf with
        | [||] ->
            match state.pstate with
            | PSClient(cstate) ->
                match cstate with
                | ServerCCS (_) ->
                    OutFinished(rg,f,state)
                | ClientWritingFinishedResume(cvd,svd) ->
                    let state = {state with pstate = PSClient(ClientIdle(cvd,svd))} in
                    OutComplete(rg,f,state)
                | _ -> OutSome(rg,f,state)
            | PSServer(sstate) ->
                match sstate with
                | ServerWritingFinished(si,ms,cvd,svd) ->
                    let sDB =
                        if equalBytes si.sessionID [||] then
                            state.sDB
                        else
                            SessionDB.insert state.sDB (si.sessionID,Server,state.poptions.client_name) (si,ms)
                    let state = {state with pstate = PSServer(ServerIdle(cvd,svd))   
                                            sDB = sDB} in
                    OutComplete(rg,f,state)
                | ClientCCSResume(_) ->
                    OutFinished(rg,f,state)
                | _ -> OutSome(rg,f,state)
        | _ -> OutSome(rg,f,state)
                
type incoming = (* the fragment is accepted, and... *)
  | InAck of hs_state
  | InVersionAgreed of hs_state * ProtocolVersion
  | InQuery of Cert.cert * hs_state
  | InFinished of hs_state
    // FIXME: StorableSession
  | InComplete of hs_state
  | InError of alertDescription * string * hs_state

type incomingCCS =
  | InCCSAck of ConnectionInfo * StatefulAEAD.state * hs_state
  | InCCSError of alertDescription * string * hs_state




/// ClientKeyExchange

    
let find_client_cert_sign certType algOpt distName pv hint =
    let certAlg =
        match algOpt with
        | Some(alg) -> alg
        | None -> cert_type_list_to_SigHashAlg certType pv
    let keyAlg = sigHashAlg_bySigList certAlg (cert_type_list_to_SigAlg certType) in
    Cert.for_signing certAlg hint keyAlg

let prepare_client_output_full_RSA (ci:ConnectionInfo) state (si:SessionInfo) cert_req log =
    let clientCertBytes =
      match cert_req with
      | Some(certOpt) ->
        makeCertificateBytes_sign certOpt
      | None -> [||]

    let si =
        match cert_req with
        | None -> si
        | Some(certOpt) ->
            match certOpt with
            | None -> si
            | Some(certList,_,_) -> {si with clientID = certList}

    let log = log @| clientCertBytes in

    match makeClientKEX_RSA si state.poptions with
    | Error(x,y) -> Error(x,y)
    | Correct(clientKEXBytes,pms) ->

    let log = log @| clientKEXBytes in

    let ms = PRFs.prfSmoothRSA si pms in
    (* FIXME: here we should shred pms *)
    let certificateVerifyBytes =
        match cert_req with
        | Some(certOpt) ->
            match certOpt with
            | None ->
                (* We sent an empty Certificate message, so no certificate verify message at all *)
                [||]
            | Some(certList,algs,skey) ->
                makeCertificateVerifyBytes si ms algs skey log
        | None ->
            (* No client certificate ==> no certificateVerify message *)
            [||]
    let log = log @| certificateVerifyBytes in

    (* Enqueue current messages in output buffer *)
    let to_send = clientCertBytes @| clientKEXBytes @| certificateVerifyBytes in
    let new_outgoing = state.hs_outgoing @| to_send in
    let state = {state with hs_outgoing = new_outgoing} in
    correct (state,si,ms,log)

let prepare_client_output_full_DHE (ci:ConnectionInfo) state (si:SessionInfo) cert_req g p sy log =
    // TODO: Factor code out with RSA case
    let clientCertBytes =
      match cert_req with
      | Some(certOpt) ->
        makeCertificateBytes_sign certOpt
      | None -> [||]

    let si =
        match cert_req with
        | None -> si
        | Some(certOpt) ->
            match certOpt with
            | None -> si
            | Some(certList,_,_) -> {si with clientID = certList}

    let log = log @| clientCertBytes in

    let (x,cy) = DHE.genKey (g, p) in

    let clientKEXBytes = makeClientKEX_DH_explicit cy in

    let log = log @| clientKEXBytes in

    let pms = DHE.genPMS si (g, p) x sy in
    let ms = PRFs.prfSmoothDHE si pms in
    (* FIXME: here we should shred pms *)
    let certificateVerifyBytes =
        match cert_req with
        | Some(certOpt) ->
            match certOpt with
            | None ->
                (* We sent an empty Certificate message, so no certificate verify message at all *)
                [||]
            | Some(certList,algs,skey) ->
                makeCertificateVerifyBytes si ms algs skey log
        | None ->
            (* No client certificate ==> no certificateVerify message *)
            [||]
    let log = log @| certificateVerifyBytes in

    (* Enqueue current messages in output buffer *)
    let to_send = clientCertBytes @| clientKEXBytes @| certificateVerifyBytes in
    let new_outgoing = state.hs_outgoing @| to_send in
    let state = {state with hs_outgoing = new_outgoing} in
    correct (state,si,ms,log)
 
let on_serverHello_full crand log shello =
    let (sh_server_version,sh_random,sh_session_id,sh_cipher_suite,sh_compression_method,sh_neg_extensions) = shello
    let si = { clientID = []
               serverID = []
               sessionID = sh_session_id
               protocol_version = sh_server_version
               cipher_suite = sh_cipher_suite
               compression = sh_compression_method
               init_crand = crand
               init_srand = sh_random
               } in
    (* If DH_ANON, go into the ServerKeyExchange state, else go to the Certificate state *)
    if isAnonCipherSuite sh_cipher_suite then
        PSClient(ServerKeyExchangeDH_anon(si,log))
    elif isDHCipherSuite sh_cipher_suite then
        PSClient(ServerCertificateDH(si,log))
    elif isDHECipherSuite sh_cipher_suite then
        PSClient(ServerCertificateDHE(si,log))
    elif isRSACipherSuite sh_cipher_suite then
        PSClient(ServerCertificateRSA(si,log))
    else
        unexpectedError "[recv_fragment] Unknown ciphersuite"


let parseMessageState state = 
    match parseMessage state.hs_incoming with
    | None -> None
    | Some(rem,hstype,payload,to_log) -> 
         let state = { state with hs_incoming = rem } in
         Some(state,hstype,payload,to_log)

let rec recv_fragment_client (ci:ConnectionInfo) (state:hs_state) (agreedVersion:ProtocolVersion option) =
    match parseMessageState state with
    | None ->
      match agreedVersion with
      | None      -> InAck(state)
      | Some (pv) -> InVersionAgreed(state,pv)
    | Some (state,hstypeb,payload,to_log) ->
      match parseHt hstypeb with
      | Error(x,y) -> InError(x,y,state)
      | Correct(hstype) ->
      match state.pstate with
      | PSClient(cState) ->
        match hstype with
        | HT_hello_request ->
            match cState with
            | ClientIdle(_,_) -> 
                (* This is a legitimate hello request.
                   Handle it, but according to the spec do not log this message *)
                match state.poptions.honourHelloReq with
                | HRPIgnore -> recv_fragment_client ci state agreedVersion
                | HRPResume -> let (_,state) = rekey ci state state.poptions in InAck(state)       (* Terminating case, we're not idle anymore *)
                | HRPFull   -> let (_,state) = rehandshake ci state state.poptions in InAck(state) (* Terminating case, we're not idle anymore *)
            | _ -> 
                (* RFC 7.4.1.1: ignore this message *)
                recv_fragment_client ci state agreedVersion

        | HT_server_hello ->
            match cState with
            | ServerHello (crand,sid,cvd,svd,log) ->
                match parseServerHello payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct (shello) ->
                  let (sh_server_version,sh_random,sh_session_id,sh_cipher_suite,sh_compression_method,sh_neg_extensions) = shello
                  // Sanity checks on the received message; they are security relevant. 
                  // Check that the server agreed version is between maxVer and minVer.
                  if not (geqPV sh_server_version state.poptions.minVer 
                       && geqPV state.poptions.maxVer sh_server_version) 
                  then InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation",state)
                  else
                  // Check that the negotiated ciphersuite is in the proposed list.
                  // Note: if resuming a session, we still have to check that this ciphersuite is the expected one!
                  if not (List.exists (fun x -> x = sh_cipher_suite) state.poptions.ciphersuites) 
                  then InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation",state)
                  else
                  // Check that the compression method is in the proposed list.
                  if not (List.exists (fun x -> x = sh_compression_method) state.poptions.compressions) 
                  then InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Compression method negotiation",state)
                  else
                  // Handling of safe renegotiation
                  let safe_reneg_result =
                    if state.poptions.safe_renegotiation then
                        let expected = cvd @| svd in
                        inspect_ServerHello_extensions sh_neg_extensions expected
                    else
                        // RFC Sec 7.4.1.4: with no safe renegotiation, we never send extensions; if the server sent any extension
                        // we MUST abort the handshake with unsupported_extension fatal alter (handled by the dispatcher)
                        if not (equalBytes sh_neg_extensions [||])
                        then Error(AD_unsupported_extension, perror __SOURCE_FILE__ __LINE__ "The server gave an unknown extension")
                        else let unitVal = () in correct (unitVal)
                  match safe_reneg_result with
                    | Error (x,y) -> InError (x,y,state)
                    | Correct _ ->
                        // Log the received message.
                        let log = log @| to_log in
                        (* Check whether we asked for resumption *)
                        if equalBytes sid [||] then
                            (* we did not request resumption, do a full handshake *)
                            (* define the sinfo we're going to establish *)
                            let next_pstate = on_serverHello_full crand log shello in
                            let state = {state with pstate = next_pstate} in
                            recv_fragment_client ci state (Some(sh_server_version))
                        else
                            if equalBytes sid sh_session_id then (* use resumption *)
                                (* Search for the session in our DB *)
                                match SessionDB.select state.sDB (sid,Client,state.poptions.server_name) with
                                | None ->
                                    (* This can happen, although we checked for the session before starting the HS.
                                       For example, the session may have expired between us sending client hello, and now. *)
                                    InError(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "A session expried while it was being resumed",state)
                                | Some(storable) ->
                                let (si,ms) = storable in
                                (* Check that protocol version, ciphersuite and compression method are indeed the correct ones *)
                                if si.protocol_version = sh_server_version then
                                    if si.cipher_suite = sh_cipher_suite then
                                        if si.compression = sh_compression_method then
                                            let next_ci = getNextEpochs ci si crand sh_random in
                                            let (writer,reader) = PRFs.keyGen next_ci ms in
                                            let state = {state with pstate = PSClient(ServerCCSResume(next_ci.id_out,writer,
                                                                                                      next_ci.id_in,reader,
                                                                                                      ms,log))} in
                                            recv_fragment_client ci state (Some(sh_server_version))
                                        else InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Compression method negotiation",state)
                                    else InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation",state)
                                else InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation",state)
                            else (* server did not agree on resumption, do a full handshake *)
                                (* define the sinfo we're going to establish *)
                                let next_pstate = on_serverHello_full crand log shello in
                                let state = {state with pstate = next_pstate} in
                                recv_fragment_client ci state (Some(sh_server_version))
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerHello arrived in the wrong state",state)
        
        | HT_certificate ->
            match cState with
            // FIXME: Most of the code in the branches is duplicated
            | ServerCertificateRSA (si,log) ->
                match parseCertificate payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(certs) ->
                    let allowedAlgs = default_sigHashAlg si.protocol_version si.cipher_suite in // In TLS 1.2, this is the same as we sent in our extension
                    if Cert.is_chain_for_key_encryption certs && Cert.validate_cert_chain allowedAlgs certs then
                        (* We have validated server identity *)
                        (* Log the received packet *)
                        let log = log @| to_log in        
                        (* update the sinfo we're establishing *)
                        let si = {si with serverID = certs} in
                        let state = {state with pstate = PSClient(CertificateRequestRSA(si,log))} in
                        recv_fragment_client ci state agreedVersion
                    else
                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate could not be verified",state)
            | ServerCertificateDHE (si,log) ->
                match parseCertificate payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(certs) ->
                    let allowedAlgs = default_sigHashAlg si.protocol_version si.cipher_suite in // In TLS 1.2, this is the same as we sent in our extension
                    if Cert.is_chain_for_key_encryption certs && Cert.validate_cert_chain allowedAlgs certs then
                        (* We have validated server identity *)
                        (* Log the received packet *)
                        let log = log @| to_log in        
                        (* update the sinfo we're establishing *)
                        let si = {si with serverID = certs} in
                        let state = {state with pstate = PSClient(ServerKeyExchangeDHE(si,log))} in
                        recv_fragment_client ci state agreedVersion
                    else
                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate could not be verified",state)
            | ServerCertificateDH (si,log) -> InError(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Unimplemented",state) // TODO
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Certificate arrived in the wrong state",state)


        | HT_server_key_exchange ->
            match cState with
            | ServerKeyExchangeDHE(si,log) ->
                match checkServerKeyExchange_DHE si.init_crand si.init_srand si.serverID si.protocol_version si.cipher_suite payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(p,g,y) ->
                    let log = log @| to_log in
                    let state = {state with pstate = PSClient(CertificateRequestDHE(si,g,p,y,log))} in
                    recv_fragment_client ci state agreedVersion
            | ServerKeyExchangeDH_anon(si,log) ->
                match parseServerKeyExchange_DH_anon payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(p,g,y) ->
                    let log = log @| to_log in
                    let state = {state with pstate = PSClient(ServerHelloDoneDH_anon(si,g,p,y,log))} in
                    recv_fragment_client ci state agreedVersion
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerKeyExchange arrived in the wrong state",state)

        | HT_certificate_request ->
            match cState with
            | CertificateRequestRSA(si,log) ->
                (* Log the received packet *)
                let log = log @| to_log in

                (* Note: in next statement, use si, because the handshake runs according to the session we want to
                   establish, not the current one *)
                match parseCertificateRequest si.protocol_version payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(certType,alg,distNames) ->
                let client_cert = find_client_cert_sign certType alg distNames si.protocol_version state.poptions.client_name in
                let state = {state with pstate = PSClient(ServerHelloDoneRSA(si,client_cert,log))} in
                recv_fragment_client ci state agreedVersion
            | CertificateRequestDHE(si,g,p,y,log) ->
                // Duplicated code
                (* Log the received packet *)
                let log = log @| to_log in

                (* Note: in next statement, use si, because the handshake runs according to the session we want to
                   establish, not the current one *)
                match parseCertificateRequest si.protocol_version payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(certType,alg,distNames) ->
                let client_cert = find_client_cert_sign certType alg distNames si.protocol_version state.poptions.client_name in
                let state = {state with pstate = PSClient(ServerHelloDoneDHE(si,client_cert,g,p,y,log))} in
                recv_fragment_client ci state agreedVersion
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CertificateRequest arrived in the wrong state",state)

        | HT_server_hello_done ->
            match cState with
            | CertificateRequestRSA(si,log) ->
                if equalBytes payload [||] then     
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_RSA ci state si None log with
                    | Error (x,y) -> InError (x,y, state)
                    | Correct (state,si,ms,log) ->
                        let state = {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                        recv_fragment_client ci state agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | ServerHelloDoneRSA(si,skey,log) ->
                if equalBytes payload [||] then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_RSA ci state si (Some(skey)) log with
                    | Error (x,y) -> InError (x,y, state)
                    | Correct (state,si,ms,log) ->
                        let state = {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                        recv_fragment_client ci state agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | CertificateRequestDHE(si,g,p,y,log) | ServerHelloDoneDH_anon(si,g,p,y,log) ->
                if equalBytes payload [||] then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_DHE ci state si None g p y log with
                    | Error (x,y) -> InError (x,y, state)
                    | Correct (state,si,ms,log) ->
                        let state = {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                        recv_fragment_client ci state agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | ServerHelloDoneDHE(si,skey,g,p,y,log) ->
                if equalBytes payload [||] then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_DHE ci state si (Some(skey)) g p y log with
                    | Error (x,y) -> InError (x,y, state)
                    | Correct (state,si,ms,log) ->
                        let state = {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                        recv_fragment_client ci state agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerHelloDone arrived in the wrong state",state)


        | HT_finished ->
            match cState with
            | ServerFinished(si,ms,cvd,log) ->
                if checkVerifyData si Server ms log payload then
                    let sDB = 
                        if equalBytes si.sessionID [||] then state.sDB
                        else SessionDB.insert state.sDB (si.sessionID,Client,state.poptions.server_name) (si,ms)
                    let state = {state with pstate = PSClient(ClientIdle(cvd,payload)); sDB = sDB} in
                    InComplete(state)
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | ServerFinishedResume(e,w,ms,log) ->
                if checkVerifyData (epochSI ci.id_in) Server ms log payload then
                    let log = log @| to_log in
                    let state = {state with pstate = PSClient(ClientWritingCCSResume(e,w,ms,payload,log))} in
                    InFinished(state)
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Finished arrived in the wrong state",state)
        | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Unrecognized message",state)
      
      (* Should never happen *)
      | PSServer(_) -> unexpectedError "[recv_fragment_client] should only be invoked when in client role."

let prepare_server_hello si srand config cvd svd =
    // FIXME: Super-redundant. At some point we should clean all this "preparing" functions...
    let ext = 
      if config.safe_renegotiation then
        let data = cvd @| svd in
        let ren_extB = renegotiationInfoExtensionBytes data in
        extensionListBytes [ren_extB]
      else
        [||]
    makeServerHelloBytes si srand ext

let prepare_server_output_full_RSA (ci:ConnectionInfo) state si cv calgs cvd svd log =
    let serverHelloB = prepare_server_hello si si.init_srand state.poptions cvd svd in
    match Cert.for_key_encryption calgs state.poptions.server_name with
    | None -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Could not find in the store a certificate for the negotiated ciphersuite")
    | Some(c,sk) ->
        (* update server identity in the sinfo *)
        let si = {si with serverID = c} in
        let certificateB = makeCertificateBytes c in
        (* No ServerKEyExchange in RSA ciphersuites *)
        let certificateRequestB =
            if state.poptions.request_client_certificate then
                makeCertificateRequest true si.cipher_suite si.protocol_version // true: Ask for sign-capable certificates
            else
                [||]
        let output = serverHelloB @| certificateB @| certificateRequestB @| serverHelloDoneBytes in
        (* Log the output and put it into the output buffer *)
        let log = log @| output in
        let state = {state with hs_outgoing = output} in
        (* Compute the next state of the server *)
        let state =
            if state.poptions.request_client_certificate then
                {state with pstate = PSServer(ClientCertificateRSA(si,cv,sk,log))}
            else
                {state with pstate = PSServer(ClientKeyExchangeRSA(si,cv,sk,log))}
        correct (state,si.protocol_version)

let prepare_server_output_full_DH ci state si log =
    Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Unimplemented") // TODO

let prepare_server_output_full_DHE (ci:ConnectionInfo) state si certAlgs cvd svd log =
    let serverHelloB = prepare_server_hello si si.init_srand state.poptions cvd svd in
    let keyAlgs = sigHashAlg_bySigList certAlgs [sigAlg_of_ciphersuite si.cipher_suite] in
    if keyAlgs.IsEmpty then
        Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "The client provided inconsistent signature algorithms and ciphersuites")
    else
    match Cert.for_signing certAlgs state.poptions.server_name keyAlgs with
    | None -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Could not find in the store a certificate for the negotiated ciphersuite")
    | Some(c,alg,sk) ->
        (* update server identity in the sinfo *)
        let si = {si with serverID = c} in
        let certificateB = makeCertificateBytes c in
        (* ServerKEyExchange *)
        let (g,p) = DHE.defaultParams () in
        let (x,y) = DHE.genKey (g, p) in
        let serverKEXB = serverKeyExchange_DHE si.init_crand si.init_srand p g y alg sk si.protocol_version in
        (* CertificateRequest *)
        let certificateRequestB =
            if state.poptions.request_client_certificate then
                makeCertificateRequest true si.cipher_suite si.protocol_version // true: Ask for sign-capable certificates
            else
                [||]
        let output = serverHelloB @| certificateB @| serverKEXB @| certificateRequestB @| serverHelloDoneBytes in
        (* Log the output and put it into the output buffer *)
        let log = log @| output in
        let state = {state with hs_outgoing = output} in
        (* Compute the next state of the server *)
        let state =
            if state.poptions.request_client_certificate then
                {state with pstate = PSServer(ClientCertificateDHE(si,g,p,x,log))}
            else
                {state with pstate = PSServer(ClientKeyExchangeDHE(si,g,p,x,log))}
        correct (state,si.protocol_version)

let prepare_server_output_full_DH_anon (ci:ConnectionInfo) state si cvd svd log =
    let serverHelloB = prepare_server_hello si si.init_srand state.poptions cvd svd in
    
    (* ServerKEyExchange *)
    let (g,p) = DHE.defaultParams () in
    let (x,y) = DHE.genKey (g, p) in
    let serverKEXB = serverKeyExchange_DH_anon p g y in
 
    let output = serverHelloB @|serverKEXB @| serverHelloDoneBytes in
    (* Log the output and put it into the output buffer *)
    let log = log @| output in
    let state = {state with hs_outgoing = output} in
    (* Compute the next state of the server *)
    let state = {state with pstate = PSServer(ClientKeyExchangeDH_anon(si,g,p,x,log))}
    correct (state,si.protocol_version)

let prepare_server_output_full ci state si cv calgs cvd svd log =
    if isAnonCipherSuite si.cipher_suite then
        prepare_server_output_full_DH_anon ci state si cvd svd log
    elif isDHCipherSuite si.cipher_suite then
        prepare_server_output_full_DH ci state si log
    elif isDHECipherSuite si.cipher_suite then
        prepare_server_output_full_DHE ci state si calgs cvd svd log
    elif isRSACipherSuite si.cipher_suite then
        prepare_server_output_full_RSA ci state si cv calgs cvd svd log
    else
        unexpectedError "[prepare_server_hello_full] unexpected ciphersuite"

// The server "negotiates" its first proposal included in the client's proposal
let negotiate cList sList =
    List.tryFind (fun s -> List.exists (fun c -> c = s) cList) sList

let prepare_server_output_resumption ci state crand si ms cvd svd log =
    let srand = makeRandom () in
    let sHelloB = prepare_server_hello si srand state.poptions cvd svd in

    let log = log @| sHelloB
    let state = {state with hs_outgoing = sHelloB} in
    let next_ci = getNextEpochs ci si crand srand in
    let (writer,reader) = PRFs.keyGen next_ci ms in
    let state = {state with pstate = PSServer(ServerWritingCCSResume(next_ci.id_out,writer,
                                                                     next_ci.id_in,reader,
                                                                     ms,log))} in
    state

let startServerFull (ci:ConnectionInfo) state cHello cvd svd log =  
    let (ch_client_version,ch_random,ch_session_id,ch_cipher_suites,ch_compression_methods,ch_extensions) = cHello
    // Negotiate the protocol parameters
    let version = minPV ch_client_version state.poptions.maxVer in
    if not (geqPV version state.poptions.minVer) then
        Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation")
    else
        match negotiate ch_cipher_suites state.poptions.ciphersuites with
        | Some(cs) ->
            match negotiate ch_compression_methods state.poptions.compressions with
            | Some(cm) ->
                // Get the client supported SignatureAndHash algorithms. In TLS 1.2, this should be extracted from a client extension
                let clientAlgs = default_sigHashAlg version cs in
                let sid = mkRandom 32 in
                let srand = makeRandom () in
                (* Fill in the session info we're establishing *)
                let si = { clientID         = []
                           serverID         = []
                           sessionID        = sid
                           protocol_version = version
                           cipher_suite     = cs
                           compression      = cm
                           init_crand       = ch_random
                           init_srand       = srand }
                prepare_server_output_full ci state si ch_client_version clientAlgs cvd svd log
            | None -> Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Compression method negotiation")
        | None ->     Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation")


(*CF: recursive only to enable processing of multiple messages; 
      can we loop externally, and avoid passing agreedVersion? 
      we retry iff the result is not InAck or InError. 
      What can we do after InError btw? *)

(*CF: we should rediscuss this monster pattern matching, factoring out some of it. *)

let rec recv_fragment_server (ci:ConnectionInfo) (state:hs_state) (agreedVersion:ProtocolVersion option) =
    match parseMessageState state with
    | None ->
      match agreedVersion with
      | None      -> InAck(state)
      | Some (pv) -> InVersionAgreed(state,pv) (*CF: why? AP: Needed in first handshake, to check the protocol version at the record level. (See sec E.1 RFC5246) *)
    | Some (state,hstypeb,payload,to_log) ->
      match parseHt hstypeb with
      | Error(x,y) -> InError(x,y,state)
      | Correct(hstype) ->
      match state.pstate with
      | PSServer(sState) ->
        match hstype with
        | HT_client_hello ->
            match sState with
            | ClientHello(cvd,svd) | ServerIdle(cvd,svd) ->
                match parseClientHello payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct (cHello) ->
                let (ch_client_version,ch_random,ch_session_id,ch_cipher_suites,ch_compression_methods,ch_extensions) = cHello
                (* Log the received message *)
                let log = to_log in
                (* handle extensions: for now only renegotiation_info *) (*CF? AP: we need to add support for the Signature Algorithm extension at least.*)
                match parseExtensionList ch_extensions with
                | Error(x,y) -> InError(x,y,state)
                | Correct(extList) ->
                let extRes =
                    if state.poptions.safe_renegotiation then
                        if checkClientRenegotiationInfoExtension extList ch_cipher_suites cvd then
                            correct(state)
                        else
                            (* We don't accept an insecure client *)
                            Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Safe renegotiation not supported by the peer")
                    else
                        (* We can ignore the extension, if any *)
                        correct(state)
                match extRes with
                | Error(x,y) -> InError(x,y,state)
                | Correct(state) ->
                    if equalBytes ch_session_id [||] 
                    then 
                        (* Client asked for a full handshake *)
                        match startServerFull ci state cHello cvd svd log with 
                        | Error(x,y) -> InError(x,y,state)
                        | Correct(state,pv) -> recv_fragment_server ci state (Some(pv))
                    else
                        (* Client asked for resumption, let's see if we can satisfy the request *)
                        match SessionDB.select state.sDB (ch_session_id,Server,state.poptions.client_name) with
                        | Some (storedSinfo,storedMS) 
                            (* We have the requested session stored *)
                            (* Check that the client proposals match those of our stored session *)
                            when ch_client_version >= storedSinfo.protocol_version
                              && List.exists (fun cs -> cs = storedSinfo.cipher_suite) ch_cipher_suites
                              && List.exists (fun cm -> cm = storedSinfo.compression) ch_compression_methods ->
                              
                                (* Proceed with resumption *)
                                let state = prepare_server_output_resumption ci state ch_random storedSinfo storedMS cvd svd log 
                                recv_fragment_server ci state (Some(storedSinfo.protocol_version))

                        | _ ->  (* Do a full handshake *)
                                match startServerFull ci state cHello cvd svd log with
                                | Correct(state,pv) -> recv_fragment_server ci state (Some(pv))
                                | Error(x,y) -> InError(x,y,state)
                                   
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ClientHello arrived in the wrong state",state)

        | HT_certificate ->
            match sState with
            | ClientCertificateRSA (si,cv,sk,log) ->
                match parseCertificate payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(certs) ->
                    if Cert.is_chain_for_signing certs && Cert.validate_cert_chain (default_sigHashAlg si.protocol_version si.cipher_suite) certs then // FIXME: we still have to ask the user
                        (* We have validated client identity *)
                        (* Log the received packet *)
                        let log = log @| to_log in           
                        (* update the sinfo we're establishing *)
                        let si = {si with clientID = certs}
                        (* move to the next state *)
                        let state = {state with pstate = PSServer(ClientKeyExchangeRSA(si,cv,sk,log))} in
                        recv_fragment_server ci state agreedVersion
                    else
                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate could not be verified",state)
            | ClientCertificateDHE (si,g,p,x,log) ->
                // Duplicated code from above.
                match parseCertificate payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(certs) ->
                    if Cert.is_chain_for_signing certs && Cert.validate_cert_chain (default_sigHashAlg si.protocol_version si.cipher_suite) certs then // FIXME: we still have to ask the user
                        (* We have validated client identity *)
                        (* Log the received packet *)
                        let log = log @| to_log in           
                        (* update the sinfo we're establishing *)
                        let si = {si with clientID = certs}
                        (* move to the next state *)
                        let state = {state with pstate = PSServer(ClientKeyExchangeDHE(si,g,p,x,log))} in
                        recv_fragment_server ci state agreedVersion
                    else
                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate could not be verified",state)
            | ClientCertificateDH  (si,log) -> (* TODO *) InError(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Unimplemented",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Certificate arrived in the wrong state",state)

        | HT_client_key_exchange ->
            match sState with
            | ClientKeyExchangeRSA(si,cv,sk,log) ->
                match parseClientKEX_RSA si sk cv state.poptions payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(pms) ->
                    let log = log @| to_log in
                    let ms = PRFs.prfSmoothRSA si pms in
                    (* TODO: we should shred the pms *)
                    (* move to new state *)
                    if state.poptions.request_client_certificate then
                        let state = {state with pstate = PSServer(CertificateVerify(si,ms,log))} in
                        recv_fragment_server ci state agreedVersion
                    else
                        let state = {state with pstate = PSServer(ClientCCS(si,ms,log))} in
                        recv_fragment_server ci state agreedVersion
            | ClientKeyExchangeDHE(si,g,p,x,log) ->
                match parseClientKEX_DH_explicit payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(y) ->
                    let log = log @| to_log in
                    let pms = DHE.genPMS si (g, p) x y in
                    let ms = PRFs.prfSmoothDHE si pms in
                    (* TODO: we should shred the pms *)
                    (* we rely on scopes & type safety to get forward secrecy*) (* AP:? *)
                    (* move to new state *)
                    if state.poptions.request_client_certificate then
                        let state = {state with pstate = PSServer(CertificateVerify(si,ms,log))} in
                        recv_fragment_server ci state agreedVersion
                    else
                        let state = {state with pstate = PSServer(ClientCCS(si,ms,log))} in
                        recv_fragment_server ci state agreedVersion
            | ClientKeyExchangeDH_anon(si,g,p,x,log) ->
                match parseClientKEX_DH_explicit payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(y) ->
                    let log = log @| to_log in
                    let pms = DHE.genPMS si (g, p) x y in
                    let ms = PRFs.prfSmoothDHE si pms in
                    (* TODO: here we should shred pms *)
                    (* move to new state *)
                    let state = {state with pstate = PSServer(ClientCCS(si,ms,log))} in
                    recv_fragment_server ci state agreedVersion
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ClientKeyExchange arrived in the wrong state",state)

        | HT_certificate_verify ->
            match sState with
            | CertificateVerify(si,ms,log) ->
                let allowedAlgs = default_sigHashAlg si.protocol_version si.cipher_suite in // In TLS 1.2, these are the same as we sent in CertificateRequest
                if certificateVerifyCheck si ms allowedAlgs si.clientID log payload then// payload then
                    let log = log @| to_log in  
                    let state = {state with pstate = PSServer(ClientCCS(si,ms,log))} in
                    recv_fragment_server ci state agreedVersion
                else  
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Certificate verify check failed",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CertificateVerify arrived in the wrong state",state)

        | HT_finished ->
            match sState with
            | ClientFinished(si,ms,e,w,log) ->
                if checkVerifyData si Client ms log payload then
                    let log = log @| to_log in
                    let state = {state with pstate = PSServer(ServerWritingCCS(si,ms,e,w,payload,log))} in
                    InFinished(state)
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | ClientFinishedResume(si,ms,svd,log) ->
                if checkVerifyData si Client ms log payload then
                    let state = {state with pstate = PSServer(ServerIdle(payload,svd))} in
                    InComplete(state)                       
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Finished arrived in the wrong state",state)

        | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Unknown message received",state)
      (* Should never happen *)
      | PSClient(_) -> unexpectedError "[recv_fragment_server] should only be invoked when in server role."

let enqueue_fragment (ci:ConnectionInfo) state fragment =
    let new_inc = state.hs_incoming @| fragment in
    {state with hs_incoming = new_inc}

let recv_fragment ci (state:hs_state) (r:DataStream.range) (fragment:Fragment.fragment) =
    // FIXME: cleanup when Hs is ported to streams and deltas
    let b = Fragment.fragmentRepr ci.id_in r fragment in 
    if length b = 0 then
        // Empty HS fragment are not allowed
        InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "Empty handshake fragment received",state)
    else
        let state = enqueue_fragment ci state b in
        match state.pstate with
        | PSClient (_) -> recv_fragment_client ci state None
        | PSServer (_) -> recv_fragment_server ci state None

let recv_ccs (ci:ConnectionInfo) (state: hs_state) (r:DataStream.range) (fragment:Fragment.fragment): incomingCCS =
    // FIXME: cleanup when Hs is ported to streams and deltas
    let b = Fragment.fragmentRepr ci.id_in r fragment in 
    if equalBytes b CCSBytes then  
        match state.pstate with
        | PSClient (cstate) -> // Check that we are in the right state (CCCS) 
            match cstate with
            | ServerCCS(si,ms,e,r,cvd,log) ->
                let state = {state with pstate = PSClient(ServerFinished(si,ms,cvd,log))} in
                let ci = {ci with id_in = e} in
                InCCSAck(ci,r,state)
            | ServerCCSResume(ew,w,er,r,ms,log) ->
                let state = {state with pstate = PSClient(ServerFinishedResume(ew,w,ms,log))} in
                let ci = {ci with id_in = er} in
                InCCSAck(ci,r,state)
            | _ -> InCCSError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CCS arrived in the wrong state",state)
        | PSServer (sState) ->
            match sState with
            | ClientCCS(si,ms,log) ->
                let next_ci = getNextEpochs ci si si.init_crand si.init_srand in
                let (writer,reader) = PRFs.keyGen next_ci ms in
                let ci = {ci with id_in = next_ci.id_in} in
                let state = {state with pstate = PSServer(ClientFinished(si,ms,next_ci.id_out,writer,log))} in
                InCCSAck(ci,reader,state)
            | ClientCCSResume(e,r,svd,ms,log) ->
                let state = {state with pstate = PSServer(ClientFinishedResume(epochSI e,ms,svd,log))} in
                let ci = {ci with id_in = e} in
                InCCSAck(ci,r,state)
            | _ -> InCCSError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CCS arrived in the wrong state",state)
    else           InCCSError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)

let getMinVersion (ci:ConnectionInfo) state = state.poptions.minVer

let authorize (ci:ConnectionInfo) (s:hs_state) (q:Cert.cert) = s // TODO

(* function used by an ideal handshake implementation to decide whether to idealize keys
let safe ki = 
    match (CS(ki), Honest(LTKey(ki, Server)), Honest(LTKey(ki,Client))) with
    | (CipherSuite (RSA, MtE (AES_256_CBC, SHA256)), true, _) -> pmsGenerated ki            
    | (CipherSuite (DHE_DSS, MtE (AES_256_CBC, SHA)), _, _) -> 
        if (TcGenerated ki) && (TsGenerated ki) then 
            true 
        else 
            false
    | _ -> false

 *)
