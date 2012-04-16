module CipherSuites

open Bytes
open Algorithms
open Error

// By now, we only support one SCSV, but there exist others.
type SCSVsuite =
    | TLS_EMPTY_RENEGOTIATION_INFO_SCSV

type cipherSuite =
    | NullCipherSuite
    | CipherSuite of kexAlg * authencAlg
    | OnlyMACCipherSuite of kexAlg * hashAlg
    | SCSV of SCSVsuite

type cipherSuites = cipherSuite list

type Compression =
    | NullCompression

let compressionBytes (comp:Compression) = 
    match comp with
    | NullCompression -> [|0uy|]

let parseCompression b =
    match b with
    | [|0uy|] -> correct(NullCompression)
    | _       -> Error(Parsing,WrongInputParameters)

// Ignore compression methods we don't understand. This is a departure
// from usual parsing, where we fail on unknown values, but that's how TLS
// handle compression method lists.
let rec parseCompressions b =
    let l = length b
    if l > 0 
    then
        let (cmB,b) = split b 1 in
        match parseCompression cmB with
        | Error(x,y) -> // skip this one
            parseCompressions b
        | Correct(cm) -> cm :: parseCompressions b
    else []

type ProtocolVersion =
    | SSL_3p0
    | TLS_1p0
    | TLS_1p1
    | TLS_1p2

let versionBytes pv =
    match pv with
    | SSL_3p0 -> [| 3uy; 0uy |]
    | TLS_1p0 -> [| 3uy; 1uy |]
    | TLS_1p1 -> [| 3uy; 2uy |]
    | TLS_1p2 -> [| 3uy; 3uy |]

let parseVersion (v:bytes) =
    match v with
    | [| 3uy; 0uy |] -> correct(SSL_3p0)
    | [| 3uy; 1uy |] -> correct(TLS_1p0)
    | [| 3uy; 2uy |] -> correct(TLS_1p1)
    | [| 3uy; 3uy |] -> correct(TLS_1p2)
    | _ -> Error(Parsing,WrongInputParameters)

let minPV (a:ProtocolVersion) (b:ProtocolVersion) =
  match (a,b) with
  | SSL_3p0, _ | _, SSL_3p0 -> SSL_3p0
  | TLS_1p0, _ | _, TLS_1p0 -> TLS_1p0
  | TLS_1p1, _ | _, TLS_1p1 -> TLS_1p1
  | _, _                    -> TLS_1p2
  // in F#, could use if a < b then a else b

let geqPV (a:ProtocolVersion) (b:ProtocolVersion) =
    match (a,b) with
    | _,SSL_3p0 -> true
    | SSL_3p0,_ -> false
    | _,TLS_1p0 -> true
    | TLS_1p0,_ -> false
    | _,TLS_1p1 -> true
    | TLS_1p1,_ -> false
    | _,_       -> true

let nullCipherSuite = NullCipherSuite

let isNullCipherSuite cs =
    cs = NullCipherSuite

let isOnlyMACCipherSuite cs =
    match cs with
    | OnlyMACCipherSuite (_,_) -> true
    | _ -> false

let cipherSuiteBytes cs = 
    match cs with
    | NullCipherSuite                                     -> [| 0x00uy; 0x00uy |]

    | OnlyMACCipherSuite (RSA, MD5)                       -> [| 0x00uy; 0x01uy |]
    | OnlyMACCipherSuite (RSA, SHA)                       -> [| 0x00uy; 0x02uy |]
    | OnlyMACCipherSuite (RSA, SHA256)                    -> [| 0x00uy; 0x3Buy |]
    | CipherSuite (RSA, EncMAC (RC4_128, MD5))            -> [| 0x00uy; 0x04uy |]
    | CipherSuite (RSA, EncMAC (RC4_128, SHA))            -> [| 0x00uy; 0x05uy |]
    | CipherSuite (RSA, EncMAC (TDES_EDE_CBC, SHA))       -> [| 0x00uy; 0x0Auy |]
    | CipherSuite (RSA, EncMAC (AES_128_CBC, SHA))        -> [| 0x00uy; 0x2Fuy |]
    | CipherSuite (RSA, EncMAC (AES_256_CBC, SHA))        -> [| 0x00uy; 0x35uy |]
    | CipherSuite (RSA, EncMAC (AES_128_CBC, SHA256))     -> [| 0x00uy; 0x3Cuy |]
    | CipherSuite (RSA, EncMAC (AES_256_CBC, SHA256))     -> [| 0x00uy; 0x3Duy |]

    | CipherSuite (DH_DSS,  EncMAC (TDES_EDE_CBC, SHA))   -> [| 0x00uy; 0x0Duy |]
    | CipherSuite (DH_RSA,  EncMAC (TDES_EDE_CBC, SHA))   -> [| 0x00uy; 0x10uy |]
    | CipherSuite (DHE_DSS, EncMAC (TDES_EDE_CBC, SHA))   -> [| 0x00uy; 0x13uy |]
    | CipherSuite (DHE_RSA, EncMAC (TDES_EDE_CBC, SHA))   -> [| 0x00uy; 0x16uy |]
    | CipherSuite (DH_DSS,  EncMAC (AES_128_CBC, SHA))    -> [| 0x00uy; 0x30uy |]
    | CipherSuite (DH_RSA,  EncMAC (AES_128_CBC, SHA))    -> [| 0x00uy; 0x31uy |]
    | CipherSuite (DHE_DSS, EncMAC (AES_128_CBC, SHA))    -> [| 0x00uy; 0x32uy |]
    | CipherSuite (DHE_RSA, EncMAC (AES_128_CBC, SHA))    -> [| 0x00uy; 0x33uy |]
    | CipherSuite (DH_DSS,  EncMAC (AES_256_CBC, SHA))    -> [| 0x00uy; 0x36uy |]
    | CipherSuite (DH_RSA,  EncMAC (AES_256_CBC, SHA))    -> [| 0x00uy; 0x37uy |]
    | CipherSuite (DHE_DSS, EncMAC (AES_256_CBC, SHA))    -> [| 0x00uy; 0x38uy |]
    | CipherSuite (DHE_RSA, EncMAC (AES_256_CBC, SHA))    -> [| 0x00uy; 0x39uy |]
    | CipherSuite (DH_DSS,  EncMAC (AES_128_CBC, SHA256)) -> [| 0x00uy; 0x3Euy |]
    | CipherSuite (DH_RSA,  EncMAC (AES_128_CBC, SHA256)) -> [| 0x00uy; 0x3Fuy |]
    | CipherSuite (DHE_DSS, EncMAC (AES_128_CBC, SHA256)) -> [| 0x00uy; 0x40uy |]
    | CipherSuite (DHE_RSA, EncMAC (AES_128_CBC, SHA256)) -> [| 0x00uy; 0x67uy |]
    | CipherSuite (DH_DSS,  EncMAC (AES_256_CBC, SHA256)) -> [| 0x00uy; 0x68uy |]
    | CipherSuite (DH_RSA,  EncMAC (AES_256_CBC, SHA256)) -> [| 0x00uy; 0x69uy |]
    | CipherSuite (DHE_DSS, EncMAC (AES_256_CBC, SHA256)) -> [| 0x00uy; 0x6Auy |]
    | CipherSuite (DHE_RSA, EncMAC (AES_256_CBC, SHA256)) -> [| 0x00uy; 0x6Buy |]

    | CipherSuite (DH_anon, EncMAC (RC4_128, MD5))        -> [| 0x00uy; 0x18uy |]
    | CipherSuite (DH_anon, EncMAC (TDES_EDE_CBC, SHA))   -> [| 0x00uy; 0x1Buy |]
    | CipherSuite (DH_anon, EncMAC (AES_128_CBC, SHA))    -> [| 0x00uy; 0x34uy |]
    | CipherSuite (DH_anon, EncMAC (AES_256_CBC, SHA))    -> [| 0x00uy; 0x3Auy |]
    | CipherSuite (DH_anon, EncMAC (AES_128_CBC, SHA256)) -> [| 0x00uy; 0x6Cuy |]
    | CipherSuite (DH_anon, EncMAC (AES_256_CBC, SHA256)) -> [| 0x00uy; 0x6Duy |]

    | SCSV (TLS_EMPTY_RENEGOTIATION_INFO_SCSV)            -> [| 0x00uy; 0xFFuy |]

(* KB: Must define known cipher suites as a predicate before typechecking the following: *)
    | _ -> unexpectedError "[bytearray_of_ciphersuite] invoked on an unknown ciphersuite"

let cipherSuite_of_bytes b = 
    match b with
    | [| 0x00uy; 0x00uy |] -> correct(NullCipherSuite)
   
    | [| 0x00uy; 0x01uy |] -> correct(OnlyMACCipherSuite (RSA, MD5))
    | [| 0x00uy; 0x02uy |] -> correct(OnlyMACCipherSuite (RSA, SHA))
    | [| 0x00uy; 0x3Buy |] -> correct(OnlyMACCipherSuite (RSA, SHA256))

    | [| 0x00uy; 0x04uy |] -> correct(CipherSuite (    RSA, EncMAC (     RC4_128, MD5)))
    | [| 0x00uy; 0x05uy |] -> correct(CipherSuite (    RSA, EncMAC (     RC4_128, SHA)))
    | [| 0x00uy; 0x0Auy |] -> correct(CipherSuite (    RSA, EncMAC (TDES_EDE_CBC, SHA)))
    | [| 0x00uy; 0x2Fuy |] -> correct(CipherSuite (    RSA, EncMAC ( AES_128_CBC, SHA)))
    | [| 0x00uy; 0x35uy |] -> correct(CipherSuite (    RSA, EncMAC ( AES_256_CBC, SHA)))
    | [| 0x00uy; 0x3Cuy |] -> correct(CipherSuite (    RSA, EncMAC ( AES_128_CBC, SHA256)))
    | [| 0x00uy; 0x3Duy |] -> correct(CipherSuite (    RSA, EncMAC ( AES_256_CBC, SHA256)))

    | [| 0x00uy; 0x0Duy |] -> correct(CipherSuite ( DH_DSS, EncMAC (TDES_EDE_CBC, SHA)))
    | [| 0x00uy; 0x10uy |] -> correct(CipherSuite ( DH_RSA, EncMAC (TDES_EDE_CBC, SHA)))
    | [| 0x00uy; 0x13uy |] -> correct(CipherSuite (DHE_DSS, EncMAC (TDES_EDE_CBC, SHA)))
    | [| 0x00uy; 0x16uy |] -> correct(CipherSuite (DHE_RSA, EncMAC (TDES_EDE_CBC, SHA)))
    | [| 0x00uy; 0x30uy |] -> correct(CipherSuite ( DH_DSS, EncMAC ( AES_128_CBC, SHA)))
    | [| 0x00uy; 0x31uy |] -> correct(CipherSuite ( DH_RSA, EncMAC ( AES_128_CBC, SHA)))
    | [| 0x00uy; 0x32uy |] -> correct(CipherSuite (DHE_DSS, EncMAC ( AES_128_CBC, SHA)))
    | [| 0x00uy; 0x33uy |] -> correct(CipherSuite (DHE_RSA, EncMAC ( AES_128_CBC, SHA)))
    | [| 0x00uy; 0x36uy |] -> correct(CipherSuite ( DH_DSS, EncMAC ( AES_256_CBC, SHA)))
    | [| 0x00uy; 0x37uy |] -> correct(CipherSuite ( DH_RSA, EncMAC ( AES_256_CBC, SHA)))
    | [| 0x00uy; 0x38uy |] -> correct(CipherSuite (DHE_DSS, EncMAC ( AES_256_CBC, SHA)))
    | [| 0x00uy; 0x39uy |] -> correct(CipherSuite (DHE_RSA, EncMAC ( AES_256_CBC, SHA)))
    | [| 0x00uy; 0x3Euy |] -> correct(CipherSuite ( DH_DSS, EncMAC ( AES_128_CBC, SHA256)))
    | [| 0x00uy; 0x3Fuy |] -> correct(CipherSuite ( DH_RSA, EncMAC ( AES_128_CBC, SHA256)))
    | [| 0x00uy; 0x40uy |] -> correct(CipherSuite (DHE_DSS, EncMAC ( AES_128_CBC, SHA256)))
    | [| 0x00uy; 0x67uy |] -> correct(CipherSuite (DHE_RSA, EncMAC ( AES_128_CBC, SHA256)))
    | [| 0x00uy; 0x68uy |] -> correct(CipherSuite ( DH_DSS, EncMAC ( AES_256_CBC, SHA256)))
    | [| 0x00uy; 0x69uy |] -> correct(CipherSuite ( DH_RSA, EncMAC ( AES_256_CBC, SHA256)))
    | [| 0x00uy; 0x6Auy |] -> correct(CipherSuite (DHE_DSS, EncMAC ( AES_256_CBC, SHA256)))
    | [| 0x00uy; 0x6Buy |] -> correct(CipherSuite (DHE_RSA, EncMAC ( AES_256_CBC, SHA256)))

    | [| 0x00uy; 0x18uy |] -> correct(CipherSuite (DH_anon, EncMAC (     RC4_128, MD5)))
    | [| 0x00uy; 0x1Buy |] -> correct(CipherSuite (DH_anon, EncMAC (TDES_EDE_CBC, SHA)))
    | [| 0x00uy; 0x34uy |] -> correct(CipherSuite (DH_anon, EncMAC ( AES_128_CBC, SHA)))
    | [| 0x00uy; 0x3Auy |] -> correct(CipherSuite (DH_anon, EncMAC ( AES_256_CBC, SHA)))
    | [| 0x00uy; 0x6Cuy |] -> correct(CipherSuite (DH_anon, EncMAC ( AES_128_CBC, SHA256)))
    | [| 0x00uy; 0x6Duy |] -> correct(CipherSuite (DH_anon, EncMAC ( AES_256_CBC, SHA256)))

    | [| 0x00uy; 0xFFuy |] -> correct(SCSV (TLS_EMPTY_RENEGOTIATION_INFO_SCSV))

    | _ -> Error(Parsing,WrongInputParameters)


let consCipherSuites (cs:cipherSuite) (css:cipherSuites) = cs::css

// called by the server handshake; 
// ciphersuites that we do not understand are parsed,
// but not added to the list, and thus will be ignored by the server
let rec parseCipherSuites b:cipherSuites Result =
    if length b > 1 then
        let (b0,b1) = split b 2 
        match parseCipherSuites b1 with 
        | Correct(css) ->
            match cipherSuite_of_bytes b0 with
            | Error(x,y) -> // ignore this cs
                correct(css)
            | Correct(cs) -> let ncss = consCipherSuites cs css  in correct(ncss)
        | Error(x,y) -> Error(x,y) 
    else if length b = 0 then Correct([])
    else Error(Parsing,CheckFailed)

let rec bytes_of_cipherSuites css =
    match css with 
    | [] -> [||] 
    | cs::css -> cipherSuiteBytes cs @| 
                 bytes_of_cipherSuites css
    
(* we could use sub instead, with proper refinements:
let rec cipherSuites_of_bytes2 i b =
    if i <= Length(b) + 2 then 
        cipherSuite_of_bytes (sub b i 2) :: cipherSuites_of_bytes2 (i+2) b 
    else if i = Length(b) then 
        []
    else
        Error // the cipherSuite had an odd length!
*)


let isAnonCipherSuite cs =
    match cs with
    | CipherSuite ( DH_anon, _ )   -> true
 (* | ( ECDH_anon, _ ) -> true *)
    | _ -> false

let cipherSuiteRequiresKeyExchange cs =
    match cs with
    | CipherSuite ( DHE_DSS, _ )     -> true
    | CipherSuite ( DHE_RSA, _ )     -> true
 (* | CipherSuite ( ECDHE_ECDSA, _ ) -> true
    | CipherSuite ( ECDHE_RSA, _ )   -> true *)
    | _ -> false

let canEncryptPMS cs =
    match cs with
    | CipherSuite ( RSA, _ )     -> true
    | OnlyMACCipherSuite ( RSA, _ ) -> true
    | _ -> false

let contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV (css: cipherSuite list) =
#if fs
    List.exists (fun cs -> cs = SCSV (TLS_EMPTY_RENEGOTIATION_INFO_SCSV) ) css
#else
    failwith "TODO: fix list library": bool
#endif


let verifyDataLen_of_ciphersuite (cs:cipherSuite) =
    (* Only to be invoked with TLS 1.2 (hardcoded in previous versions *)
    match cs with
    | _ -> 12

let prfHashAlg_of_ciphersuite (cs:cipherSuite) =
    (* Only to be invoked with TLS 1.2 (hardcoded in previous versions *)
    match cs with
   // | CipherSuite ( ECDH*, EncMAC (_,SHA384)) -> SHA384
    | CipherSuite ( _ , EncMAC ( _ , _ )) -> SHA256
    | CipherSuite ( _ , AEAD ( _ , hAlg ))   -> hAlg
    | NullCipherSuite         -> unexpectedError "[prfHashAlg_of_ciphersuite] invoked on an invalid ciphersuite" 
    | SCSV (_)                -> unexpectedError "[prfHashAlg_of_ciphersuite] invoked on an invalid ciphersuite" 
    | _ -> unexpectedError "[prfHashAlg_of_ciphersuite] invoked on an invalid ciphersuite"

// PRF and verifyData hash algorithms are potentially independent in TLS 1.2,
// so we use two distinct functions. However, all currently defined ciphersuites
// use the same hash algorithm, so the current implementation of the two functions
// is the same.
let verifyDataHashAlg_of_ciphersuite (cs:cipherSuite) =
    (* Only to be invoked with TLS 1.2 (hardcoded in previous versions *)
    match cs with
   // | CipherSuite ( ECDH*, EncMAC (_,SHA384)) -> SHA384
    | CipherSuite ( _ , EncMAC ( _ , _ )) -> SHA256
    | CipherSuite ( _ , AEAD ( _ , hAlg ))   -> hAlg
    | NullCipherSuite         -> unexpectedError "[verifyDataHashAlg_of_ciphersuite] invoked on an invalid ciphersuite"
    | SCSV (_)                -> unexpectedError "[verifyDataHashAlg_of_ciphersuite] invoked on an invalid ciphersuite"
    | _ -> unexpectedError "[verifyDataHashAlg_of_ciphersuite] invoked on an invalid ciphersuite"

let maxPadSize pv cs =
    match cs with
    | NullCipherSuite
    | OnlyMACCipherSuite (_,_) -> 0
    | CipherSuite(_,aead) ->
        match aead with
        | AEAD (_,_) -> 0
        | EncMAC (encAlg,_) ->
            match encAlg with
            | RC4_128 -> 0
            | TDES_EDE_CBC
            | AES_128_CBC
            | AES_256_CBC ->
                match pv with
                | SSL_3p0 | TLS_1p0 -> blockSize encAlg
                | TLS_1p1 | TLS_1p2 -> 255
    | SCSV _ -> unexpectedError "[maxPadSize] invoked on an invalid ciphersuite"

let mkIntTriple x:(int*int*int) = x

let getKeyExtensionLength pv cs =
    let (keySize, IVSize, hashSize ) =
        match cs with
        | CipherSuite (_, EncMAC(cAlg, hAlg)) ->
            match pv with
            | SSL_3p0 | TLS_1p0 -> mkIntTriple ((encKeySize cAlg), (ivSize cAlg), (macKeySize hAlg)) 
            | TLS_1p1 | TLS_1p2 -> ((encKeySize cAlg),             0, (macKeySize hAlg)) (* TLS 1.1: no implicit IV *)
        | CipherSuite (_, AEAD(cAlg, hAlg)) -> ((aeadKeySize cAlg), (aeadIVSize cAlg), (macKeySize hAlg))
        | OnlyMACCipherSuite (_,hAlg) -> (0,0,macKeySize hAlg)
        | _ -> unexpectedError "[getKeyExtensionLength] invoked on an invalid ciphersuite"
    2 * (keySize + IVSize + hashSize)

let PVRequiresExplicitIV pv = 
    pv = TLS_1p1 || pv = TLS_1p2

let macAlg_of_ciphersuite cs =
    match cs with
    | CipherSuite (_, EncMAC(_,alg)) -> alg
    | OnlyMACCipherSuite (_, alg) -> alg
    | _ -> unexpectedError "[macAlg_of_ciphersuite] invoked on an invalid ciphersuite"

let encAlg_of_ciphersuite cs =
    match cs with
    | CipherSuite (_, EncMAC(alg,_)) -> alg
    | _ -> unexpectedError "[encAlg_of_ciphersuite] inovked on an invalid ciphersuite"

(* Not for verification, just to run the implementation. See TLSInfo.fs *)
type cipherSuiteName =
    | TLS_NULL_WITH_NULL_NULL              

    | TLS_RSA_WITH_NULL_MD5              
    | TLS_RSA_WITH_NULL_SHA              
    | TLS_RSA_WITH_NULL_SHA256           
    | TLS_RSA_WITH_RC4_128_MD5           
    | TLS_RSA_WITH_RC4_128_SHA           
    | TLS_RSA_WITH_3DES_EDE_CBC_SHA      
    | TLS_RSA_WITH_AES_128_CBC_SHA       
    | TLS_RSA_WITH_AES_256_CBC_SHA       
    | TLS_RSA_WITH_AES_128_CBC_SHA256    
    | TLS_RSA_WITH_AES_256_CBC_SHA256 
       
    | TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA   
    | TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA   
    | TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA  
    | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA  
    | TLS_DH_DSS_WITH_AES_128_CBC_SHA    
    | TLS_DH_RSA_WITH_AES_128_CBC_SHA    
    | TLS_DHE_DSS_WITH_AES_128_CBC_SHA   
    | TLS_DHE_RSA_WITH_AES_128_CBC_SHA      
    | TLS_DH_DSS_WITH_AES_256_CBC_SHA    
    | TLS_DH_RSA_WITH_AES_256_CBC_SHA    
    | TLS_DHE_DSS_WITH_AES_256_CBC_SHA   
    | TLS_DHE_RSA_WITH_AES_256_CBC_SHA    
    | TLS_DH_DSS_WITH_AES_128_CBC_SHA256 
    | TLS_DH_RSA_WITH_AES_128_CBC_SHA256 
    | TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 
    | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    | TLS_DH_DSS_WITH_AES_256_CBC_SHA256 
    | TLS_DH_RSA_WITH_AES_256_CBC_SHA256 
    | TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256

    | TLS_DH_anon_WITH_RC4_128_MD5       
    | TLS_DH_anon_WITH_3DES_EDE_CBC_SHA  
    | TLS_DH_anon_WITH_AES_128_CBC_SHA
    | TLS_DH_anon_WITH_AES_256_CBC_SHA  
    | TLS_DH_anon_WITH_AES_128_CBC_SHA256
    | TLS_DH_anon_WITH_AES_256_CBC_SHA256

let cipherSuites_of_nameList (nameList: cipherSuiteName list) =
#if fs
   List.map (
    fun name ->
        match name with
        | TLS_NULL_WITH_NULL_NULL                -> NullCipherSuite

        | TLS_RSA_WITH_NULL_MD5                  -> OnlyMACCipherSuite (RSA, MD5)
        | TLS_RSA_WITH_NULL_SHA                  -> OnlyMACCipherSuite (RSA, SHA)
        | TLS_RSA_WITH_NULL_SHA256               -> OnlyMACCipherSuite (RSA, SHA256)
        | TLS_RSA_WITH_RC4_128_MD5               -> CipherSuite (RSA, EncMAC (RC4_128, MD5))
        | TLS_RSA_WITH_RC4_128_SHA               -> CipherSuite (RSA, EncMAC (RC4_128, SHA))
        | TLS_RSA_WITH_3DES_EDE_CBC_SHA          -> CipherSuite (RSA, EncMAC (TDES_EDE_CBC, SHA))
        | TLS_RSA_WITH_AES_128_CBC_SHA           -> CipherSuite (RSA, EncMAC (AES_128_CBC, SHA))
        | TLS_RSA_WITH_AES_256_CBC_SHA           -> CipherSuite (RSA, EncMAC (AES_256_CBC, SHA))
        | TLS_RSA_WITH_AES_128_CBC_SHA256        -> CipherSuite (RSA, EncMAC (AES_128_CBC, SHA256))
        | TLS_RSA_WITH_AES_256_CBC_SHA256        -> CipherSuite (RSA, EncMAC (AES_256_CBC, SHA256))
       
        | TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA       -> CipherSuite (DH_DSS,  EncMAC (TDES_EDE_CBC, SHA))
        | TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA       -> CipherSuite (DH_RSA,  EncMAC (TDES_EDE_CBC, SHA))
        | TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      -> CipherSuite (DHE_DSS, EncMAC (TDES_EDE_CBC, SHA))
        | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      -> CipherSuite (DHE_RSA, EncMAC (TDES_EDE_CBC, SHA))
        | TLS_DH_DSS_WITH_AES_128_CBC_SHA        -> CipherSuite (DH_DSS,  EncMAC (AES_128_CBC, SHA))
        | TLS_DH_RSA_WITH_AES_128_CBC_SHA        -> CipherSuite (DH_RSA,  EncMAC (AES_128_CBC, SHA))
        | TLS_DHE_DSS_WITH_AES_128_CBC_SHA       -> CipherSuite (DHE_DSS, EncMAC (AES_128_CBC, SHA))
        | TLS_DHE_RSA_WITH_AES_128_CBC_SHA       -> CipherSuite (DHE_RSA, EncMAC (AES_128_CBC, SHA))
        | TLS_DH_DSS_WITH_AES_256_CBC_SHA        -> CipherSuite (DH_DSS,  EncMAC (AES_256_CBC, SHA))
        | TLS_DH_RSA_WITH_AES_256_CBC_SHA        -> CipherSuite (DH_RSA,  EncMAC (AES_256_CBC, SHA))
        | TLS_DHE_DSS_WITH_AES_256_CBC_SHA       -> CipherSuite (DHE_DSS, EncMAC (AES_256_CBC, SHA))
        | TLS_DHE_RSA_WITH_AES_256_CBC_SHA       -> CipherSuite (DHE_RSA, EncMAC (AES_256_CBC, SHA))
        | TLS_DH_DSS_WITH_AES_128_CBC_SHA256     -> CipherSuite (DH_DSS,  EncMAC (AES_128_CBC, SHA256))
        | TLS_DH_RSA_WITH_AES_128_CBC_SHA256     -> CipherSuite (DH_RSA,  EncMAC (AES_128_CBC, SHA256))
        | TLS_DHE_DSS_WITH_AES_128_CBC_SHA256    -> CipherSuite (DHE_DSS, EncMAC (AES_128_CBC, SHA256))
        | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256    -> CipherSuite (DHE_RSA, EncMAC (AES_128_CBC, SHA256))
        | TLS_DH_DSS_WITH_AES_256_CBC_SHA256     -> CipherSuite (DH_DSS,  EncMAC (AES_256_CBC, SHA256))
        | TLS_DH_RSA_WITH_AES_256_CBC_SHA256     -> CipherSuite (DH_RSA,  EncMAC (AES_256_CBC, SHA256))
        | TLS_DHE_DSS_WITH_AES_256_CBC_SHA256    -> CipherSuite (DHE_DSS, EncMAC (AES_256_CBC, SHA256))
        | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256    -> CipherSuite (DHE_RSA, EncMAC (AES_256_CBC, SHA256))

        | TLS_DH_anon_WITH_RC4_128_MD5           -> CipherSuite (DH_anon, EncMAC (RC4_128, MD5))
        | TLS_DH_anon_WITH_3DES_EDE_CBC_SHA      -> CipherSuite (DH_anon, EncMAC (TDES_EDE_CBC, SHA))
        | TLS_DH_anon_WITH_AES_128_CBC_SHA       -> CipherSuite (DH_anon, EncMAC (AES_128_CBC, SHA))
        | TLS_DH_anon_WITH_AES_256_CBC_SHA       -> CipherSuite (DH_anon, EncMAC (AES_256_CBC, SHA))
        | TLS_DH_anon_WITH_AES_128_CBC_SHA256    -> CipherSuite (DH_anon, EncMAC (AES_128_CBC, SHA256))
        | TLS_DH_anon_WITH_AES_256_CBC_SHA256    -> CipherSuite (DH_anon, EncMAC (AES_256_CBC, SHA256))
   ) nameList 
#else
    failwith "TODO: fix list library": cipherSuites
#endif
