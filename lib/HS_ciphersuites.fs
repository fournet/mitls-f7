module HS_ciphersuites

open Data
open Bytearray
open Algorithms
open Error_handling

type SCSVsuite =
    | TLS_EMPTY_RENEGOTIATION_INFO_SCSV

type cipherSuite =
    | NullCipherSuite
    | CipherSuite of kexAlg * authencAlg
    | OnlyMACCipherSuite of kexAlg * hashAlg
    | SCSV of SCSVsuite
    | Unknown of bytes

type cipherSuites = cipherSuite list

type Compression =
    | Null
    | UnknownComp of byte

let byte_of_compression comp =
    match comp with
    | Null -> 0uy
    | UnknownComp _ -> unexpectedError "[byte_of_compression] Cannot convert the unknown compression type to a byte"

let compression_of_byte b =
    match b with
    | 0uy -> Null
    | _ -> UnknownComp b

let rec compressions_of_bytes_int b list =
    if length b = 0 then
        list
    else
        let (cmB,rem) = split b 1 in
        let cm = compression_of_byte cmB.[0] in
        let list = [cm] @ list in
        compressions_of_bytes_int rem list

let compressions_of_bytes b = compressions_of_bytes_int b []

type ProtocolVersionType =
    | SSL_2p0 = 10
    | SSL_3p0 = 20
    | TLS_1p0 = 30
    | TLS_1p1 = 40
    | TLS_1p2 = 50
    | UnknownPV = -1

let nullCipherSuite = NullCipherSuite

let isNullCipherSuite cs =
    cs = NullCipherSuite

let cipherSuite_of_bytes b = 
    match b with
    | [| 0x00uy; 0x00uy |] -> NullCipherSuite
   
    | [| 0x00uy; 0x01uy |] -> OnlyMACCipherSuite (kexAlg.RSA, hashAlg.MD5)
    | [| 0x00uy; 0x02uy |] -> OnlyMACCipherSuite (kexAlg.RSA, hashAlg.SHA)
    | [| 0x00uy; 0x3Buy |] -> OnlyMACCipherSuite (kexAlg.RSA, hashAlg.SHA256)
    | [| 0x00uy; 0x04uy |] -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.RC4_128, hashAlg.MD5))
    | [| 0x00uy; 0x05uy |] -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.RC4_128, hashAlg.SHA))
    | [| 0x00uy; 0x0Auy |] -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x2Fuy |] -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x35uy |] -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x3Cuy |] -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
    | [| 0x00uy; 0x3Duy |] -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))
    
    | [| 0x00uy; 0x0Duy |] -> CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x10uy |] -> CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x13uy |] -> CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x16uy |] -> CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x30uy |] -> CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x31uy |] -> CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x32uy |] -> CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x33uy |] -> CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x36uy |] -> CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x37uy |] -> CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x38uy |] -> CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x39uy |] -> CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x3Euy |] -> CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
    | [| 0x00uy; 0x3Fuy |] -> CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
    | [| 0x00uy; 0x40uy |] -> CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
    | [| 0x00uy; 0x67uy |] -> CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
    | [| 0x00uy; 0x68uy |] -> CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))
    | [| 0x00uy; 0x69uy |] -> CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))
    | [| 0x00uy; 0x6Auy |] -> CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))
    | [| 0x00uy; 0x6Buy |] -> CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))

    | [| 0x00uy; 0x18uy |] -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.RC4_128, hashAlg.MD5))
    | [| 0x00uy; 0x1Buy |] -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x34uy |] -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x3Auy |] -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
    | [| 0x00uy; 0x6Cuy |] -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
    | [| 0x00uy; 0x6Duy |] -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))

    | [| 0x00uy; 0xFFuy |] -> SCSV (TLS_EMPTY_RENEGOTIATION_INFO_SCSV)

    | _ -> cipherSuite.Unknown (b)

let bytes_of_cipherSuite cs = 
    match cs with
    | NullCipherSuite                                                                -> [| 0x00uy; 0x00uy |]

    | OnlyMACCipherSuite (kexAlg.RSA, hashAlg.MD5)                                   -> [| 0x00uy; 0x01uy |]
    | OnlyMACCipherSuite (kexAlg.RSA, hashAlg.SHA)                                   -> [| 0x00uy; 0x02uy |]
    | OnlyMACCipherSuite (kexAlg.RSA, hashAlg.SHA256)                                -> [| 0x00uy; 0x3Buy |]
    | CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.RC4_128, hashAlg.MD5))              -> [| 0x00uy; 0x04uy |]
    | CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.RC4_128, hashAlg.SHA))              -> [| 0x00uy; 0x05uy |]
    | CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))     -> [| 0x00uy; 0x0Auy |]
    | CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))          -> [| 0x00uy; 0x2Fuy |]
    | CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))          -> [| 0x00uy; 0x35uy |]
    | CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))       -> [| 0x00uy; 0x3Cuy |]
    | CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))       -> [| 0x00uy; 0x3Duy |]

    | CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA)) -> [| 0x00uy; 0x0Duy |]
    | CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA)) -> [| 0x00uy; 0x10uy |]
    | CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA)) -> [| 0x00uy; 0x13uy |]
    | CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA)) -> [| 0x00uy; 0x16uy |]
    | CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))      -> [| 0x00uy; 0x30uy |]
    | CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))      -> [| 0x00uy; 0x31uy |]
    | CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))      -> [| 0x00uy; 0x32uy |]
    | CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))      -> [| 0x00uy; 0x33uy |]
    | CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))      -> [| 0x00uy; 0x36uy |]
    | CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))      -> [| 0x00uy; 0x37uy |]
    | CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))      -> [| 0x00uy; 0x38uy |]
    | CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))      -> [| 0x00uy; 0x39uy |]
    | CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))   -> [| 0x00uy; 0x3Euy |]
    | CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))   -> [| 0x00uy; 0x3Fuy |]
    | CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))   -> [| 0x00uy; 0x40uy |]
    | CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))   -> [| 0x00uy; 0x67uy |]
    | CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))   -> [| 0x00uy; 0x68uy |]
    | CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))   -> [| 0x00uy; 0x69uy |]
    | CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))   -> [| 0x00uy; 0x6Auy |]
    | CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))   -> [| 0x00uy; 0x6Buy |]

    | CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.RC4_128, hashAlg.MD5))          -> [| 0x00uy; 0x18uy |]
    | CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA)) -> [| 0x00uy; 0x1Buy |]
    | CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))      -> [| 0x00uy; 0x34uy |]
    | CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))      -> [| 0x00uy; 0x3Auy |]
    | CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))   -> [| 0x00uy; 0x6Cuy |]
    | CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))   -> [| 0x00uy; 0x6Duy |]

    | SCSV (TLS_EMPTY_RENEGOTIATION_INFO_SCSV)                                      -> [| 0x00uy; 0xFFuy |]

    | cipherSuite.Unknown (b)                                                       -> b
    | _ -> unexpectedError "[bytearray_of_ciphersuite] invoked on an unknown ciphersuite"


let rec cipherSuites_of_bytes_int b list =
    if Bytearray.length b = 0 then
        list
    else
        let (csB,rem) = split b 2 in
        let cs = cipherSuite_of_bytes csB in
        let list = [cs] @ list in
        cipherSuites_of_bytes_int rem list

let cipherSuites_of_bytes b = cipherSuites_of_bytes_int b []

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

let contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV ciphlist =
    List.exists (fun cs -> cs = SCSV (TLS_EMPTY_RENEGOTIATION_INFO_SCSV) ) ciphlist

let verifyDataLen_of_ciphersuite (cs:cipherSuite) =
    (* Only to be invoked with TLS 1.2 (hardcoded in previous versions *)
    match cs with
    | _ -> 12

let prfHashAlg_of_ciphersuite (cs:cipherSuite) =
    (* Only to be invoked with TLS 1.2 (hardcoded in previous versions *)
    match cs with
    | CipherSuite ( _ , EncMAC ( _ , SHA384 )) -> SHA384
    | CipherSuite ( _ , AEAD ( _ , SHA384 ))   -> SHA384
    | NullCipherSuite | SCSV (_) | cipherSuite.Unknown (_) -> unexpectedError "[prfHashAlg_of_ciphersuite] invoked on an invalid ciphersuite"
    | _ -> SHA256

let verifyDataHashAlg_of_ciphersuite (cs:cipherSuite) =
    (* Only to be invoked with TLS 1.2 (hardcoded in previous versions *)
    match cs with
    | CipherSuite ( _ , EncMAC ( _ , SHA384 )) -> SHA384
    | CipherSuite ( _ , AEAD ( _ , SHA384 ))   -> SHA384
    | NullCipherSuite | SCSV (_) | cipherSuite.Unknown (_) -> unexpectedError "[prfHashAlg_of_ciphersuite] invoked on an invalid ciphersuite"
    | _ -> SHA256

let getKeyExtensionLength pv cs =
    let (keySize, hashSize, IVSize ) =
        match cs with
        | CipherSuite (_, EncMAC(cAlg, hAlg)) ->
            match pv with
            | x when x >= ProtocolVersionType.TLS_1p1 -> ((keyMaterialSize cAlg), 0, (macKeyLength hAlg)) (* TLS 1.1: no implicit IV *)
            | _ -> ((keyMaterialSize cAlg), (ivSize cAlg), (macKeyLength hAlg))
        | CipherSuite (_, AEAD(cAlg, hAlg)) -> ((aeadKeyMaterialSize cAlg), (aeadIVSize cAlg), (macKeyLength hAlg))
        | OnlyMACCipherSuite (_,hAlg) -> (0,0,macKeyLength hAlg)
        | _ -> unexpectedError "[getKeyExtensionLength] invoked on an invalid ciphersuite"
    2 * (keySize + hashSize + IVSize)

let PVRequiresExplicitIV pv =
    match pv with
    | ProtocolVersionType.SSL_3p0 | ProtocolVersionType.TLS_1p0 -> false
    | x when x >= ProtocolVersionType.TLS_1p1 -> true
    | _ -> unexpectedError "[PVRequiresExplicitIV] invoked on an invalid protocol version"

let macAlg_of_ciphersuite cs =
    match cs with
    | CipherSuite (_, EncMAC(_,alg)) -> alg
    | OnlyMACCipherSuite (_, alg) -> alg
    | _ -> unexpectedError "[macAlg_of_ciphersuite] invoked on an invalid ciphersuite"

let encAlg_of_ciphersuite cs =
    match cs with
    | CipherSuite (_, EncMAC(alg,_)) -> alg
    | _ -> unexpectedError "[encAlg_of_ciphersuite] inovked on an invalid ciphersuite"

(* Not for verification, just to run the implementation *)

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

let cipherSuites_of_nameList nameList =
   List.map (
    fun name ->
        match name with
        | TLS_NULL_WITH_NULL_NULL                -> NullCipherSuite

        | TLS_RSA_WITH_NULL_MD5                  -> OnlyMACCipherSuite (kexAlg.RSA, hashAlg.MD5)
        | TLS_RSA_WITH_NULL_SHA                  -> OnlyMACCipherSuite (kexAlg.RSA, hashAlg.SHA)
        | TLS_RSA_WITH_NULL_SHA256               -> OnlyMACCipherSuite (kexAlg.RSA, hashAlg.SHA256)
        | TLS_RSA_WITH_RC4_128_MD5               -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.RC4_128, hashAlg.MD5))
        | TLS_RSA_WITH_RC4_128_SHA               -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.RC4_128, hashAlg.SHA))
        | TLS_RSA_WITH_3DES_EDE_CBC_SHA          -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
        | TLS_RSA_WITH_AES_128_CBC_SHA           -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
        | TLS_RSA_WITH_AES_256_CBC_SHA           -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
        | TLS_RSA_WITH_AES_128_CBC_SHA256        -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
        | TLS_RSA_WITH_AES_256_CBC_SHA256        -> CipherSuite (kexAlg.RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))
       
        | TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA       -> CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
        | TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA       -> CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
        | TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      -> CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
        | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      -> CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
        | TLS_DH_DSS_WITH_AES_128_CBC_SHA        -> CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
        | TLS_DH_RSA_WITH_AES_128_CBC_SHA        -> CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
        | TLS_DHE_DSS_WITH_AES_128_CBC_SHA       -> CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
        | TLS_DHE_RSA_WITH_AES_128_CBC_SHA       -> CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
        | TLS_DH_DSS_WITH_AES_256_CBC_SHA        -> CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
        | TLS_DH_RSA_WITH_AES_256_CBC_SHA        -> CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
        | TLS_DHE_DSS_WITH_AES_256_CBC_SHA       -> CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
        | TLS_DHE_RSA_WITH_AES_256_CBC_SHA       -> CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
        | TLS_DH_DSS_WITH_AES_128_CBC_SHA256     -> CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
        | TLS_DH_RSA_WITH_AES_128_CBC_SHA256     -> CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
        | TLS_DHE_DSS_WITH_AES_128_CBC_SHA256    -> CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
        | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256    -> CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
        | TLS_DH_DSS_WITH_AES_256_CBC_SHA256     -> CipherSuite (kexAlg.DH_DSS,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))
        | TLS_DH_RSA_WITH_AES_256_CBC_SHA256     -> CipherSuite (kexAlg.DH_RSA,  EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))
        | TLS_DHE_DSS_WITH_AES_256_CBC_SHA256    -> CipherSuite (kexAlg.DHE_DSS, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))
        | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256    -> CipherSuite (kexAlg.DHE_RSA, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))

        | TLS_DH_anon_WITH_RC4_128_MD5           -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.RC4_128, hashAlg.MD5))
        | TLS_DH_anon_WITH_3DES_EDE_CBC_SHA      -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.THREEDES_EDE_CBC, hashAlg.SHA))
        | TLS_DH_anon_WITH_AES_128_CBC_SHA       -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA))
        | TLS_DH_anon_WITH_AES_256_CBC_SHA       -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA))
        | TLS_DH_anon_WITH_AES_128_CBC_SHA256    -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_128_CBC, hashAlg.SHA256))
        | TLS_DH_anon_WITH_AES_256_CBC_SHA256    -> CipherSuite (kexAlg.DH_anon, EncMAC (cipherAlg.AES_256_CBC, hashAlg.SHA256))
   ) nameList 