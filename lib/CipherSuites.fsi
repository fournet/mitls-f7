module CipherSuites

open Bytes
open Algorithms
open Error

type cipherSuite

type cipherSuites = cipherSuite list

type Compression =
    | Null
    | UnknownComp

type ProtocolVersionType =
    | UnknownPV = -1
    | SSL_3p0   = 10
    | TLS_1p0   = 20
    | TLS_1p1   = 30
    | TLS_1p2   = 40

val versionBytes: ProtocolVersionType -> bytes
val parseVersion: bytes -> ProtocolVersionType
val minPV: ProtocolVersionType -> ProtocolVersionType -> ProtocolVersionType

val nullCipherSuite: cipherSuite
val isNullCipherSuite: cipherSuite -> bool
val isOnlyMACCipherSuite: cipherSuite -> bool

val isAnonCipherSuite: cipherSuite -> bool
val cipherSuiteRequiresKeyExchange: cipherSuite -> bool
val canEncryptPMS: cipherSuite -> bool
val contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV: cipherSuites -> bool
val verifyDataLen_of_ciphersuite: cipherSuite -> int
val prfHashAlg_of_ciphersuite: cipherSuite -> hashAlg
val verifyDataHashAlg_of_ciphersuite: cipherSuite -> hashAlg

val macAlg_of_ciphersuite: cipherSuite -> hashAlg
val encAlg_of_ciphersuite: cipherSuite -> cipherAlg

val compression_of_bytes: bytes -> Compression
val compressionBytes: Compression -> bytes
val compressions_of_bytes: bytes -> Compression list

val bytes_of_cipherSuite: cipherSuite -> bytes
val cipherSuite_of_bytes: bytes -> cipherSuite 
val cipherSuites_of_bytes: bytes -> cipherSuites Result
val bytes_of_cipherSuites: cipherSuites -> bytes 

val getKeyExtensionLength: ProtocolVersionType -> cipherSuite -> int

val PVRequiresExplicitIV: ProtocolVersionType -> bool

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

val cipherSuites_of_nameList: cipherSuiteName list -> cipherSuites