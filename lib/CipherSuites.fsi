module CipherSuites

open Bytes
open Algorithms
open Error

type cipherSuite

type cipherSuites = cipherSuite list

type Compression =
    | NullCompression

type ProtocolVersion =
    | SSL_3p0
    | TLS_1p0
    | TLS_1p1
    | TLS_1p2

val versionBytes: ProtocolVersion -> bytes
val parseVersion: bytes -> ProtocolVersion Result
val minPV: ProtocolVersion -> ProtocolVersion -> ProtocolVersion
val geqPV: ProtocolVersion -> ProtocolVersion -> bool

val nullCipherSuite: cipherSuite
val isNullCipherSuite: cipherSuite -> bool
val isOnlyMACCipherSuite: cipherSuite -> bool
val isAEADCipherSuite: cipherSuite -> bool

val isAnonCipherSuite: cipherSuite -> bool
val isDHECipherSuite: cipherSuite -> bool
val isRSACipherSuite: cipherSuite -> bool
val contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV: cipherSuites -> bool
val verifyDataLen_of_ciphersuite: cipherSuite -> int
val prfHashAlg_of_ciphersuite: cipherSuite -> hashAlg
val verifyDataHashAlg_of_ciphersuite: cipherSuite -> hashAlg

val macAlg_of_ciphersuite: cipherSuite -> hashAlg
val encAlg_of_ciphersuite: cipherSuite -> cipherAlg

val compressionBytes: Compression -> bytes
val parseCompression: bytes -> Compression Result
val parseCompressions: bytes -> Compression list

val cipherSuiteBytes: cipherSuite -> bytes
val cipherSuite_of_bytes: bytes -> cipherSuite Result
val parseCipherSuites: bytes -> cipherSuites Result
val bytes_of_cipherSuites: cipherSuites -> bytes

val maxPadSize: ProtocolVersion -> cipherSuite -> nat

val getKeyExtensionLength: ProtocolVersion -> cipherSuite -> int

val PVRequiresExplicitIV: ProtocolVersion -> bool

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