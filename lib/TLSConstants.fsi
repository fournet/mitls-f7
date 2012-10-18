module TLSConstants

open Bytes
open Error

(* Not abstracts, but only meant to be used by
   crypto modules and CipherSuites *)
type kexAlg =
    | RSA
    | DH_DSS
    | DH_RSA
    | DHE_DSS
    | DHE_RSA
    | DH_anon

type cipherAlg =
    | RC4_128
    | TDES_EDE_CBC
    | AES_128_CBC
    | AES_256_CBC

type hashAlg =
    | MD5
    | SHA
    | SHA256
    | SHA384

type sigAlg = 
  | SA_RSA
  | SA_DSA 
  | SA_ECDSA

type aeadAlg =
    | AES_128_GCM
    | AES_256_GCM

type authencAlg =
    | MtE of cipherAlg * hashAlg
    | AEAD of aeadAlg * hashAlg

val sigAlgBytes: sigAlg -> bytes
val parseSigAlg: bytes -> sigAlg Result
val hashAlgBytes: hashAlg -> bytes
val parseHashAlg: bytes -> hashAlg Result

val encKeySize: cipherAlg -> int
val blockSize: cipherAlg -> int
val ivSize: cipherAlg -> int
val aeadKeySize: aeadAlg -> int
val aeadIVSize: aeadAlg -> int
val macKeySize: hashAlg -> int
val macSize: hashAlg -> int
val hashSize: hashAlg -> int

(* SSL Constants *)
val ssl_pad1_md5: bytes
val ssl_pad2_md5: bytes
val ssl_pad1_sha1: bytes
val ssl_pad2_sha1: bytes

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
val isDHCipherSuite: cipherSuite -> bool
val isDHECipherSuite: cipherSuite -> bool
val isRSACipherSuite: cipherSuite -> bool
val contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV: cipherSuites -> bool
val verifyDataLen_of_ciphersuite: cipherSuite -> int
val prfHashAlg_of_ciphersuite: cipherSuite -> hashAlg
val verifyDataHashAlg_of_ciphersuite: cipherSuite -> hashAlg

val macAlg_of_ciphersuite: cipherSuite -> hashAlg
val encAlg_of_ciphersuite: cipherSuite -> cipherAlg
val sigAlg_of_ciphersuite: cipherSuite -> sigAlg

val compressionBytes: Compression -> bytes
val compressionMethodsBytes: Compression list -> bytes
val parseCompression: bytes -> Compression Result
val parseCompressions: bytes -> Compression list

val cipherSuiteBytes: cipherSuite -> bytes
val parseCipherSuite: bytes -> cipherSuite Result
val parseCipherSuites: bytes -> cipherSuites Result
val cipherSuitesBytes: cipherSuites -> bytes

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

val cipherSuites_of_nameList: cipherSuiteName list -> cipherSuitesmodule Formats

(* val split_at_most: bytes -> int -> (bytes * bytes) *)

type preContentType =
    | Change_cipher_spec
    | Alert
    | Handshake
    | Application_data

type ContentType = preContentType 
val bytes_of_seq: int -> bytes
val seq_of_bytes: bytes -> int

val ctBytes: ContentType -> bytes
val parseCT: bytes -> ContentType Result
val CTtoString: ContentType -> string

val vlbytes: int -> bytes -> bytes
val vlsplit: int -> bytes -> (bytes * bytes) Result
val vlparse: int -> bytes -> bytes Result

//val splitList: bytes -> int list -> bytes list

type certType =
    | RSA_sign
    | DSA_sign
    | RSA_fixed_dh
    | DSA_fixed_dh

val certTypeBytes: certType -> bytes
val parseCertType: bytes -> certType Result
