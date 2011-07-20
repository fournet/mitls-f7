module HS_ciphersuites
open Data
open Formats
open Error_handling

type CipherSuite =
    | TLS_NULL_WITH_NULL_NULL                

    | TLS_RSA_WITH_NULL_MD5                  
    | TLS_RSA_WITH_NULL_SHA                  
    | TLS_RSA_EXPORT_WITH_RC4_40_MD5         
    | TLS_RSA_WITH_RC4_128_MD5               
    | TLS_RSA_WITH_RC4_128_SHA               
    | TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5     
    | TLS_RSA_WITH_IDEA_CBC_SHA              
    | TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      
    | TLS_RSA_WITH_DES_CBC_SHA               
    | TLS_RSA_WITH_3DES_EDE_CBC_SHA          

    | TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   
    | TLS_DH_DSS_WITH_DES_CBC_SHA            
    | TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA       
    | TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA   
    | TLS_DH_RSA_WITH_DES_CBC_SHA            
    | TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA       
    | TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  
    | TLS_DHE_DSS_WITH_DES_CBC_SHA           
    | TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      
    | TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  
    | TLS_DHE_RSA_WITH_DES_CBC_SHA           
    | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      

    | TLS_DH_anon_EXPORT_WITH_RC4_40_MD5     
    | TLS_DH_anon_WITH_RC4_128_MD5           
    | TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA  
    | TLS_DH_anon_WITH_DES_CBC_SHA           
    | TLS_DH_anon_WITH_3DES_EDE_CBC_SHA      


    | TLS_RSA_WITH_AES_128_CBC_SHA           
    | TLS_DH_DSS_WITH_AES_128_CBC_SHA        
    | TLS_DH_RSA_WITH_AES_128_CBC_SHA        
    | TLS_DHE_DSS_WITH_AES_128_CBC_SHA       
    | TLS_DHE_RSA_WITH_AES_128_CBC_SHA       
    | TLS_DH_anon_WITH_AES_128_CBC_SHA       

    | TLS_RSA_WITH_AES_256_CBC_SHA           
    | TLS_DH_DSS_WITH_AES_256_CBC_SHA        
    | TLS_DH_RSA_WITH_AES_256_CBC_SHA        
    | TLS_DHE_DSS_WITH_AES_256_CBC_SHA       
    | TLS_DHE_RSA_WITH_AES_256_CBC_SHA       
    | TLS_DH_anon_WITH_AES_256_CBC_SHA       


    | TLS_ECDH_ECDSA_WITH_NULL_SHA           
    | TLS_ECDH_ECDSA_WITH_RC4_128_SHA        
    | TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA   
    | TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA    
    | TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA    

    | TLS_ECDHE_ECDSA_WITH_NULL_SHA          
    | TLS_ECDHE_ECDSA_WITH_RC4_128_SHA       
    | TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA  
    | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   
    | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   

    | TLS_ECDH_RSA_WITH_NULL_SHA             
    | TLS_ECDH_RSA_WITH_RC4_128_SHA          
    | TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA     
    | TLS_ECDH_RSA_WITH_AES_128_CBC_SHA      
    | TLS_ECDH_RSA_WITH_AES_256_CBC_SHA      

    | TLS_ECDHE_RSA_WITH_NULL_SHA            
    | TLS_ECDHE_RSA_WITH_RC4_128_SHA         
    | TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA    
    | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     
    | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     

    | TLS_ECDH_anon_WITH_NULL_SHA            
    | TLS_ECDH_anon_WITH_RC4_128_SHA         
    | TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA    
    | TLS_ECDH_anon_WITH_AES_128_CBC_SHA     
    | TLS_ECDH_anon_WITH_AES_256_CBC_SHA     

    (* carryovers from SSLv2 *)
    | TLS_RC4_128_WITH_MD5
    | TLS_RC4_128_EXPORT40_WITH_MD5
    | TLS_RC2_CBC_128_CBC_WITH_MD5
    | TLS_RC2_CBC_128_CBC_EXPORT40_WITH_MD5
    | TLS_IDEA_128_CBC_WITH_MD5
    | TLS_DES_64_CBC_WITH_MD5
    | TLS_DES_192_EDE3_CBC_WITH_MD5

    | UNKNOWN_CIPHERSUITE of int * int

type cipherSuites = CipherSuite list

val cipherSuite_of_intpair : int * int -> CipherSuite
val intpair_of_cipherSuite : CipherSuite -> (int * int)
val bytes_of_cipherSuite: CipherSuite -> bytes
val cipherSuite_of_bytes: bytes -> CipherSuite
val isAnonCipherSuite: CipherSuite -> bool
val cipherSuiteRequiresKeyExchange: CipherSuite -> bool
val canEncryptPMS: CipherSuite -> bool
val securityParameters_of_ciphersuite: CipherSuite -> SecurityParameters Result