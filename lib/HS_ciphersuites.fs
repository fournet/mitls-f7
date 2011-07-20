module HS_ciphersuites

open Data
open Formats

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

let cipherSuite_of_intpair i = 
   match i with
    |  ( 0x00,0x00 )  ->  TLS_NULL_WITH_NULL_NULL                

    |  ( 0x00,0x01 )  ->  TLS_RSA_WITH_NULL_MD5                  
    |  ( 0x00,0x02 )  ->  TLS_RSA_WITH_NULL_SHA                  
    |  ( 0x00,0x03 )  ->  TLS_RSA_EXPORT_WITH_RC4_40_MD5         
    |  ( 0x00,0x04 )  ->  TLS_RSA_WITH_RC4_128_MD5               
    |  ( 0x00,0x05 )  ->  TLS_RSA_WITH_RC4_128_SHA               
    |  ( 0x00,0x06 )  ->  TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5     
    |  ( 0x00,0x07 )  ->  TLS_RSA_WITH_IDEA_CBC_SHA              
    |  ( 0x00,0x08 )  ->  TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      
    |  ( 0x00,0x09 )  ->  TLS_RSA_WITH_DES_CBC_SHA               
    |  ( 0x00,0x0A )  ->  TLS_RSA_WITH_3DES_EDE_CBC_SHA          

    |  ( 0x00,0x0B )  ->  TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   
    |  ( 0x00,0x0C )  ->  TLS_DH_DSS_WITH_DES_CBC_SHA            
    |  ( 0x00,0x0D )  ->  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA       
    |  ( 0x00,0x0E )  ->  TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA   
    |  ( 0x00,0x0F )  ->  TLS_DH_RSA_WITH_DES_CBC_SHA            
    |  ( 0x00,0x10 )  ->  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA       
    |  ( 0x00,0x11 )  ->  TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  
    |  ( 0x00,0x12 )  ->  TLS_DHE_DSS_WITH_DES_CBC_SHA           
    |  ( 0x00,0x13 )  ->  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      
    |  ( 0x00,0x14 )  ->  TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  
    |  ( 0x00,0x15 )  ->  TLS_DHE_RSA_WITH_DES_CBC_SHA           
    |  ( 0x00,0x16 )  ->  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      

    |  ( 0x00,0x17 )  ->  TLS_DH_anon_EXPORT_WITH_RC4_40_MD5     
    |  ( 0x00,0x18 )  ->  TLS_DH_anon_WITH_RC4_128_MD5           
    |  ( 0x00,0x19 )  ->  TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA  
    |  ( 0x00,0x1A )  ->  TLS_DH_anon_WITH_DES_CBC_SHA           
    |  ( 0x00,0x1B )  ->  TLS_DH_anon_WITH_3DES_EDE_CBC_SHA      


    |  ( 0x00, 0x2F )  ->  TLS_RSA_WITH_AES_128_CBC_SHA           
    |  ( 0x00, 0x30 )  ->  TLS_DH_DSS_WITH_AES_128_CBC_SHA        
    |  ( 0x00, 0x31 )  ->  TLS_DH_RSA_WITH_AES_128_CBC_SHA        
    |  ( 0x00, 0x32 )  ->  TLS_DHE_DSS_WITH_AES_128_CBC_SHA       
    |  ( 0x00, 0x33 )  ->  TLS_DHE_RSA_WITH_AES_128_CBC_SHA       
    |  ( 0x00, 0x34 )  ->  TLS_DH_anon_WITH_AES_128_CBC_SHA       

    |  ( 0x00, 0x35 )  ->  TLS_RSA_WITH_AES_256_CBC_SHA           
    |  ( 0x00, 0x36 )  ->  TLS_DH_DSS_WITH_AES_256_CBC_SHA        
    |  ( 0x00, 0x37 )  ->  TLS_DH_RSA_WITH_AES_256_CBC_SHA        
    |  ( 0x00, 0x38 )  ->  TLS_DHE_DSS_WITH_AES_256_CBC_SHA       
    |  ( 0x00, 0x39 )  ->  TLS_DHE_RSA_WITH_AES_256_CBC_SHA       
    |  ( 0x00, 0x3A )  ->  TLS_DH_anon_WITH_AES_256_CBC_SHA       


    |  ( 0xC0, 0x01 )  ->  TLS_ECDH_ECDSA_WITH_NULL_SHA           
    |  ( 0xC0, 0x02 )  ->  TLS_ECDH_ECDSA_WITH_RC4_128_SHA        
    |  ( 0xC0, 0x03 )  ->  TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA   
    |  ( 0xC0, 0x04 )  ->  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA    
    |  ( 0xC0, 0x05 )  ->  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA    

    |  ( 0xC0, 0x06 )  ->  TLS_ECDHE_ECDSA_WITH_NULL_SHA          
    |  ( 0xC0, 0x07 )  ->  TLS_ECDHE_ECDSA_WITH_RC4_128_SHA       
    |  ( 0xC0, 0x08 )  ->  TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA  
    |  ( 0xC0, 0x09 )  ->  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   
    |  ( 0xC0, 0x0A )  ->  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   

    |  ( 0xC0, 0x0B )  ->  TLS_ECDH_RSA_WITH_NULL_SHA             
    |  ( 0xC0, 0x0C )  ->  TLS_ECDH_RSA_WITH_RC4_128_SHA          
    |  ( 0xC0, 0x0D )  ->  TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA     
    |  ( 0xC0, 0x0E )  ->  TLS_ECDH_RSA_WITH_AES_128_CBC_SHA      
    |  ( 0xC0, 0x0F )  ->  TLS_ECDH_RSA_WITH_AES_256_CBC_SHA      

    |  ( 0xC0, 0x10 )  ->  TLS_ECDHE_RSA_WITH_NULL_SHA            
    |  ( 0xC0, 0x11 )  ->  TLS_ECDHE_RSA_WITH_RC4_128_SHA         
    |  ( 0xC0, 0x12 )  ->  TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA    
    |  ( 0xC0, 0x13 )  ->  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     
    |  ( 0xC0, 0x14 )  ->  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     

    |  ( 0xC0, 0x15 )  ->  TLS_ECDH_anon_WITH_NULL_SHA            
    |  ( 0xC0, 0x16 )  ->  TLS_ECDH_anon_WITH_RC4_128_SHA         
    |  ( 0xC0, 0x17 )  ->  TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA    
    |  ( 0xC0, 0x18 )  ->  TLS_ECDH_anon_WITH_AES_128_CBC_SHA     
    |  ( 0xC0, 0x19 )  ->  TLS_ECDH_anon_WITH_AES_256_CBC_SHA     

    |  (x,y) -> UNKNOWN_CIPHERSUITE(x,y)

let intpair_of_cipherSuite i = 
   match i with
    | TLS_NULL_WITH_NULL_NULL                -> ( 0x00,0x00 )

    | TLS_RSA_WITH_NULL_MD5                  -> ( 0x00,0x01 )
    | TLS_RSA_WITH_NULL_SHA                  -> ( 0x00,0x02 )
    | TLS_RSA_EXPORT_WITH_RC4_40_MD5         -> ( 0x00,0x03 )
    | TLS_RSA_WITH_RC4_128_MD5               -> ( 0x00,0x04 )
    | TLS_RSA_WITH_RC4_128_SHA               -> ( 0x00,0x05 )
    | TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5     -> ( 0x00,0x06 )
    | TLS_RSA_WITH_IDEA_CBC_SHA              -> ( 0x00,0x07 )
    | TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      -> ( 0x00,0x08 )
    | TLS_RSA_WITH_DES_CBC_SHA               -> ( 0x00,0x09 )
    | TLS_RSA_WITH_3DES_EDE_CBC_SHA          -> ( 0x00,0x0A )

    | TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   -> ( 0x00,0x0B )
    | TLS_DH_DSS_WITH_DES_CBC_SHA            -> ( 0x00,0x0C )
    | TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA       -> ( 0x00,0x0D )
    | TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA   -> ( 0x00,0x0E )
    | TLS_DH_RSA_WITH_DES_CBC_SHA            -> ( 0x00,0x0F )
    | TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA       -> ( 0x00,0x10 )
    | TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  -> ( 0x00,0x11 )
    | TLS_DHE_DSS_WITH_DES_CBC_SHA           -> ( 0x00,0x12 )
    | TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      -> ( 0x00,0x13 )
    | TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  -> ( 0x00,0x14 )
    | TLS_DHE_RSA_WITH_DES_CBC_SHA           -> ( 0x00,0x15 )
    | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      -> ( 0x00,0x16 )

    | TLS_DH_anon_EXPORT_WITH_RC4_40_MD5     -> ( 0x00,0x17 )
    | TLS_DH_anon_WITH_RC4_128_MD5           -> ( 0x00,0x18 )
    | TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA  -> ( 0x00,0x19 )
    | TLS_DH_anon_WITH_DES_CBC_SHA           -> ( 0x00,0x1A )
    | TLS_DH_anon_WITH_3DES_EDE_CBC_SHA      -> ( 0x00,0x1B )


    | TLS_RSA_WITH_AES_128_CBC_SHA           -> ( 0x00, 0x2F )
    | TLS_DH_DSS_WITH_AES_128_CBC_SHA        -> ( 0x00, 0x30 )
    | TLS_DH_RSA_WITH_AES_128_CBC_SHA        -> ( 0x00, 0x31 )
    | TLS_DHE_DSS_WITH_AES_128_CBC_SHA       -> ( 0x00, 0x32 )
    | TLS_DHE_RSA_WITH_AES_128_CBC_SHA       -> ( 0x00, 0x33 )
    | TLS_DH_anon_WITH_AES_128_CBC_SHA       -> ( 0x00, 0x34 )

    | TLS_RSA_WITH_AES_256_CBC_SHA           -> ( 0x00, 0x35 )
    | TLS_DH_DSS_WITH_AES_256_CBC_SHA        -> ( 0x00, 0x36 )
    | TLS_DH_RSA_WITH_AES_256_CBC_SHA        -> ( 0x00, 0x37 )
    | TLS_DHE_DSS_WITH_AES_256_CBC_SHA       -> ( 0x00, 0x38 )
    | TLS_DHE_RSA_WITH_AES_256_CBC_SHA       -> ( 0x00, 0x39 )
    | TLS_DH_anon_WITH_AES_256_CBC_SHA       -> ( 0x00, 0x3A )


    | TLS_ECDH_ECDSA_WITH_NULL_SHA           -> ( 0xC0, 0x01 )
    | TLS_ECDH_ECDSA_WITH_RC4_128_SHA        -> ( 0xC0, 0x02 )
    | TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA   -> ( 0xC0, 0x03 )
    | TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA    -> ( 0xC0, 0x04 )
    | TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA    -> ( 0xC0, 0x05 )

    | TLS_ECDHE_ECDSA_WITH_NULL_SHA          -> ( 0xC0, 0x06 )
    | TLS_ECDHE_ECDSA_WITH_RC4_128_SHA       -> ( 0xC0, 0x07 )
    | TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA  -> ( 0xC0, 0x08 )
    | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   -> ( 0xC0, 0x09 )
    | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   -> ( 0xC0, 0x0A )

    | TLS_ECDH_RSA_WITH_NULL_SHA             -> ( 0xC0, 0x0B )
    | TLS_ECDH_RSA_WITH_RC4_128_SHA          -> ( 0xC0, 0x0C )
    | TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA     -> ( 0xC0, 0x0D )
    | TLS_ECDH_RSA_WITH_AES_128_CBC_SHA      -> ( 0xC0, 0x0E )
    | TLS_ECDH_RSA_WITH_AES_256_CBC_SHA      -> ( 0xC0, 0x0F )

    | TLS_ECDHE_RSA_WITH_NULL_SHA            -> ( 0xC0, 0x10 )
    | TLS_ECDHE_RSA_WITH_RC4_128_SHA         -> ( 0xC0, 0x11 )
    | TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA    -> ( 0xC0, 0x12 )
    | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     -> ( 0xC0, 0x13 )
    | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     -> ( 0xC0, 0x14 )

    | TLS_ECDH_anon_WITH_NULL_SHA            -> ( 0xC0, 0x15 )
    | TLS_ECDH_anon_WITH_RC4_128_SHA         -> ( 0xC0, 0x16 )
    | TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA    -> ( 0xC0, 0x17 )
    | TLS_ECDH_anon_WITH_AES_128_CBC_SHA     -> ( 0xC0, 0x18 )
    | TLS_ECDH_anon_WITH_AES_256_CBC_SHA     -> ( 0xC0, 0x19 )

    | UNKNOWN_CIPHERSUITE (x,y) -> (x,y)
    | x -> failwith "[int_of_ciphersuite] -- maybe a SSLv2 ciphersuite"

let bytes_of_cipherSuite cs =
    bytes_of_intpair (intpair_of_cipherSuite cs)

let cipherSuite_of_bytes b =
    cipherSuite_of_intpair (intpair_of_bytes b)

let isAnonCipherSuite cs =
    match cs with
    | TLS_DH_anon_EXPORT_WITH_RC4_40_MD5     -> true
    | TLS_DH_anon_WITH_RC4_128_MD5           -> true
    | TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA  -> true
    | TLS_DH_anon_WITH_DES_CBC_SHA           -> true
    | TLS_DH_anon_WITH_3DES_EDE_CBC_SHA      -> true
    | TLS_DH_anon_WITH_AES_128_CBC_SHA       -> true
    | TLS_DH_anon_WITH_AES_256_CBC_SHA       -> true
    | TLS_ECDH_anon_WITH_NULL_SHA            -> true
    | TLS_ECDH_anon_WITH_RC4_128_SHA         -> true
    | TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA    -> true
    | TLS_ECDH_anon_WITH_AES_128_CBC_SHA     -> true
    | TLS_ECDH_anon_WITH_AES_256_CBC_SHA     -> true
    | _ -> false

let cipherSuiteRequiresKeyExchange cs =
    match cs with
    | TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  -> true
    | TLS_DHE_DSS_WITH_DES_CBC_SHA           -> true
    | TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      -> true
    | TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  -> true
    | TLS_DHE_RSA_WITH_DES_CBC_SHA           -> true
    | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      -> true
    | TLS_DHE_DSS_WITH_AES_128_CBC_SHA       -> true
    | TLS_DHE_RSA_WITH_AES_128_CBC_SHA       -> true
    | TLS_DHE_DSS_WITH_AES_256_CBC_SHA       -> true
    | TLS_DHE_RSA_WITH_AES_256_CBC_SHA       -> true
    | TLS_ECDHE_ECDSA_WITH_NULL_SHA          -> true
    | TLS_ECDHE_ECDSA_WITH_RC4_128_SHA       -> true
    | TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA  -> true
    | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   -> true
    | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   -> true
    | TLS_ECDHE_RSA_WITH_NULL_SHA            -> true
    | TLS_ECDHE_RSA_WITH_RC4_128_SHA         -> true
    | TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA    -> true
    | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     -> true
    | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     -> true
    | _ -> false

let canEncryptPMS cs =
    match cs with
    | TLS_RSA_WITH_NULL_MD5                  -> true
    | TLS_RSA_WITH_NULL_SHA                  -> true
    | TLS_RSA_EXPORT_WITH_RC4_40_MD5         -> true
    | TLS_RSA_WITH_RC4_128_MD5               -> true
    | TLS_RSA_WITH_RC4_128_SHA               -> true
    | TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5     -> true
    | TLS_RSA_WITH_IDEA_CBC_SHA              -> true
    | TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      -> true
    | TLS_RSA_WITH_DES_CBC_SHA               -> true
    | TLS_RSA_WITH_3DES_EDE_CBC_SHA          -> true
    | TLS_RSA_WITH_AES_128_CBC_SHA           -> true
    | TLS_RSA_WITH_AES_256_CBC_SHA           -> true
    | _ -> false