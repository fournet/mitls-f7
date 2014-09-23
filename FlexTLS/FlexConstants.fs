#light "off"

module FlexConstants

open Bytes
open Error
open TLSInfo
open TLSConstants
open CoreKeys

open FlexTypes




type FlexConstants =
    class

    /// <summary> Default TCP port to connect to </summary>
    static member defaultTCPPort = 443

    /// <summary> Define a default ProtocolVersion </summary>
    static member defaultProtocolVersion = TLS_1p2

    /// <summary> Define a default fragmentationPolicy </summary>
    static member defaultFragmentationPolicy = All(fragmentLength)


    /// <summary> All supported algorithms for signatures and HMAC </summary>
    static member sigAlgs_ALL = [(SA_RSA, SHA256);(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL);(SA_DSA, SHA)]

    /// <summary> Algorithms for signatures and HMAC in RSA ciphersuites </summary>
    static member sigAlgs_RSA = [(SA_RSA, SHA256);(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL)]

  
    /// <summary>  Redefine TLSConstants name parsing to handle SCSV ciphersuites </summary>
    static member names_of_cipherSuites css =
        match css with
        | [] -> correct []
        | h::t ->
            if contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV [h] then
                match FlexConstants.names_of_cipherSuites t with
                | Error(x,y) -> Error(x,y)
                | Correct(rem) -> correct(rem)
            else
                match name_of_cipherSuite h with
                | Error(x,y) -> Error(x,y)
                | Correct(n) ->
                    match FlexConstants.names_of_cipherSuites t with
                    | Error(x,y) -> Error(x,y)
                    | Correct(rem) -> correct (n::rem)

    /// <summary>  Diffie Hellman defaults for size and database name </summary>
    static member minDHSize = TLSInfo.defaultConfig.dhPQMinLength
    static member dhdb = DHDB.create "dhparams-db.bin"

    /// <summary>  Null value for CoreKeys.dhparams parameters </summary>
    static member nullDHParams =
        let _,dhp = CoreDH.load_default_params "default-dh.pem" FlexConstants.dhdb FlexConstants.minDHSize in
        dhp

    /// <summary> Define a default DH key exchange parameters structure where x,gx are the local values and gy is the remote public value </summary>
    static member nullKexDH = { 
        pg = (FlexConstants.nullDHParams.dhp,FlexConstants.nullDHParams.dhg);
        x  = empty_bytes;
        gx = empty_bytes;
        gy = empty_bytes;
    }
    
    /// <summary> Define a null FHelloRequest record </summary>
    static member nullFHelloRequest : FHelloRequest = { 
        payload = empty_bytes; 
    }

    /// <summary>  Define a null FClientHello record </summary>
    static member nullFClientHello : FClientHello = {   
        pv = defaultConfig.maxVer;
        rand = empty_bytes; 
        sid = empty_bytes;
        suites = (match FlexConstants.names_of_cipherSuites defaultConfig.ciphersuites with
        | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
        | Correct(s) -> s);
        comps = defaultConfig.compressions;
        ext = [];
        payload = empty_bytes;
    }


    /// <summary>  Define a null FServerHello record </summary>
    static member nullFServerHello : FServerHello = {   
        pv = defaultConfig.maxVer;
        rand = empty_bytes; 
        sid = empty_bytes;
        suite = (match name_of_cipherSuite defaultConfig.ciphersuites.Head with
        | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
        | Correct(cs) -> cs);
        comp = defaultConfig.compressions.Head;
        ext = [];
        payload = empty_bytes;
    }

    /// <summary>  Define a null FCertificate record </summary>
    static member nullFCertificate : FCertificate = {   
        chain = [];
        payload = empty_bytes;
    }

    /// <summary>  Define a null FCertificateRequest record </summary>
    static member nullFCertificateRequest : FCertificateRequest = { 
        certTypes = [RSA_sign; DSA_sign];
        sigAlgs = [];
        names = [];
        payload = empty_bytes;
    }

    /// <summary>  Define a null FCertificateVerify record </summary>
    static member nullFCertificateVerify : FCertificateVerify = { 
        sigAlg = FlexConstants.sigAlgs_RSA.Head;
        signature = empty_bytes;
        payload = empty_bytes;
    }

    /// <summary>  Define a null FServerKeyExchange record for all DH key exchange mechanisms </summary>
    static member nullFServerKeyExchangeDHx : FServerKeyExchange = { 
        sigAlg = FlexConstants.sigAlgs_RSA.Head;
        signature = empty_bytes;
        kex = DH(FlexConstants.nullKexDH);
        payload = empty_bytes;
    }

    /// <summary>  Define a null FServerHelloDone record </summary>
    static member nullFServerHelloDone : FServerHelloDone =  { 
        payload = empty_bytes; 
    }

    /// <summary>  Define a null FClientKeyExchange record for RSA </summary>
    static member nullFClientKeyExchangeRSA : FClientKeyExchange = { 
        kex = RSA(empty_bytes);
        payload = empty_bytes;
    }

    /// <summary>  Define a null FClientKeyExchange record for DHx </summary>
    static member nullFClientKeyExchangeDHx : FClientKeyExchange = { 
        kex = DH(FlexConstants.nullKexDH);
        payload = empty_bytes;
    }

    /// <summary>  Define a null FChangeCipherSpecs record </summary>
    static member nullFChangeCipherSpecs : FChangeCipherSpecs = { 
        payload = HandshakeMessages.CCSBytes; 
    }

    /// <summary>  Define a null FFinished record </summary>
    static member nullFFinished : FFinished = {   
        verify_data = empty_bytes;
        payload = empty_bytes;
    }

    /// <summary>  Define a null SessionInfo record </summary>
    static member nullSessionInfo = {   
        clientID = [];
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

    /// <summary>  Define a null epoch_keys </summary>
    // TODO : Here the key exchange should probably be agnostic instead of using a RSA constructor
    static member nullKeys = {
        kex = RSA(empty_bytes);
        pms = empty_bytes;
        ms = empty_bytes;
        epoch_keys = empty_bytes,empty_bytes;
    }

    /// <summary>  Define a null nextSecurityContext record </summary>
    static member nullNextSecurityContext = {   
        si = FlexConstants.nullSessionInfo;
        crand = empty_bytes;
        srand = empty_bytes;
        keys = FlexConstants.nullKeys;
    }

    end
