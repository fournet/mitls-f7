#light "off"

module FlexTLS.FlexConstants

open Bytes
open Error
open TLSInfo
open TLSConstants
open CoreKeys

open FlexTypes




/// <summary>
/// Module for constant values and initialization values
/// </summary>
type FlexConstants =
    class

    /// <summary> EXPERIMENTAL TLS 1.3 Diffie Hellman default negotiated group </summary>
    static member defaultTLS13group = TLSInfo.defaultConfig.negotiableDHGroups.Head

    /// <summary> Default TCP port, used to listen or to connect to </summary>
    static member defaultTCPPort = 443

    /// <summary> Default protocol version </summary>
    static member defaultProtocolVersion = TLS_1p2

    /// <summary> Default fragmentation policy </summary>
    static member defaultFragmentationPolicy = All(fragmentLength)


    /// <summary> All supported signature algorithms </summary>
    static member sigAlgs_ALL = [(SA_RSA, SHA256);(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL);(SA_DSA, SHA)]

    /// <summary> Signature algorithms suitable for RSA ciphersuites </summary>
    static member sigAlgs_RSA = [(SA_RSA, SHA256);(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL)]

    /// <summary> Redefine TLSConstants ciphersuite name parsing to handle SCSV ciphersuites </summary>
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

    /// <summary> Default minimum accepted size for DH parameters </summary>
    static member minDHSize = TLSInfo.defaultConfig.dhPQMinLength

    /// <summary> Default DH database name </summary>
    static member dhdb = DHDB.create "dhparams-db.bin"

    /// <summary> Default DH group </summary>
    static member nullDHParams =
        let _,dhp = CoreDH.load_default_params "default-dh.pem" FlexConstants.dhdb FlexConstants.minDHSize in
        dhp

    /// <summary> Default DH key exchange parameters, with default DH group and empty DH shares </summary>
    static member nullKexDH = { 
        pg = (FlexConstants.nullDHParams.dhp,FlexConstants.nullDHParams.dhg);
        x  = empty_bytes;
        gx = empty_bytes;
        gy = empty_bytes;
    }
    
    /// <summary> Empty HelloRequest message </summary>
    static member nullFHelloRequest : FHelloRequest = { 
        payload = empty_bytes; 
    }

    /// <summary> Default ClientHello message </summary>
    /// <remarks>
    /// Sending this message will produce a client hello with
    /// - Highest supported protocol version
    /// - Fresh client randomness
    /// - Empty session identifier
    /// - Default ciphersuites and compression method
    /// - All extensions enabled by the default configuration
    /// </remarks>
    static member nullFClientHello : FClientHello = {   
        pv = defaultConfig.maxVer;
        rand = empty_bytes; 
        sid = empty_bytes;
        suites = (match FlexConstants.names_of_cipherSuites defaultConfig.ciphersuites with
        | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
        | Correct(s) -> s);
        comps = defaultConfig.compressions;
        ext = None;
        payload = empty_bytes;
    }


    /// <summary> Default ServerHello message </summary>
    /// <remark>
    /// Sending this message together with a filled ClientHello message
    /// will perform some basic negotiation and send a valid ServerHello with
    /// fresh server randomness.
    /// </remarks>
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

    /// <summary> Empty Certificate message </summary>
    static member nullFCertificate : FCertificate = {   
        chain = [];
        payload = empty_bytes;
    }

    /// <summary> Empry CertificateRequest message </summary>
    static member nullFCertificateRequest : FCertificateRequest = { 
        certTypes = [RSA_sign; DSA_sign];
        sigAlgs = [];
        names = [];
        payload = empty_bytes;
    }

    /// <summary> Empty CertificateVerify message </summary>
    static member nullFCertificateVerify : FCertificateVerify = { 
        sigAlg = FlexConstants.sigAlgs_RSA.Head;
        signature = empty_bytes;
        payload = empty_bytes;
    }

    /// <summary> Empty ServerKeyExchange message, for DH key exchange </summary>
    static member nullFServerKeyExchangeDHx : FServerKeyExchange = { 
        sigAlg = FlexConstants.sigAlgs_RSA.Head;
        signature = empty_bytes;
        kex = DH(FlexConstants.nullKexDH);
        payload = empty_bytes;
    }

    /// <summary> Empty FServerHelloDone message </summary>
    static member nullFServerHelloDone : FServerHelloDone =  { 
        payload = empty_bytes; 
    }

    /// <summary> Empty ClientKeyExchange message, for RSA key exchange </summary>
    static member nullFClientKeyExchangeRSA : FClientKeyExchange = { 
        kex = RSA(empty_bytes);
        payload = empty_bytes;
    }

    /// <summary> Empty ClientKeyExchange message, for DH key exchange </summary>
    static member nullFClientKeyExchangeDHx : FClientKeyExchange = { 
        kex = DH(FlexConstants.nullKexDH);
        payload = empty_bytes;
    }

    /// <summary> Default ChangeCipherSpecs message </summary>
    static member nullFChangeCipherSpecs : FChangeCipherSpecs = { 
        payload = HandshakeMessages.CCSBytes; 
    }

    /// <summary> Empty Finished message </summary>
    static member nullFFinished : FFinished = {   
        verify_data = empty_bytes;
        payload = empty_bytes;
    }

    /// <summary> Null SessionInfo </summary>
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

    /// <summary> Null epoch keys </summary>
    //BB TODO : Here the key exchange should probably be agnostic instead of using a RSA constructor
    static member nullKeys = {
        kex = RSA(empty_bytes);
        pms = empty_bytes;
        ms = empty_bytes;
        epoch_keys = empty_bytes,empty_bytes;
    }

    /// <summary> Null next Security Context </summary>
    static member nullNextSecurityContext = {   
        si = FlexConstants.nullSessionInfo;
        crand = empty_bytes;
        srand = empty_bytes;
        keys = FlexConstants.nullKeys;
        offers = [];
    }

    end
