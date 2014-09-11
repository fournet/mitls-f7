#light "off"

module FlexConstants

open Bytes
open System
open Error
open TLSError
open TLSInfo
open TLSConstants
open CoreKeys

open FlexTypes


type FlexConstants =
    class

    (* Default TCP port to connect to *)
    static member defaultTCPPort = 443

    (* Define a default ProtocolVersion *)
    static member defaultProtocolVersion = TLS_1p2

    (* Define a default fragmentationPolicy *)
    static member defaultFragmentationPolicy = All(fragmentLength)


    (* All supported algorithms for signatures and HMAC *)
    static member sigAlgs_ALL = [(SA_RSA, SHA256);(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL);(SA_DSA, SHA)]

    (* Algorithms for signatures and HMAC in RSA ciphersuites *)
    static member sigAlgs_RSA = [(SA_RSA, SHA256);(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL)]

  
    (* Redefine TLSConstants name parsing to handle SCSV ciphersuites *)
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

    static member minDHSize = TLSInfo.defaultConfig.dhPQMinLength
    static member dhdb = DHDB.create "dhparams-db.bin"

    (* Null value for CoreKeys.dhparams parameters *)
    static member nullDHParams =
        let _,dhp = CoreDH.load_default_params "default-dh.pem" FlexConstants.dhdb FlexConstants.minDHSize in
        dhp

    (* Define a default DH key exchange parameters structure where x,gx are the local values and gy is the remote public value *)
    static member nullKexDH = { 
        pg = (FlexConstants.nullDHParams.dhp,FlexConstants.nullDHParams.dhg);
        x  = empty_bytes;
        gx = empty_bytes;
        gy = empty_bytes;
    }
    
    (* Define a null FHelloRequest record *)
    static member nullFHelloRequest : FHelloRequest = { 
        payload = empty_bytes; 
    }

    (* Define a null FClientHello record *)
    static member nullFClientHello : FClientHello = {   
        pv = defaultConfig.maxVer;
        rand = empty_bytes; 
        sid = empty_bytes;
        suites = (match FlexConstants.names_of_cipherSuites defaultConfig.ciphersuites with
        | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
        | Correct(s) -> s);
        comps = defaultConfig.compressions;
        ext = empty_bytes;
        payload = empty_bytes;
    }


    (* Define a null FServerHello record *)
    static member nullFServerHello : FServerHello = {   
        pv = defaultConfig.maxVer;
        rand = empty_bytes; 
        sid = empty_bytes;
        suite = (match name_of_cipherSuite defaultConfig.ciphersuites.Head with
        | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
        | Correct(cs) -> cs);
        comp = defaultConfig.compressions.Head;
        ext = empty_bytes;
        payload = empty_bytes;
    }

    (* Define a null FCertificate record *)
    static member nullFCertificate : FCertificate = {   
        chain = [];
        payload = empty_bytes;
    }

    (* Define a null FCertificateRequest record *)
    // FIXME: We may find better defaults for this, once CertificateRequest generation is improved
    static member nullFCertificateRequest : FCertificateRequest = { 
        certTypes = [RSA_sign; DSA_sign];
        sigAlgs = [];
        names = [];
        payload = empty_bytes;
    }

    (* Define a null FCertificateVerify record *)
    static member nullFCertificateVerify : FCertificateVerify = { 
        sigAlg = FlexConstants.sigAlgs_RSA.Head;
        signature = empty_bytes;
        payload = empty_bytes;
    }

    (* Define a null FServerKeyExchange record for all DH key exchange mechanisms *)
    static member nullFServerKeyExchangeDHx : FServerKeyExchange = { 
        sigAlg = FlexConstants.sigAlgs_RSA.Head;
        signature = empty_bytes;
        kex = DH(FlexConstants.nullKexDH);
        payload = empty_bytes;
    }

    (* Define a null FServerHelloDone record *)
    static member nullFServerHelloDone : FServerHelloDone =  { 
        payload = empty_bytes; 
    }

    (* Define a null FClientKeyExchange record for RSA *)
    static member nullFClientKeyExchangeRSA : FClientKeyExchange = { 
        kex = RSA(empty_bytes);
        payload = empty_bytes;
    }

    (* Define a null FClientKeyExchange record for DHx *)
    static member nullFClientKeyExchangeDHx : FClientKeyExchange = { 
        kex = DH(FlexConstants.nullKexDH);
        payload = empty_bytes;
    }

    (* Define a null FChangeCipherSpecs record *)
    static member nullFChangeCipherSpecs : FChangeCipherSpecs = { 
        payload = HandshakeMessages.CCSBytes; 
    }

    (* Define a null FFinished record *)
    static member nullFFinished : FFinished = {   
        verify_data = empty_bytes;
        payload = empty_bytes;
    }

    (* Define a null FHSMessages record *)
    static member nullFHSMessages = {   
        helloRequest = FlexConstants.nullFHelloRequest;
        clientHello = FlexConstants.nullFClientHello;
        serverHello = FlexConstants.nullFServerHello;
        serverCertificate = FlexConstants.nullFCertificate;
        certificateRequest = FlexConstants.nullFCertificateRequest;
        clientCertificate = FlexConstants.nullFCertificate;
        serverKeyExchange = FlexConstants.nullFServerKeyExchangeDHx;
        serverHelloDone = FlexConstants.nullFServerHelloDone;
        certificateVerify = FlexConstants.nullFCertificateVerify;
        clientKeyExchange = FlexConstants.nullFClientKeyExchangeRSA; //could be DHx
        clientChangeCipherSpecs = FlexConstants.nullFChangeCipherSpecs;
        serverChangeCipherSpecs = FlexConstants.nullFChangeCipherSpecs;
        clientFinished = FlexConstants.nullFFinished;
        serverFinished = FlexConstants.nullFFinished;
    }

    (* Define a null SessionInfo record *)
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

    (* Define a null nextSecurityContext record *)
    static member nullNextSecurityContext = {   
        si = FlexConstants.nullSessionInfo;
        crand = empty_bytes;
        srand = empty_bytes;
        kex = RSA(empty_bytes);
        pms = empty_bytes;
        ms = empty_bytes;
        keys = empty_bytes,empty_bytes;
    }

    end
