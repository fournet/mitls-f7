#light "off"

module FlexTLS.FlexStatefulAPI

open Bytes
open Error
open TLSInfo

open FlexTypes
open FlexConstants
open FlexState
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished

type FlexStatefulAPI(st:FlexTypes.state,r:Role,?cfg:config) =
    class

    /// <summary> State of the connection </summary>
    member val st  = st                                    with get,set
    /// <summary> Intended role </summary>
    member val r   = r                                     with get,set
    /// <summary> Protocol configuration options </summary>
    member val cfg = defaultArg cfg TLSInfo.defaultConfig  with get,set
    /// <summary> Next security context (session keys and parameters) that this handshake is negotiating </summary>
    member val nsc = FlexConstants.nullNextSecurityContext with get,set
    /// <summary> The most recent client hello sent or received </summary>
    member val fch = FlexConstants.nullFClientHello        with get,set
    /// <summary> The log, built incrementally for every sent/received message </summary>
    member val log = empty_bytes                           with get,set

    /// <summary>
    /// Send a Client Hello message
    /// </summary>
    /// <param name="fch"> User provided ClientHello message </param>
    /// <param name="fp"> Fragmentation policy </param>
    member this.SendClientHello(?fch:FClientHello, ?fp:fragmentationPolicy) : unit =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fch = defaultArg fch FlexConstants.nullFClientHello in
        let st,nsc,fch = FlexClientHello.send(this.st,fch=fch,cfg=this.cfg,fp=fp) in
        this.st  <- st;
        this.nsc <- nsc;
        this.fch <- fch;
        this.log <- this.log @| fch.payload

    /// <summary>
    /// Receive a Client Hello message
    /// </summary>
    /// <param name="checkVD"> Enforce check of the verify data if renegotiation indication extension is present (default: true) </param>
    member this.ReceiveClientHello(?checkVD:bool) : unit =
        let checkVD = defaultArg checkVD true in
        let st,nsc,fch = FlexClientHello.receive(this.st,checkVD=checkVD) in
        this.st  <- st;
        this.nsc <- nsc;
        this.fch <- fch;
        this.log <- this.log @| fch.payload

    /// <summary>
    /// Send a Server Hello message
    /// </summary>
    /// <param name="fsh"> User provided ServerHello message </param>
    /// <param name="fp"> Fragmentation policy </param>
    member this.SendServerHello(?fsh:FServerHello, ?fp:fragmentationPolicy) : unit =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fsh = defaultArg fsh FlexConstants.nullFServerHello in
        let st,nsc,fsh = FlexServerHello.send(this.st,this.fch,this.nsc,fsh=fsh,cfg=this.cfg,fp=fp) in
        this.st <- st;
        this.nsc <- nsc;
        this.log <- this.log @| fsh.payload

    /// <summary>
    /// Receive a Server Hello message
    /// </summary>
    member this.ReceiveServerHello() : unit =
        let st,nsc,fsh = FlexServerHello.receive(this.st,this.fch,nsc=this.nsc) in
        this.st <- st;
        this.nsc <- nsc;
        this.log <- this.log @| fsh.payload

    /// <summary>
    /// Send a Certificate message
    /// </summary>
    /// <param name="role"> Role we use for the certificate (Default to Server) </param>
    /// <param name="cn"> Common name to search for certificate chain and private key </param>
    /// <param name="fp"> Fragmentation policy </param>
    member this.SendCertificate(?role:Role,?cn:string, ?fp:fragmentationPolicy) : unit =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let role = defaultArg role Server in
        let cn = defaultArg cn "" in
        match Cert.for_key_encryption FlexConstants.sigAlgs_RSA cn with
        | None -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Private key not found for the given CN: %s" cn))
        | Some(chain,sk) ->
            let st,nsc,fcert = FlexCertificate.send(this.st,role,chain,this.nsc,fp=fp) in
            this.st <- st;
            this.nsc <- nsc;
            this.log <- this.log @| fcert.payload

    /// <summary>
    /// Receive Certificate for Stateful API
    /// </summary>
    /// <param name="role"> Role we use for the certificate (Default to Client) </param>
    member this.ReceiveCertificate(?role:Role) : unit =
        let role = defaultArg role Client in
        let st,nsc,fcert = FlexCertificate.receive(this.st,role,this.nsc) in
        this.st <- st;
        this.nsc <- nsc;
        this.log <- this.log @| fcert.payload
    
    /// <summary>
    /// Send Server Hello Done for Stateful API
    /// </summary>
    member this.SendServerHelloDone() : unit =
        let st,fshd = FlexServerHelloDone.send(this.st) in
        this.st <- st;
        this.log <- this.log @| fshd.payload

    /// <summary>
    /// Receive Server Hello Done for Stateful API
    /// </summary>
    member this.ReceiveServerHelloDone() : unit = 
        let st,fshd      = FlexServerHelloDone.receive(this.st) in
        this.st <- st;
        this.log <- this.log @| fshd.payload

    /// <summary>
    /// Send Client Key Exchange RSA for Stateful API
    /// </summary>
    /// <param name="fp"> Fragmentation policy </param>
    member this.SendClientKeyExchangeRSA(?fp:fragmentationPolicy) : unit = 
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(this.st,this.nsc,this.fch,fp=fp) in
        this.st <- st;
        this.nsc <- nsc;
        this.log <- this.log @| fcke.payload

    /// <summary>
    /// Receive Client Key Exchange RSA for Stateful API
    /// </summary>
    /// <param name="cn"> Common name to search for private key </param>
    member this.ReceiveClientKeyExchangeRSA(?cn:string) : unit =
        let cn = defaultArg cn "" in
        match Cert.for_key_encryption FlexConstants.sigAlgs_RSA cn with
        | None -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Private key not found for the given CN: %s" cn))
        | Some(chain,sk) ->
            let st,nsc,fcke  = FlexClientKeyExchange.receiveRSA(this.st,this.nsc,this.fch,sk=sk) in
            this.st <- st;
            this.nsc <- nsc;
            this.log <- this.log @| fcke.payload

    /// <summary>
    /// Send a CCS message for Stateful API
    /// </summary>
    member this.SendCCS() : unit =
        let st,_ = FlexCCS.send(this.st) in
        let st = FlexState.installWriteKeys this.st this.nsc in
        this.st <- st
    
    /// <summary>
    /// Receive a CCS message for Stateful API
    /// </summary>
    member this.ReceiveCCS() : unit =
        let st,_,_ = FlexCCS.receive(this.st) in
        let st = FlexState.installReadKeys this.st this.nsc in
        this.st <- st
    
    /// <summary>
    /// Send Finished message for StatefulAPI
    /// </summary>
    /// <param name="fp"> Fragmentation policy </param>
    member this.SendFinished(?fp:fragmentationPolicy) : unit =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let st,ffC = FlexFinished.send(this.st,this.nsc,role=this.r,fp=fp) in
        this.st <- st;
        this.log <- this.log @| ffC.payload

    /// <summary>
    /// Receive Finished messages for StatefulAPI
    /// </summary>
    member this.ReceiveFinished() : unit =
        let st,ffS = FlexFinished.receive(this.st,this.nsc,role=this.r) in // FIXME: dual role!
        this.st <- st;
        this.log <- this.log @| ffS.payload

    end