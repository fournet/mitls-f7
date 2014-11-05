#light "off"

module FlexTLS.FlexStatefulAPI

open Bytes
open Error
open TLSInfo

open FlexTypes
open FlexConstants
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished




type FlexStatefulAPI(st:FlexTypes.state) =
    class

    let mutable _st = st
    let mutable _nsc = FlexConstants.nullNextSecurityContext
    let mutable _fch = FlexConstants.nullFClientHello
    let mutable _log = empty_bytes

    /// <summary>
    /// Send a Client Hello message
    /// </summary>
    /// <param name="fch"> User provided ClientHello message </param>
    /// <param name="fp"> Fragmentation policy </param>
    member this.SendClientHello(?fch:FClientHello, ?fp:fragmentationPolicy) : unit =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fch = defaultArg fch FlexConstants.nullFClientHello in
        let st,nsc,fch = FlexClientHello.send(_st,fch=fch,fp=fp) in
        _st  <- st;
        _nsc <- nsc;
        _fch <- fch;
        _log <- _log @| fch.payload

    /// <summary>
    /// Receive a Client Hello message
    /// </summary>
    /// <param name="checkVD"> Enforce check of the verify data if renegotiation indication extension is present (default: true) </param>
    member this.ReceiveClientHello(?checkVD:bool) : unit =
        let checkVD = defaultArg checkVD true in
        let st,nsc,fch = FlexClientHello.receive(_st,checkVD=checkVD) in
        _st  <- st;
        _nsc <- nsc;
        _fch <- fch;
        _log <- _log @| fch.payload

    /// <summary>
    /// Send a Server Hello message
    /// </summary>
    /// <param name="fsh"> User provided ServerHello message </param>
    /// <param name="fp"> Fragmentation policy </param>
    member this.SendServerHello(?fsh:FServerHello, ?fp:fragmentationPolicy) : unit =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fsh = defaultArg fsh FlexConstants.nullFServerHello in
        let st,nsc,fsh = FlexServerHello.send(_st,_fch,_nsc,fsh=fsh,fp=fp) in
        _st <- st;
        _nsc <- nsc;
        _log <- _log @| fsh.payload

    /// <summary>
    /// Receive a Server Hello message
    /// </summary>
    member this.ReceiveServerHello() : unit =
        let st,nsc,fsh = FlexServerHello.receive(_st,_fch,nsc=_nsc) in
        _st <- st;
        _nsc <- nsc;
        _log <- _log @| fsh.payload

    /// <summary>
    /// Send a Certificate message
    /// </summary>
    /// <param name="role"> Role we use for the certificate (Default to Server) </param>
    /// <param name="cn"> Common name to search for certificate chain and private key </param>
    member this.SendCertificate(?role:Role,?cn:string) : unit =
        let role = defaultArg role Server in
        let cn = defaultArg cn "" in
        match Cert.for_key_encryption FlexConstants.sigAlgs_RSA cn with
        | None -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Private key not found for the given CN: %s" cn))
        | Some(chain,sk) ->
            let st,nsc,fcert = FlexCertificate.send(_st,role,chain,_nsc) in
            _st <- st;
            _nsc <- nsc;
            _log <- _log @| fcert.payload

    /// <summary>
    /// Receive Certificate for Stateful API
    /// </summary>
    /// <param name="role"> Role we use for the certificate (Default to Client) </param>
    member this.ReceiveCertificate(?role:Role) : unit =
        let role = defaultArg role Client in
        let st,nsc,fcert = FlexCertificate.receive(_st,role,_nsc) in
        _st <- st;
        _nsc <- nsc;
        _log <- _log @| fcert.payload
    
    /// <summary>
    /// Send Server Hello Done for Stateful API
    /// </summary>
    member this.SendServerHelloDone() : unit =
        let st,fshd = FlexServerHelloDone.send(_st) in
        _st <- st;
        _log <- _log @| fshd.payload

    /// <summary>
    /// Receive Server Hello Done for Stateful API
    /// </summary>
    member this.ReceiveServerHelloDone() : unit = 
        let st,fshd      = FlexServerHelloDone.receive(_st) in
        _st <- st;
        _log <- _log @| fshd.payload

    /// <summary>
    /// Send Client Key Exchange RSA for Stateful API
    /// </summary>
    /// <param name="fp"> Fragmentation policy </param>
    member this.SendClientKeyExchangeRSA(?fp:fragmentationPolicy) : unit = 
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(_st,_nsc,_fch) in
        _st <- st;
        _nsc <- nsc;
        _log <- _log @| fcke.payload

    /// <summary>
    /// Receive Client Key Exchange RSA for Stateful API
    /// </summary>
    /// <param name="cn"> Common name to search for private key </param>
    member this.ReceiveClientKeyExchangeRSA(?cn:string) : unit =
        let cn = defaultArg cn "" in
        match Cert.for_key_encryption FlexConstants.sigAlgs_RSA cn with
        | None -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Private key not found for the given CN: %s" cn))
        | Some(chain,sk) ->
            let st,nsc,fcke  = FlexClientKeyExchange.receiveRSA(_st,_nsc,_fch,sk=sk) in
            _st <- st;
            _nsc <- nsc;
            _log <- _log @| fcke.payload

    /// <summary>
    /// Send a CCS message for Stateful API
    /// </summary>
    member this.SendCCS() : unit =
        let st,_ = FlexCCS.send(_st) in
        _st <- st
    
    /// <summary>
    /// Receive a CCS message for Stateful API
    /// </summary>
    member this.ReceiveCCS() : unit =
        let st,_,_ = FlexCCS.receive(_st) in
        _st <- st
    
    /// <summary>
    /// Send Finished message for StatefulAPI
    /// </summary>
    /// <param name="role"> Role we use to compute the log (Default to Client) </param>
    /// <param name="fp"> Fragmentation policy </param>
    member this.SendFinished(?role:Role,?fp:fragmentationPolicy) : unit =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let role = defaultArg role Client in
        let st,ffC = FlexFinished.send(_st,logRoleNSC=(_log,role,_nsc)) in
        _st <- st;
        _log <- _log @| ffC.payload

    /// <summary>
    /// Receive Finished messages for StatefulAPI
    /// </summary>
    /// <param name="role"> Role we use to compute the log (Default to Server) </param>
    member this.ReceiveFinished(?role:Role) : unit =
        let role = defaultArg role Server in
        let st,ffS = FlexFinished.receive(_st,logRoleNSC=(_log,role,_nsc)) in
        _st <- st;
        _log <- _log @| ffS.payload

    end