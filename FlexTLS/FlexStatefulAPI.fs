#light "off"

module FlexTLS.FlexStatefulAPI

open Bytes
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

    member this.SendClientHello(?fch:FClientHello, ?fp:fragmentationPolicy) : unit =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fch = defaultArg fch FlexConstants.nullFClientHello in
        let st,nsc,fch = FlexClientHello.send(_st,fch=fch,fp=fp) in
        _st  <- st;
        _nsc <- nsc;
        _fch <- fch;
        _log <- _log @| fch.payload

    member this.ReceiveClientHello(?checkVD:bool) : unit =
        let checkVD = defaultArg checkVD true in
        let st,nsc,fch = FlexClientHello.receive(_st,checkVD=checkVD) in
        _st  <- st;
        _nsc <- nsc;
        _fch <- fch;
        _log <- _log @| fch.payload

    member this.SendServerHello(?fsh:FServerHello, ?fp:fragmentationPolicy) : unit =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fsh = defaultArg fsh FlexConstants.nullFServerHello in
        let st,nsc,fsh = FlexServerHello.send(_st,_fch,_nsc,fsh=fsh,fp=fp) in
        _st <- st;
        _nsc <- nsc;
        _log <- _log @| fsh.payload

    member this.ReceiveServerHello() : unit =
        let st,nsc,fsh = FlexServerHello.receive(_st,_fch,nsc=_nsc) in
        _st <- st;
        _nsc <- nsc;
        _log <- _log @| fsh.payload

    // SendCertificate

    member this.ReceiveCertificate(?role:Role) : unit =
        let role = defaultArg role Client in
        let st,nsc,fcert = FlexCertificate.receive(_st,role,_nsc) in
        _st <- st;
        _nsc <- nsc;
        _log <- _log @| fcert.payload

    member this.ReceiveServerHelloDone() : unit = 
        let st,fshd      = FlexServerHelloDone.receive(_st) in
        _st <- st;
        _log <- _log @| fshd.payload

    member this.SendClientKeyExchange(?fp:fragmentationPolicy) : unit = 
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(_st,_nsc,_fch) in
        _st <- st;
        _nsc <- nsc;
        _log <- _log @| fcke.payload

    member this.SendCCS() : unit =
        let st,_ = FlexCCS.send(_st) in
        _st <- st
    
    member this.ReceiveCCS() : unit =
        let st,_,_ = FlexCCS.receive(_st) in
        _st <- st

    member this.SendFinished(?role:Role,?fp:fragmentationPolicy) : unit =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let role = defaultArg role Client in
        let st,ffC = FlexFinished.send(_st,logRoleNSC=(_log,role,_nsc)) in
        _st <- st;
        _log <- _log @| ffC.payload

    member this.ReceiveFinished(?role:Role) : unit =
        let role = defaultArg role Server in
        let st,ffS = FlexFinished.receive(_st,logRoleNSC=(_log,role,_nsc)) in
        _st <- st;
        _log <- _log @| ffS.payload

    end