#light "off"

module FlexTLS.FlexStatefulAPI

open Bytes

open FlexTypes
open FlexConstants
open FlexClientHello
open FlexServerHello

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

    end