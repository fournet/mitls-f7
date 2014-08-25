#light "off"

module FlexAttacks

open Bytes
open TLSError

open FlexTypes
open FlexConstants
open FlexState
open FlexAlert
open FlexClientHello
open FlexServerHello




type FlexAttacks =
    class

    (* Alert attack inside the first handshake *)
    static member runAlertPlaintextAttack (st:state) : state =
        let st,nsc,fch = FlexClientHello.send(st) in
        let st,nsc,fsh = FlexServerHello.receive(st,nsc) in
        let st = FlexAlert.send(st,AD_close_notify,fp=One(1)) in
        let st = FlexState.updateOutgoingAlertBuffer st empty_bytes in
        FlexAlert.send(st,AD_close_notify)

    end
