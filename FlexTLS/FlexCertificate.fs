#light "off"

module FlexCertificate

open Tcp
open Bytes
open Error
open TLSInfo

open FlexTypes
open FlexFragment

(* TODO : Below the client ID requires Cert.cert list but I give Cert.chain *)


(* Receive a ServerHello message from the network stream *)
let receiveClientOrServerCertificate (role:Role) (ns:NetworkStream) (st:state) (si:SessionInfo) : state * SessionInfo * FCertificate =
    
        let ct,pv,len = parseFragmentHeader ns in

        match getFragmentContent ns ct len st with
        | Error (ad,x) -> failwith x
        | Correct (rec_in,rg,frag)  ->
            let read_s = {st.read_s with record = rec_in} in
            let st = {st with read_s = read_s} in
            let id = TLSInfo.id st.read_s.epoch in
            let history = Record.history st.read_s.epoch Reader st.read_s.record in
          
            let f = TLSFragment.RecordPlainToHSPlain st.read_s.epoch history rg frag in
            let b = HSFragment.fragmentRepr id rg f in 

            match HandshakeMessages.parseClientOrServerCertificate b with
            | Error (ad,x) -> failwith x
            | Correct (certC) -> 
                let cert = { nullFCertificate with chain = certC; } in
                match role with
                | Client ->
                    let si  = { si with 
                                client_auth = true;
                                clientID = certC;
                    } in
                    (st,si,cert)
                | Server ->
                    let si  = { si with 
                                serverID = certC;
                    } in
                    (st,si,cert)

(* Send a ServerHello message from the network stream *)
