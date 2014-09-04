#light "off"

module FlexSecrets

open Bytes
open Error
open TLSInfo

open FlexTypes
open FlexConstants




type FlexSecrets =
    class

    (* Convert DH secret parameter from abstract type to concrete bytes *)
    static member adh_to_dh (p:DHGroup.p) (g:DHGroup.g) (gx:DHGroup.elt) (adh:DH.secret) : bytes =
        DH.leak p g gx adh
       
    (* Convert DH secret parameter from concrete bytes to an abstract type *)
    static member dh_to_adh (p:DHGroup.p) (g:DHGroup.g) (gx:DHGroup.elt) (dh:bytes) : DH.secret =
        DH.coerce p g gx dh


    (* Use the DH parameters to generate the PreMasterSecret *)
    static member kex_to_pms (kexdh:kexDH) : bytes =
        let g,p = kexdh.gp in
        let x,gy = kexdh.x, kexdh.gy in
        let dhp : CoreKeys.dhparams = {g = g; p = p; q=None} in
        CoreDH.agreement dhp x gy 

    (* Use the DH parameters to generate the PreMasterSecret *)
    static member dh_to_pms (g:bytes) (p:bytes) (x:bytes) (gy:bytes) : bytes =
        let dhp : CoreKeys.dhparams = {g = g; p = p; q=None} in
        CoreDH.agreement dhp x gy 
        //let dhpms = DH.serverExp p g gx gy x in
        //let pms = PMS.DHPMS(p,g,gx,y,dhpms) in


    (* Use the PreMasterSecret to generate the MasterSecret *)
    static member pms_to_ms (si:SessionInfo) (pms:bytes) : bytes =
        (* It doesn't really matter if we coerce to DH or RSA, as internally
           they're both just bytes. *)
        let apms = PMS.coerceDH empty_bytes empty_bytes empty_bytes empty_bytes pms in
        let pms =
            let eb = empty_bytes in
            PMS.DHPMS(eb,eb,eb,eb,apms) in
        let ams = KEF.extract si pms in
        PRF.leak (msi si) ams

    (* Use the MasterSecret to generate the Keys. Returns (read, write) keys. *)
    static member ms_to_keys (er:epoch) (ew:epoch) (role:Role) (ms:bytes) : bytes * bytes =
        let ams = PRF.coerce (msi (epochSI er)) ms in
        let ark,awk = PRF.deriveKeys (TLSInfo.id er) (TLSInfo.id ew) ams role in
        let rk = StatefulLHAE.LEAK (TLSInfo.id er) TLSInfo.Reader ark in
        let wk = StatefulLHAE.LEAK (TLSInfo.id ew) TLSInfo.Writer awk in
        rk,wk


    (* Get abstract typed master secret from bytes and session info *)
    static member ms_to_ams (ms:bytes) (si:SessionInfo) : PRF.masterSecret = 
        PRF.coerce (msi si) ms

    (* Get abstract typed master secret from bytes and session info *)
    static member ams_to_ms (ams:PRF.masterSecret) (si:SessionInfo) : bytes =
        PRF.leak (msi si) ams


    (* Make verify_data from log and necessary informations *)
    static member makeVerifyData (si:SessionInfo) (ms:bytes) (role:Role) (log:bytes) : bytes =
        let ams = FlexSecrets.ms_to_ams ms si in
        PRF.makeVerifyData si ams role log


    (* Generate secrets from the Key Exchange data and fill the next security context *)
    static member fillSecrets (st:state, role:Role, nsc:nextSecurityContext, kex:kex) : nextSecurityContext =

        let er = TLSInfo.nextEpoch st.read.epoch  nsc.crand nsc.srand nsc.si in
        let ew = TLSInfo.nextEpoch st.write.epoch nsc.crand nsc.srand nsc.si in

        let pms = 
            match kex with
            | RSA(pms)  -> pms
            | DH(kexdh) -> FlexSecrets.kex_to_pms kexdh
        in

        let ms = FlexSecrets.pms_to_ms nsc.si pms in
        let keys = FlexSecrets.ms_to_keys er ew role ms in
        
        // Here the kex provided also updates the next security context
        { nsc with pms = pms; ms = ms; keys = keys; kex = kex }

    end
