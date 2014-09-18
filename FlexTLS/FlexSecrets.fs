#light "off"

module FlexSecrets

open Bytes
open TLSInfo

open FlexTypes
open FlexConstants




(* Coherce a DH parameter from bytes to DH.secret abstract type *)
let dh_coerce (x:bytes) : DH.secret =
    DH.coerce FlexConstants.nullDHParams empty_bytes x


(* Leak a DH parameter from abstract type *)
let dh_leak (x:DH.secret) : bytes =
    DH.leak FlexConstants.nullDHParams empty_bytes x
    



type FlexSecrets =
    class

    (* Use the key exchange parameters to generate the PreMasterSecret *)
    static member kex_to_pms (kex:kex) : bytes =
        match kex with
        | RSA(pms) -> pms
        | DH(dhp) ->
            let p,_ = dhp.pg in
            let x,gy = dhp.x, dhp.gy in
            CoreDH.agreement p x gy

    (* Use the PreMasterSecret to generate the MasterSecret *)
    static member pms_to_ms (si:SessionInfo) (pms:bytes) : bytes =
        (* It doesn't really matter if we coerce to DH or RSA, as internally
           they're both just bytes. *)
        let apms = PMS.coerceDH FlexConstants.nullDHParams empty_bytes empty_bytes pms in
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

    (* Make verify_data from log and necessary informations *)
    static member makeVerifyData (si:SessionInfo) (ms:bytes) (role:Role) (log:bytes) : bytes =
        let ams = PRF.coerce (msi si) ms in
        PRF.makeVerifyData si ams role log
        
    (* Generate secrets from the Key Exchange data and fill the next security context.
       It is assumed that the nsc.kex field is already set to the desired value.
       Any user-provided value will not be overwritten; instead it will be used for secrets generation. *)
    static member fillSecrets (st:state, role:Role, nsc:nextSecurityContext) : nextSecurityContext =

        let er = TLSInfo.nextEpoch st.read.epoch  nsc.crand nsc.srand nsc.si in
        let ew = TLSInfo.nextEpoch st.write.epoch nsc.crand nsc.srand nsc.si in
        
        let pms =
            if nsc.keys.pms = empty_bytes then
                FlexSecrets.kex_to_pms nsc.keys.kex
            else
                nsc.keys.pms
        in

        let ms = if nsc.keys.ms = empty_bytes then FlexSecrets.pms_to_ms nsc.si pms else nsc.keys.ms in
        let keys = if nsc.keys.epoch_keys = (empty_bytes,empty_bytes) then FlexSecrets.ms_to_keys er ew role ms else nsc.keys.epoch_keys in
        let epk = {nsc.keys with pms = pms; ms = ms; epoch_keys = keys} in
        { nsc with keys = epk }

    end
