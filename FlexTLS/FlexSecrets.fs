#light "off"

module FlexSecrets

open Bytes
open Error
open TLSInfo

open FlexTypes
open FlexConstants

type FlexSecrets =
    class

    // TODO: static member dh_to_pms kexDH    : bytes =
    // TODO: static member dh_to_pms g p x gy : bytes =

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

    static member makeVerifyData (si:SessionInfo) (ms:bytes) (role:Role) (log:bytes) : bytes =
        let ms = PRF.coerce (msi si) ms in
        PRF.makeVerifyData si ms role log

    (* Fills un-set secret.
       For RSA: at least the PMS must be provided;
       For DHE: at least the DH parameters and keys must be provided *)
    (* TODO, if we ever need it
    static member fillNSCSecrets (nsc:nextSecurityContext) (role:Role): nextSecurityContext =
        // set PMS
        let nsc =
            if nsc.pms = nullNextSecurityContext.pms then
                match nsc.kex with
                | RSA -> failwith (perror __SOURCE_FILE__ __LINE__ "For RSA, at least the PMS must be provided")
                | DH(dhkex) -> failwith "TODO"
            else
                nsc
        in
        // set MS
        let nsc =
            if nsc.ms = nullNextSecurityContext.ms then
                {nsc with ms = FlexSecrets.pms_to_ms nsc.si nsc.pms}
            else
                nsc
        in
        // set keys
        let nsc =
            if nsc.keys = nullNextSecurityContext.keys then
                let er = TLSInfo.nextEpoch // I don't have the current epoch!!!
                let keys = FlexSecrets.ms_to_keys er ew role nsc.ms in
                {nsc with keys = keys}
            else
                nsc
        in
        nsc
    *)
    end

