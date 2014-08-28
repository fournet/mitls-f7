#light "off"

module FlexSecrets

open Bytes
open TLSInfo

open FlexTypes




type FlexSecrets =
    class

    (* Use the PreMasterSecret to generate the MasterSecret *)
    static member pms_to_ms (pms:bytes) (si:SessionInfo) : bytes =
        let apms = PMS.coerceDH empty_bytes empty_bytes empty_bytes empty_bytes pms in
        let pms =
            let eb = empty_bytes in
            PMS.DHPMS(eb,eb,eb,eb,apms) in
        let ams = KEF.extract si pms in
        PRF.leak (msi si) ams

    (* Use the MasterSecret to generate the Keys *)
    static member ms_to_keys (st:state) (ms:bytes) (si:SessionInfo) (role:Role) : bytes * bytes =
        let ams = PRF.coerce (msi si) ms in
        let aread,awrite = PRF.deriveKeys (TLSInfo.id st.read.epoch) (TLSInfo.id st.write.epoch) ams role in
        let rk = StatefulLHAE.LEAK (TLSInfo.id st.read.epoch) TLSInfo.Reader aread in
        let wk = StatefulLHAE.LEAK (TLSInfo.id st.read.epoch) TLSInfo.Writer awrite in
        rk,wk

    end

