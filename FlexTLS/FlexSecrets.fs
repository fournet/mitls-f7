#light "off"

module FlexSecrets

open NLog

open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTypes
open FlexConstants




/// <summary>
/// Coherce a DH parameter from bytes to DH.secret abstract type
/// </summary>
/// <param name="x"> Bytes of the DH parameter </param>
/// <returns> Abstract DH parameter </returns>
let dh_coerce (x:bytes) : DH.secret =
    DH.coerce FlexConstants.nullDHParams empty_bytes x


/// <summary>
/// Leak a DH parameter from DH.secret abstract type to bytes
/// </summary>
/// <param name="x"> Abstract DH parameter </param>
/// <returns>  DH parameter bytes </returns>
let dh_leak (x:DH.secret) : bytes =
    DH.leak FlexConstants.nullDHParams empty_bytes x
    



/// <summary>
/// Module dealing with computations on secret data.
/// </summary>
type FlexSecrets =
    class

    /// <summary>
    /// Generate the PreMasterSecret from the key exchange parameters
    /// </summary>
    /// <param name="kex"> Key Exchange record </param>
    /// <returns>  PreMasterSecret bytes </returns>
    static member kex_to_pms (kex:kex) : bytes =
        match kex with
        | RSA(pms) -> pms
        | DH(dhp) ->
            let p,_ = dhp.pg in
            CoreDH.agreement p dhp.x dhp.gy
        | DH13(dh13) -> 
            let dhparams = dhgroup_to_dhparams dh13.group in
            CoreDH.agreement dhparams.dhp dh13.x dh13.gy

    /// <summary>
    /// Generate the MasterSecret from the PreMasterSecret
    /// </summary>
    /// <param name="pms"> PreMasterSecret bytes  </param>
    /// <returns>  MasterSecret bytes </returns>
    static member pms_to_ms (si:SessionInfo) (pms:bytes) : bytes =
        (* It doesn't really matter if we coerce to DH or RSA, as internally
           they're both just bytes. *)
        let apms = PMS.coerceDH FlexConstants.nullDHParams empty_bytes empty_bytes pms in
        let pms =
            let eb = empty_bytes in
            PMS.DHPMS(eb,eb,eb,eb,apms) in
        let ams = KEF.extract si pms in
        PRF.leak (msi si) ams

    /// <summary>
    /// Generate all Keys from the MasterSecret and swap them in the proper order using the role
    /// </summary>
    /// <param name="er"> Next reading epoch </param>
    /// <param name="ew"> Next writing epoch </param>
    /// <param name="role"> Behaviour as client or Server </param>
    /// <returns>  Reading keys bytes * Writing keys bytes </returns>
    static member ms_to_keys (er:epoch) (ew:epoch) (role:Role) (ms:bytes) : bytes * bytes =
        let ams = PRF.coerce (msi (epochSI er)) ms in
        let ark,awk = PRF.deriveKeys (TLSInfo.id er) (TLSInfo.id ew) ams role in
        let rk = StatefulLHAE.LEAK (TLSInfo.id er) TLSInfo.Reader ark in
        let wk = StatefulLHAE.LEAK (TLSInfo.id ew) TLSInfo.Writer awk in
        rk,wk

    /// <summary>
    /// Compute verify_data from log and necessary informations
    /// </summary>
    /// <param name="si"> Next session info being negociated </param>
    /// <param name="ms"> MasterSecret bytes </param>
    /// <param name="role"> Behaviour as client or Server </param>
    /// <param name="log"> Log of the current Handshake messages </param>
    /// <returns> Verify_data bytes </returns>
    static member makeVerifyData (si:SessionInfo) (ms:bytes) (role:Role) (log:bytes) : bytes =
        let ams = PRF.coerce (msi si) ms in
        PRF.makeVerifyData si ams role log
        
    /// <summary>
    /// Generate secrets from the Key Exchange data and fill the next security context.
    /// It is assumed that the nsc.kex field is already set to the desired value.
    /// Any user-provided value will not be overwritten; instead it will be used for secrets generation.
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="role"> Behaviour as client or Server </param>
    /// <param name="nsc"> Next security context being negociated </param>
    /// <returns> Updated next security context </returns>
    static member fillSecrets (st:state, role:Role, nsc:nextSecurityContext) : nextSecurityContext =
        LogManager.GetLogger("file").Debug("@ Fill Secrets");
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
        let rkeys,wkeys = keys in
        let epk = {nsc.keys with pms = pms; ms = ms; epoch_keys = keys} in
        LogManager.GetLogger("file").Debug(sprintf "--- Pre Master Secret : %A" (Bytes.hexString(pms)));
        LogManager.GetLogger("file").Debug(sprintf "--- Master Secret : %A" (Bytes.hexString(ms)));
        LogManager.GetLogger("file").Debug(sprintf "--- Reading Keys : %A" (Bytes.hexString(rkeys)));
        LogManager.GetLogger("file").Debug(sprintf "--- Writing Keys : %A" (Bytes.hexString(wkeys)));
        { nsc with keys = epk }

    end
