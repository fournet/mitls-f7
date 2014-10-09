#light "off"
/// <summary>
/// Module handling the application state.
/// </summary>
module FlexTLS.FlexState

open NLog

open Bytes
open TLSInfo

open FlexTypes



/// <summary>
/// Module handling the application state.
/// </summary>
type FlexState =
    class

    /// <summary> Update the state with a new incoming record </summary>
    static member updateIncomingRecord (st:state) (incoming:Record.recvState) : state =
        let read_s = {st.read with record = incoming} in
        {st with read = read_s}

    /// <summary> Update the state with a new epoch </summary>
    static member updateIncomingEpoch (st:state) (e:TLSInfo.epoch) : state =
        let read_s = {st.read with epoch = e} in
        {st with read = read_s}

    /// <summary> Update the state with new keys </summary>
    static member updateIncomingKeys (st:state) (keys:keys) : state =
        let read_s = {st.read with keys = keys} in
        {st with read = read_s}

    /// <summary> Update the state initial epoch protocol version </summary>
    static member updateIncomingRecordEpochInitPV (st:state) (pv:TLSConstants.ProtocolVersion) : state =
        let read_s = {st.read with epoch_init_pv = pv} in
        {st with read = read_s}

    /// <summary> Update the state with a new Handshake buffer value </summary>
    static member updateIncomingHSBuffer (st:state) (buf:bytes) : state =
        let read_s = {st.read with hs_buffer = buf} in
        {st with read = read_s}

    /// <summary> Update the state with a new Alert buffer value </summary>
    static member updateIncomingAlertBuffer (st:state) (buf:bytes) : state =
        let read_s = {st.read with alert_buffer = buf} in
        {st with read = read_s}

    /// <summary> Update the state with a new Application Data buffer value </summary>
    static member updateIncomingAppDataBuffer (st:state) (buf:bytes) : state =
        let read_s = {st.read with appdata_buffer = buf} in
        {st with read = read_s}

    /// <summary> Update the state with a new buffer value for a specific content type </summary>
    static member updateIncomingBuffer st ct buf =
        match ct with
        | TLSConstants.Alert -> FlexState.updateIncomingAlertBuffer st buf
        | TLSConstants.Handshake -> FlexState.updateIncomingHSBuffer st buf
        | TLSConstants.Application_data -> FlexState.updateIncomingAppDataBuffer st buf
        | TLSConstants.Change_cipher_spec -> st

    /// <summary>
    /// Install Reading Keys into the current state
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Next security context being negociated </param>
    /// <returns> Updated state </returns>
    static member installReadKeys (st:state) (nsc:nextSecurityContext): state =
        LogManager.GetLogger("file").Debug("@ Install Read Keys");
        let nextEpoch = TLSInfo.nextEpoch st.read.epoch nsc.crand nsc.srand nsc.si in
        let rk,_ = nsc.keys.epoch_keys in
        let ark = StatefulLHAE.COERCE (id nextEpoch) TLSInfo.Reader rk in
        let nextRecord = Record.initConnState nextEpoch TLSInfo.Reader ark in
        let st = FlexState.updateIncomingRecord st nextRecord in
        let st = FlexState.updateIncomingEpoch st nextEpoch in
        let st = FlexState.updateIncomingKeys st nsc.keys in
        st

    /// <summary> Update the state with a new outgoing record </summary>
    static member updateOutgoingRecord (st:state) (outgoing:Record.sendState) : state =
        let write_s = {st.write with record = outgoing} in
        {st with write = write_s}

    /// <summary> Update the state with a new epoch </summary>
    static member updateOutgoingEpoch (st:state) (e:TLSInfo.epoch) : state =
        let write_s = {st.write with epoch = e} in
        {st with write = write_s}

    /// <summary> Update the state with new keys </summary>
    static member updateOutgoingKeys (st:state) (keys:keys) : state =
        let write_s = {st.write with keys = keys} in
        {st with write = write_s}

    /// <summary> Update the state initial epoch protocol version </summary>
    static member updateOutgoingRecordEpochInitPV (st:state) (pv:TLSConstants.ProtocolVersion) : state =
        let write_s = {st.write with epoch_init_pv = pv} in
        {st with write = write_s}

    /// <summary> Update the state with a new Handshake buffer value </summary>
    static member updateOutgoingHSBuffer (st:state) (buf:bytes) : state =
        let write_s = {st.write with hs_buffer = buf} in
        {st with write = write_s}

    /// <summary> Update the state with a new Alert buffer value </summary>
    static member updateOutgoingAlertBuffer (st:state) (buf:bytes) : state =
        let write_s = {st.write with alert_buffer = buf} in
        {st with write = write_s}

    /// <summary> Update the state with a new Application Data buffer value </summary>
    static member updateOutgoingAppDataBuffer (st:state) (buf:bytes) : state =
        let write_s = {st.write with appdata_buffer = buf} in
        {st with write = write_s}

    /// <summary> Update the state with a new buffer value for a specific content type </summary>
    static member updateOutgoingBuffer st ct buf =
        match ct with
        | TLSConstants.Alert -> FlexState.updateOutgoingAlertBuffer st buf
        | TLSConstants.Handshake -> FlexState.updateOutgoingHSBuffer st buf
        | TLSConstants.Application_data -> FlexState.updateOutgoingAppDataBuffer st buf
        | TLSConstants.Change_cipher_spec -> st
    
    /// <summary>
    /// Install Writing Keys into the current state
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Next security context being negociated </param>
    /// <returns> Updated state </returns>
    static member installWriteKeys (st:state) (nsc:nextSecurityContext) : state =
        LogManager.GetLogger("file").Debug("@ Install Write Keys");
        let nextEpoch = TLSInfo.nextEpoch st.write.epoch nsc.crand nsc.srand nsc.si in
        let _,wk = nsc.keys.epoch_keys in
        let awk = StatefulLHAE.COERCE (id nextEpoch) TLSInfo.Writer wk in
        let nextRecord = Record.initConnState nextEpoch TLSInfo.Writer awk in
        let st = FlexState.updateOutgoingRecord st nextRecord in
        let st = FlexState.updateOutgoingEpoch st nextEpoch in
        let st = FlexState.updateOutgoingKeys st nsc.keys in
        st
      
    end
