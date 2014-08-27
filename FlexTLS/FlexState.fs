#light "off"

module FlexState

open Bytes
open FlexTypes


type FlexState =
    class

    (* Update incoming state *)
    static member updateIncomingRecord (st:state) (incoming:Record.recvState) : state =
        let read_s = {st.read with record = incoming} in
        {st with read = read_s}

    static member updateIncomingRecordEpochInitPV (st:state) (pv:TLSConstants.ProtocolVersion) : state =
        let read_s = {st.read with epoch_init_pv = pv} in
        {st with read = read_s}

    static member updateIncomingHSBuffer (st:state) (buf:bytes) : state =
        let read_s = {st.read with hs_buffer = buf} in
        {st with read = read_s}

    static member updateIncomingAlertBuffer (st:state) (buf:bytes) : state =
        let read_s = {st.read with alert_buffer = buf} in
        {st with read = read_s}

    static member updateIncomingBuffer st ct buf =
        match ct with
        | TLSConstants.Alert -> FlexState.updateIncomingAlertBuffer st buf
        | TLSConstants.Handshake -> FlexState.updateIncomingHSBuffer st buf
        | TLSConstants.Change_cipher_spec -> st
        | _ -> failwith (Error.perror __SOURCE_FILE__ __LINE__ "unsupported content type")

    (* Update outgoing state *)
    static member updateOutgoingRecord (st:state) (outgoing:Record.sendState) : state =
        let write_s = {st.write with record = outgoing} in
        {st with write = write_s}

    static member updateOutgoingRecordEpochInitPV (st:state) (pv:TLSConstants.ProtocolVersion) : state =
        let write_s = {st.write with epoch_init_pv = pv} in
        {st with write = write_s}

    static member updateOutgoingHSBuffer (st:state) (buf:bytes) : state =
        let write_s = {st.write with hs_buffer = buf} in
        {st with write = write_s}

    static member updateOutgoingAlertBuffer (st:state) (buf:bytes) : state =
        let write_s = {st.write with alert_buffer = buf} in
        {st with write = write_s}

    static member updateOutgoingBuffer st ct buf =
        match ct with
        | TLSConstants.Alert -> FlexState.updateOutgoingAlertBuffer st buf
        | TLSConstants.Handshake -> FlexState.updateOutgoingHSBuffer st buf
        | TLSConstants.Change_cipher_spec -> st
        | _ -> failwith (Error.perror __SOURCE_FILE__ __LINE__ "unsupported content type")

    end
