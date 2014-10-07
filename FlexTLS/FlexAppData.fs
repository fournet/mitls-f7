#light "off"

module FlexTLS.FlexAppData

open Bytes
open Error
open TLSConstants

open FlexTypes
open FlexConstants
open FlexRecord
open FlexState




/// <summary>
/// Module receiving, sending and forwarding TLS application data.
/// </summary>
type FlexAppData =
    class

    /// <summary>
    /// Receive application data from network stream 
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <returns> Updated state * Application data bytes received </returns>
    static member receive (st:state) : state * bytes =
        let ct,pv,len,_ = FlexRecord.parseFragmentHeader st in
        match ct with
        | Application_data ->
            FlexRecord.getFragmentContent(st,ct,len)
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected content type: %A" ct))

    /// <summary>
    /// Forward application data to the network stream 
    /// </summary>
    /// <param name="stin"> State of the current Handshake on the incoming side </param>
    /// <param name="stout"> State of the current Handshake on the outgoing side </param>
    /// <param name="fp"> Optional fragmentation policy applied to the message </param>
    /// <returns> Updated incoming state * Updated outgoing state * forwarded application data bytes </returns>
    static member forward (stin:state, stout:state, ?fp:fragmentationPolicy) : state * state * bytes =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let stin,appb = FlexAppData.receive(stin) in
        let stout = FlexAppData.send(stout,appb,fp) in
        stin,stout,appb
    
    /// <summary>
    /// Send application data as encoded string to network stream 
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="data"> Application data as encoded string </param>
    /// <param name="fp"> Optional fragmentation policy applied to the message </param>
    /// <returns> Updated state </returns>
    static member send(st:state, data:string, ?encoding:System.Text.Encoding, ?fp:fragmentationPolicy): state =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let encoding = defaultArg encoding System.Text.Encoding.ASCII in
        let payload = abytes(encoding.GetBytes(data)) in
        FlexAppData.send(st,payload,fp)

    /// <summary>
    /// Send application data as raw bytes to network stream 
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="data"> Application data as raw bytes </param>
    /// <param name="fp"> Optional fragmentation policy applied to the message </param>
    /// <returns> Updated state </returns>
    static member send(st:state, data:bytes, ?fp:fragmentationPolicy) : state =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let buf = st.write.appdata_buffer @| data in
        let st = FlexState.updateOutgoingAppDataBuffer st buf in
        FlexRecord.send(st,Application_data,fp)

    end