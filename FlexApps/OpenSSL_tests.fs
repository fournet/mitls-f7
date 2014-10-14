module OpenSSL_tests

open FlexTLS
open FlexClientHello
open FlexRecord
open FlexConnection

let opensslTest myport dst port =
    
    // Start listening on localhost
    let st,_ = FlexConnection.serverOpenTcpConnection("127.0.0.1",port=myport) in
    // Get a client hello from a fully fledged implementation
    let st,_,ch = FlexClientHello.receive(st) in

    // Connect to victim
    let st,cfg = FlexConnection.clientOpenTcpConnection(dst,port=port) in
    // Forward the received client hello
    let _ = FlexRecord.send(st.ns,st.write.epoch,st.write.record,TLSConstants.Handshake,ch.payload,ch.pv) in

    // ... add here additional standard HS messages ...

    // Send the same client hello as before, with no extensions
    let ch = {ch with ext = Some([])} in
    let st,nsc,ch = FlexClientHello.send(st,ch) in

    // ... add here additioanl standard HS messages ...

    ()