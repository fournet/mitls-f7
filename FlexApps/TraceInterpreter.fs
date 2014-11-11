module TraceInterpreter
open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexCertificateRequest
open FlexCertificateVerify
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets
open TLSConstants
open Bytes
open Error
open TLSInfo
open FlexAlert
open FlexServerKeyExchange
(*no of configs = 560
no of web configs = 24
no of traces = 560
no of web traces = 24
no of duplicate traces = 20 
no of duplicate web traces = 0 
no of unique traces = 50 
no of unique web traces = 14 
no of deviant web traces = 20 
no of unique deviant web traces = 10 
no of skipped web traces = 82 
no of all web traces = 95 
no of client_cert web traces = 42 
no of client_nocert web traces = 15 
no of server web traces = 38 
*)
let cfuns = ref [];

let tr1 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr1::!cfuns;




let tr3 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr3::!cfuns;


let tr4 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr4::!cfuns;


let tr5 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr5::!cfuns;


let tr6 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr6::!cfuns;


let tr7 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr7::!cfuns;


let tr8 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr8::!cfuns;


let tr9 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr9::!cfuns;


let tr10 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey) in
  let log = log @| fcver.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr10::!cfuns;


let tr11 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr11::!cfuns;


let tr12 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr12::!cfuns;


let tr13 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr13::!cfuns;


let tr14 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr14::!cfuns;


let tr15 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr15::!cfuns;


let tr16 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr16::!cfuns;




























let tr30 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr30::!cfuns;


let tr31 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr31::!cfuns;


let tr32 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr32::!cfuns;


let tr33 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr33::!cfuns;


let tr34 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr34::!cfuns;


let tr35 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr35::!cfuns;


let tr36 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey) in
  let log = log @| fcver.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr36::!cfuns;


let tr37 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr37::!cfuns;


let tr38 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr38::!cfuns;


let tr39 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr39::!cfuns;


let tr40 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr40::!cfuns;


let tr41 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr41::!cfuns;


let tr42 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr42::!cfuns;



let cert_funs = !cfuns

cfuns := [];













let tr49 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr49::!cfuns;


let tr50 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr50::!cfuns;


let tr51 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr51::!cfuns;








let tr55 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr55::!cfuns;


let tr56 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr56::!cfuns;


let tr57 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some TLS_1p0; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := tr57::!cfuns;



let nocert_funs = !cfuns

let runCertClients server_name port hint = 
  let chain,salg,skey =
    match Cert.for_signing FlexConstants.sigAlgs_ALL hint FlexConstants.sigAlgs_RSA with
    | None -> failwith "Failed to retreive certificate data"
    | Some(c,a,s) -> c,a,s
  in
  List.iter (fun f ->
       let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in
       try
         f st chain salg skey; 
         Tcp.close st.ns 
       with e -> (System.Console.WriteLine ("exception: "^(e.ToString())); Tcp.close st.ns)) cert_funs
let runNoCertClients server_name port hint = 
  let chain,salg,skey =
    match Cert.for_signing FlexConstants.sigAlgs_ALL hint FlexConstants.sigAlgs_RSA with
    | None -> failwith "Failed to retreive certificate data"
    | Some(c,a,s) -> c,a,s
  in
  List.iter (fun f ->
       let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in
       try
         f st chain salg skey; 
         Tcp.close st.ns 
       with e -> (System.Console.WriteLine ("exception: "^(e.ToString())); Tcp.close st.ns)) nocert_funs
