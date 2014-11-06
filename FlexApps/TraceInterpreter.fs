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

let cfuns = ref [];

let tr1 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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














let tr10 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr10::!cfuns;


let tr11 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr11::!cfuns;


let tr12 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr12::!cfuns;


let tr13 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr13::!cfuns;


let tr14 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr14::!cfuns;


let tr15 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr15::!cfuns;


let tr16 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr16::!cfuns;


let tr17 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr17::!cfuns;


let tr18 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr18::!cfuns;


let tr19 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr19::!cfuns;


let tr20 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr20::!cfuns;


let tr21 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr21::!cfuns;


let tr22 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr22::!cfuns;


let tr23 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr23::!cfuns;


let tr24 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr24::!cfuns;


let tr25 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr25::!cfuns;


































let tr42 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr42::!cfuns;


let tr43 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr43::!cfuns;


let tr44 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr44::!cfuns;


let tr45 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr45::!cfuns;


let tr46 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr46::!cfuns;


let tr47 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr47::!cfuns;


let tr48 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr48::!cfuns;


let tr49 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr49::!cfuns;


let tr50 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr50::!cfuns;


let tr51 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr51::!cfuns;


let tr52 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr52::!cfuns;


let tr53 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr53::!cfuns;


let tr54 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr54::!cfuns;


let tr55 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr55::!cfuns;


let tr56 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr56::!cfuns;


let tr57 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
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

cfuns := tr57::!cfuns;



let runClients server_name port hint = 
    let chain,salg,skey =
            match Cert.for_signing FlexConstants.sigAlgs_ALL hint FlexConstants.sigAlgs_RSA with
            | None -> failwith "Failed to retreive certificate data"
            | Some(c,a,s) -> c,a,s
        in
        List.iter (fun f -> let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in
                            try
                                f st chain salg skey; 
                                Tcp.close st.ns 
                            with e -> (Printf.printf "exception: %s\n" (e.ToString()); Tcp.close st.ns)) !cfuns
