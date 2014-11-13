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

open NLog

let log = LogManager.GetLogger("file");

exception UnsupportedScenario of System.Exception

(*no of configs = 280
no of web configs = 12
no of traces = 280
no of web traces = 12
no of duplicate traces = 10 
no of duplicate web traces = 0 
no of unique traces = 25 
no of unique web traces = 7 
no of deviant web traces = 17 
no of unique deviant web traces = 9 
no of skipped web traces = 67 
no of repeated web traces = 221 
no of all web traces = 298 
no of client_cert web traces = 114 
no of client_nocert web traces = 39 
no of server web traces = 145 
*)
let cfuns = ref [];

let tr1 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (1,tr1)::!cfuns;




let tr3 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (3,tr3)::!cfuns;


let tr4 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (4,tr4)::!cfuns;


let tr5 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (5,tr5)::!cfuns;


let tr6 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (6,tr6)::!cfuns;


let tr7 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (7,tr7)::!cfuns;


let tr8 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (8,tr8)::!cfuns;


let tr9 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (9,tr9)::!cfuns;


let tr10 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (10,tr10)::!cfuns;


let tr11 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (11,tr11)::!cfuns;


let tr12 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (12,tr12)::!cfuns;


let tr13 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (13,tr13)::!cfuns;


let tr14 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (14,tr14)::!cfuns;


let tr15 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (15,tr15)::!cfuns;


let tr16 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (16,tr16)::!cfuns;




























let tr30 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (30,tr30)::!cfuns;


let tr31 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (31,tr31)::!cfuns;


let tr32 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (32,tr32)::!cfuns;


let tr33 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (33,tr33)::!cfuns;


let tr34 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (34,tr34)::!cfuns;


let tr35 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (35,tr35)::!cfuns;


let tr36 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let log = log @| ffC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (36,tr36)::!cfuns;


let tr37 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (37,tr37)::!cfuns;


let tr38 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (38,tr38)::!cfuns;


let tr39 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (39,tr39)::!cfuns;


let tr40 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (40,tr40)::!cfuns;


let tr41 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (41,tr41)::!cfuns;


let tr42 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (42,tr42)::!cfuns;


let tr43 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (43,tr43)::!cfuns;


let tr44 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (44,tr44)::!cfuns;


let tr45 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (45,tr45)::!cfuns;


let tr46 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (46,tr46)::!cfuns;


let tr47 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (47,tr47)::!cfuns;


let tr48 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (48,tr48)::!cfuns;


let tr49 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (49,tr49)::!cfuns;


let tr50 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (50,tr50)::!cfuns;


let tr51 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (51,tr51)::!cfuns;


let tr52 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (52,tr52)::!cfuns;


let tr53 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (53,tr53)::!cfuns;


let tr54 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (54,tr54)::!cfuns;


let tr55 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (55,tr55)::!cfuns;


let tr56 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (56,tr56)::!cfuns;


let tr57 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (57,tr57)::!cfuns;


let tr58 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (58,tr58)::!cfuns;


let tr59 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (59,tr59)::!cfuns;


let tr60 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (60,tr60)::!cfuns;


let tr61 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (61,tr61)::!cfuns;


let tr62 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (62,tr62)::!cfuns;


let tr63 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (63,tr63)::!cfuns;


let tr64 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (64,tr64)::!cfuns;


let tr65 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (65,tr65)::!cfuns;


let tr66 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (66,tr66)::!cfuns;


















































let tr91 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (91,tr91)::!cfuns;


let tr92 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (92,tr92)::!cfuns;


let tr93 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (93,tr93)::!cfuns;


let tr94 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (94,tr94)::!cfuns;


let tr95 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (95,tr95)::!cfuns;


let tr96 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (96,tr96)::!cfuns;


let tr97 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (97,tr97)::!cfuns;


let tr98 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (98,tr98)::!cfuns;


let tr99 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (99,tr99)::!cfuns;


let tr100 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (100,tr100)::!cfuns;


let tr101 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (101,tr101)::!cfuns;


let tr102 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (102,tr102)::!cfuns;


let tr103 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (103,tr103)::!cfuns;


let tr104 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,fcver   = FlexCertificateVerify.send(st,log,nsc.si,salg,skey,ms=nsc.keys.ms) in
  let log = log @| fcver.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (104,tr104)::!cfuns;


let tr105 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (105,tr105)::!cfuns;


let tr106 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (106,tr106)::!cfuns;


let tr107 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let log = log @| fcreq.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (107,tr107)::!cfuns;


let tr108 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (108,tr108)::!cfuns;


let tr109 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (109,tr109)::!cfuns;


let tr110 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (110,tr110)::!cfuns;


let tr111 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (111,tr111)::!cfuns;


let tr112 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let log = log @| fcertC.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (112,tr112)::!cfuns;


let tr113 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (113,tr113)::!cfuns;


let tr114 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (114,tr114)::!cfuns;



let cert_funs = !cfuns

cfuns := [];







let tr118 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (118,tr118)::!cfuns;


let tr119 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (119,tr119)::!cfuns;


let tr120 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (120,tr120)::!cfuns;








let tr124 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (124,tr124)::!cfuns;


let tr125 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (125,tr125)::!cfuns;


let tr126 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
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

cfuns := (126,tr126)::!cfuns;




















let tr136 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (136,tr136)::!cfuns;


let tr137 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (137,tr137)::!cfuns;


let tr138 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (138,tr138)::!cfuns;


let tr139 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (139,tr139)::!cfuns;


let tr140 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (140,tr140)::!cfuns;


let tr141 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let log = log @| fske.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let log = log @| fcke.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (141,tr141)::!cfuns;














let tr148 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (148,tr148)::!cfuns;


let tr149 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (149,tr149)::!cfuns;


let tr150 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (150,tr150)::!cfuns;


let tr151 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (151,tr151)::!cfuns;


let tr152 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (152,tr152)::!cfuns;


let tr153 st chain salg skey = 
  let log = empty_bytes in
  let fch = {FlexConstants.nullFClientHello with pv = Some(TLS_1p0); ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let log = log @| fch.payload in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let log = log @| fsh.payload in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let log = log @| fcert.payload in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let log = log @| fshd.payload in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let log = log @| fcke.payload in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (153,tr153)::!cfuns;



let nocert_funs = !cfuns

let runClients server_name port hint certs = 
  let funs = if certs then cert_funs else nocert_funs in
  let chain,salg,skey =
    match Cert.for_signing FlexConstants.sigAlgs_ALL hint [(SA_RSA,MD5SHA1)] with
    | None -> failwith "Failed to retreive certificate data"
    | Some(c,a,s) -> c,a,s
  in
  List.iter (fun (n,f) ->
       log.Info(sprintf "BEGIN deviant trace %d" n);
       let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port,timeout=2000) in
       try
         f st chain salg skey; 
         log.Info(sprintf "END SUCCESS deviant trace %d" n);
         Tcp.close st.ns 
       with
         | UnsupportedScenario(e) ->
           (log.Info ("unsupported: "^(e.ToString()));
           log.Info(sprintf "END UNSUPPORTED deviant trace %d" n);
           Tcp.close st.ns)
         | e ->
           (log.Info ("exception: "^(e.ToString()));
           log.Info(sprintf "END FAILURE deviant trace %d" n);
           Tcp.close st.ns)) funs

