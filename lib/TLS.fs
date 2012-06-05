module TLS

open Bytes
open Error
open TLSInfo
open Tcp
open Dispatch

type nullCn = Dispatch.Connection
type nextCn = Dispatch.Connection
type query = Certificate.cert
// FIXME: Put the following definitions close to range and delta, and use them
type msg_i = (DataStream.range * DataStream.delta)
type msg_o = (DataStream.range * DataStream.delta)


// Outcomes for top-level functions
type ioresult_i =
    | ReadError of ioerror
    | Close     of Tcp.NetworkStream
    | Fatal     of alertDescription
    | Warning   of nextCn * alertDescription 
    | CertQuery of nextCn * query
    | Handshaken of Connection
    | Read      of nextCn * msg_i
    | DontWrite of Connection

type ioresult_o =
    | WriteError    of ioerror
    | WriteComplete of nextCn
    | WritePartial  of nextCn * msg_o
    | MustRead      of Connection

let connect ns po = Dispatch.init ns Client po
let resume ns sid po = Dispatch.resume ns sid po

let rehandshake c po = Dispatch.rehandshake c po
let rekey c po = Dispatch.rekey c po

let accept list po =
    let ns = Tcp.accept list in
    Dispatch.init ns Server po
let accept_connected ns po = Dispatch.init ns Server po

let request c po = Dispatch.request c po


let read c = 
  let c,outcome,m = Dispatch.read c in 
    match outcome,m with
      | WriteOutcome(WError(err)),_ -> ReadError(err)
      | RError(err),_ -> ReadError(err)
      | RAppDataDone,Some(b) -> Read(c,b)
      | RQuery(q),_ -> CertQuery(c,q)
      | RHSDone,_ -> Handshaken(c)
      | RClose,_ -> Close (networkStream c)
      | RFatal(ad),_ -> Fatal(ad)
      | RWarning(ad),_ -> Warning(c,ad)
      | WriteOutcome(WMustRead),_ -> DontWrite(c)
      | WriteOutcome(WHSDone),_ -> Handshaken (c)
      | WriteOutcome(SentFatal(ad)),_ -> ReadError(EFatal(ad))
      | WriteOutcome(SentClose),_ -> Close (networkStream c)
      | WriteOutcome(WriteAgain),_ -> unexpectedError "[read] Dispatch.read should never return WriteAgain"
      | _,_ -> ReadError(EInternal(Dispatcher,InvalidState))

let write c msg = 
  let c,outcome,rdOpt = Dispatch.write c msg in
    match outcome with
      | WError(err) -> WriteError(err)
      | WAppDataDone ->
            match rdOpt with
              | None -> WriteComplete c
              | Some(rd) -> WritePartial (c,rd)
      | WHSDone ->
          (* A top-level write should never lead to HS completion.
             Currently, we report this as an internal error.
             Being more precise about the Dispatch state machine, we should be
             able to prove that this case should never happen, and so use the
             unexpectedError function. *)
          WriteError(EInternal(Dispatcher,InvalidState))
      | WMustRead | SentClose ->
          MustRead(c)
      | SentFatal(ad) ->
          WriteError(EFatal(ad))
      | WriteAgain ->
          unexpectedError "[write] writeAll should never return WriteAgain"



let shutdown c = Dispatch.shutdown c

let authorize c q = Dispatch.authorize c q
let refuse c q = Dispatch.refuse c q

let getEpochIn c = Dispatch.getEpochIn c
let getEpochOut c = Dispatch.getEpochOut c
let getSessionInfo ki = epochSI(ki)
let getInStream  c = Dispatch.getInStream c
let getOutStream c = Dispatch.getOutStream c
