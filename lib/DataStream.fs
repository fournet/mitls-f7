module DataStream
open TLSInfo
open Bytes
open Error

let min (a:nat) (b:nat) =
    if a <= b then a else b
let max (a:nat) (b:nat) =
    if a >= b then a else b

let splitRange ki r =
    let (l,h) = r in
    let si = epochSI(ki) in
    let FS = TLSInfo.fragmentLength in
    let PS = TLSConstants.maxPadSize si.protocol_version si.cipher_suite in
    let BS = TLSConstants.blockSize (TLSConstants.encAlg_of_ciphersuite si.cipher_suite) in
    let t  = TLSConstants.macSize (TLSConstants.macAlg_of_ciphersuite si.cipher_suite) in
    if FS < PS || PS < BS then
        unexpectedError "[splitRange] Incompatible fragment size, padding size and block size"
    else
        if l >= FS then
            let r0 = (FS,FS) in
            let r1 = (l-FS,h-FS) in
            (r0,r1)
        else
            let z0 = PS - ((PS + t + 1) % BS) in
            let zl = PS - ((l + PS + t + 1) % BS) in
            if l = 0 then
                let p = h-l in
                let fh = min p z0 in
                let r0 = (0,fh) in
                let r1 = (0,h-fh) in
                (r0,r1)
            else
                let p = (h-l) % z0 in
                if (p <= zl) && (l+p <= FS) then
                    let r0 = (l,l+p) in
                    let r1 = (0,h-(l+p)) in
                    (r0,r1)
                else
                    let r0 = (l,l) in
                    let r1 = (0,h-l) in
                    (r0,r1)

type stream = {sb: bytes list}
type delta = {contents: rbytes}

let createDelta (ki:epoch) (s:stream) (r:range) (b:bytes) = {contents = b}
let deltaPlain  (ki:epoch) (s:stream) (r:range) (b:rbytes) = {contents = b}
let deltaRepr   (ki:epoch) (s:stream) (r:range) (d:delta) = d.contents

// ghost
type es = EmptyStream of epoch

let init (ki:epoch) = {sb = []}

let append (ki:epoch) (s:stream) (r:range) (d:delta) = 
  {sb = d.contents :: s.sb}

let split (ki:epoch) (s:stream)  (r0:range) (r1:range) (d:delta) = 
  let (_,h0) = r0 in
  let (l1,_) = r1 in
  let len = length d.contents in
  let n = if h0 < (len - l1) then h0 else len - l1
  let (sb0,sb1) = Bytes.split d.contents n in
  ({contents = sb0},{contents = sb1})
