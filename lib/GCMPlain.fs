module GCMPlain

open TLSInfo
open Bytes
open Range

type plain = {adata: bytes
              text: LHAEPlain.plain}

let prepare (id:id) (adata:LHAEPlain.adata) (rg:range) (plain:LHAEPlain.plain) =
    let t = LHAEPlain.repr id adata rg plain in
    let tLen = length t in
    let tLenB = bytes_of_int 2 tLen in
    let ad = adata @| tLenB in
    {adata = ad; text = plain}

let repr id adata rg plain =
    let ad = plain.adata in
    let t = plain.text in
    let tb = LHAEPlain.repr id adata rg t in
    (ad,tb)