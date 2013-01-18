module MAC

open Bytes
open TLSConstants

open TLSInfo
open Error

type text = bytes
type tag = bytes

type key = {k:bytes}

(* generic algorithms *)

let Mac ki key data =
    let si = epochSI(ki) in
    let pv = si.protocol_version in
    let a = macAlg_of_ciphersuite si.cipher_suite pv in
    HMAC.MAC a key.k data

let Verify ki key data tag =
    let si = epochSI(ki) in
    let pv = si.protocol_version in
    let a = macAlg_of_ciphersuite si.cipher_suite pv in
    HMAC.MACVERIFY a key.k data tag

let GEN (ki) =
    let si = epochSI(ki) in
    {k= Nonce.mkRandom (macKeySize (macAlg_of_ciphersuite si.cipher_suite si.protocol_version))}
let COERCE (ki:epoch) k = {k=k}
let LEAK (ki:epoch) {k=k} = k
