module MACa

open Bytes
open TLSConstants
open TLSInfo
open Error

type text = bytes
type tag = bytes
type keyrepr = bytes
type key = {k:keyrepr}

let a = MA_HMAC(SHA256) // for concreteness; this module is actually parametric.

#if ideal 
type entry = epoch * text * tag
let log:entry list ref=ref []
let rec tmem (e:epoch) (t:text) (xs: entry list) = 
  match xs with
      [] -> false
    | (e',t',m)::res when e = e' && t = t' -> true
    | (e',t',m)::res -> tmem e t res
#endif

let Mac (ki:epoch) key t =
    let m = HMAC.MAC a key.k t in
    #if ideal // We log every authenticated texts, with their index and resulting tag
    log := (ki, t, m)::!log;
    #endif
    m

let Verify (ki:epoch) key t m =
    HMAC.MACVERIFY a key.k t m
    #if ideal // At safe indexes, we use the log to detect and correct verification errors
    && tmem ki t !log
    #endif

let GEN (ki:epoch) = {k= Nonce.mkRandom (macKeySize(a))}
