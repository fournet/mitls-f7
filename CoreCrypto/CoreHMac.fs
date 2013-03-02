module CoreHMac

open CryptoProvider

type engine = HMac of CryptoProvider.HMac
type key    = byte[]

let name (HMac engine) =
    engine.Name

let mac (HMac engine) (b : byte[]) =
    engine.Process(b)

let md5engine    (k : key) = HMac (CoreCrypto.HMac "MD5"    k)
let sha1engine   (k : key) = HMac (CoreCrypto.HMac "SHA1"   k)
let sha256engine (k : key) = HMac (CoreCrypto.HMac "SHA256" k)
let sha384engine (k : key) = HMac (CoreCrypto.HMac "SHA384" k)
let sha512engine (k : key) = HMac (CoreCrypto.HMac "SHA512" k)

let dohmac (factory : key -> engine) (k : key) (data : byte[]) =
    mac (factory k) data

let md5    (k : key) (data : byte[]) = dohmac md5engine    k data
let sha1   (k : key) (data : byte[]) = dohmac sha1engine   k data
let sha256 (k : key) (data : byte[]) = dohmac sha256engine k data
let sha384 (k : key) (data : byte[]) = dohmac sha384engine k data
let sha512 (k : key) (data : byte[]) = dohmac sha512engine k data
