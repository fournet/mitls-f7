module ECDH

open System.Security.Cryptography

// There is no managed provider for "plain" DH
// The new elliptic-curve one from CNG is a bit too abstract:
// it does not let us extract the PMS

// move to Bytes library
let s2b (s:string) =
  let ascii = new System.Text.ASCIIEncoding() 
  ascii.GetBytes s

let ecdh() = 
  let keysize = 256 // or 384, or 521 
  let dh = new ECDiffieHellmanCng(keysize) // using the NIST P-keysize curve
  dh.KeyDerivationFunction <- ECDiffieHellmanKeyDerivationFunction.Tls
  dh.HashAlgorithm         <- CngAlgorithm.Sha256
  dh.Label <- s2b "master secret"
  dh.Seed  <- s2b "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // must be 64 bytes; CR @| SR
  dh

let Role() =
  let sk = ecdh() 
  let pk = sk.PublicKey
  pk.ToByteArray(), 
  fun pkBytes -> 
    let pk' = CngKey.Import(pkBytes,CngKeyBlobFormat.EccPublicBlob)
    sk.DeriveKeyMaterial(pk') 
    // see http://msdn.microsoft.com/en-us/library/aa375393(v=vs.85).aspx 
    // presumed to compute PRF[HashAlgorithm](dh_secret,label,seed)
    // I did not find any test vector

(* basic testing
let gxBytes, cx = Role()
let gyBytes, cy = Role()

let pmsx = cx gyBytes
let pmsy = cy gxBytes

*)
