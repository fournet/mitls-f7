module DH 
open Bytes

type p = bigint
let modBytes p : bytes = failwith "todo"
let modParse b : p     = failwith "todo"

let ppgen() : p * bytes = failwith "todo" 

type elt = bigint
let eltBytes (p:p) g = failwith "todo"
let eltParse (p:p) b = failwith "todo"

type secret = bigint 
let gen p g = failwith "todo"

type pms = elt

let sample p g gx gy     = failwith "todo" 
let leak   p g gx gy pms = failwith "todo"
let exp    p g gx gy x   = failwith "todo" 

module Ideal = // implementing the ideal variant from a concrete one

    let rec mem xys x0 = 
      match xys with 
      | x::_ when x = x0 -> true
      | _::xys           -> mem xys x0
      | []               -> false

    let rec assoc xys x0 = 
      match xys with 
      | (x,y)::_ when x = x0 -> Some y
      | _    ::xys           -> assoc xys x0
      | []                   -> None

    let pplog: (p * elt) list ref                     = ref []
    let gxlog: (p * elt * elt) list ref               = ref [] 
    let gxylog:((p * elt * elt * elt) * elt) list ref = ref []

    let genpp() = 
       let p,g = genpp()
       pplog := (p,g)::pplog
       p,g

    let gen (p:p) (g:elt) = 
      let gx, x = gen p g 
      if mem !pplog (p,g) then gxlog := (p,g,gx)::!gxlog
      (gx, x)

    let exp p g gx x gy = // since x exists, we know that gx is in the table
      if mem !gxlog (p,g,gy) then
        match assoc !gxylog (p,g,gx,gy) with 
        | Some gz -> gz 
        | None    -> let gz = sample p g gx gy in 
                     gxylog := ((p,g,gx,gy),gz)::((p,g,gy,gx),gz)::!gxylog; 
                     gz
      else exp p g gx x gy 


(* a previous attemps at using .NET ECDH

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
*)