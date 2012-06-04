// Learn more about F# at http://fsharp.net

open System.Security.Cryptography
open ManagedRC4

// could be allocated only on demand
// tested only with 128-bit keys, unclear what happens with 40 bits.
// stateful, so we need to keep the encryptor/decryptor 

let encrypt (k:byte array) = 
  assert(k.Length = 16);
  let rc4 = new ManagedRC4.RC4()
  rc4.Init(k,uint32 k.Length)
  fun p ->
    let c = Array.copy p // encrypted in place
    rc4.Encrypt(c,uint32 c.Length) 
    c

let decrypt (k:byte array) c =
  assert(k.Length = 16);
  let rc4 = new ManagedRC4.RC4()
  rc4.Init(k,uint32 k.Length)
  fun c -> 
    let p = Array.copy c // decrypted in place
    rc4.Decrypt (p,uint32 p.Length)
    p

do 
  // basic testing, 
  // see http://tools.ietf.org/html/draft-josefsson-rc4-test-vectors-00#section-2 
  let k: byte array = [| 1uy; 2uy; 3uy; 4uy; 5uy; 6uy; 7uy; 8uy; 9uy; 10uy; 11uy; 12uy; 13uy; 14uy; 15uy; 16uy |] 
  let v: byte array = Array.zeroCreate 16 
  //let c = encrypt k v 
  //let p = decrypt k c  
  // Printf.printf "k=%s\nplain=%s\ncipher=%s\ndecrypted=%s\n" 
  let e = encrypt k 
  for i = 1 to 32 do
    Printf.printf "  %s\n" (System.BitConverter.ToString (e v)) 
  done  
 //   (System.BitConverter.ToString c)
 //   (System.BitConverter.ToString p)

let z = 1 

 



