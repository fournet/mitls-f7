module HASH

open Bytes
open Algorithms

(* Raw hash algorithms --
   Although in principle the libraries could throw exceptions, here
   we claim that the following functions never throw their declared
   exceptions:
   ArgumentNullException: becuase there is no null value in F# (and the arguments comes from F#)
   ObjectDisposedException: because each instance variable is always referenced *)
let md5Instance = System.Security.Cryptography.MD5.Create ()
let md5 (x:bytes) : bytes = md5Instance.ComputeHash x

let sha1Instance = System.Security.Cryptography.SHA1.Create ()
let sha1 (x:bytes) : bytes = sha1Instance.ComputeHash x

let sha256Instance = System.Security.Cryptography.SHA256.Create ()
let sha256 (x:bytes) : bytes = sha256Instance.ComputeHash x

let sha384Instance = System.Security.Cryptography.SHA384.Create ()
let sha384 (x:bytes) : bytes = sha384Instance.ComputeHash x

(* Parametric hash algorithm (implements interface) *)
let hash alg data =
    match alg with
    | MD5    -> md5 data
    | SHA    -> sha1 data
    | SHA256 -> sha256 data
    | SHA384 -> sha384 data