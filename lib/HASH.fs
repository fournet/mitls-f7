module HASH

open Bytes
open Algorithms

(* Raw hash algorithms --
   Although in principle the libraries could throw exceptions, here
   we claim that the following functions never throw their declared
   exceptions:
   ArgumentNullException: becuase there is no null value in F# (and the arguments comes from F#)
   ObjectDisposedException: because each instance variable is always referenced *)
(* Note: we could use a singleton global hashInstance object. This would be a bit more efficient, but not
   thread safe. So we create a local instance every time, which is thread safe *)
let md5 (x:bytes) : bytes =
    let md5Instance = System.Security.Cryptography.MD5.Create () in
    md5Instance.ComputeHash x

let sha1 (x:bytes) : bytes =
    let sha1Instance = System.Security.Cryptography.SHA1.Create () in
    sha1Instance.ComputeHash x

let sha256 (x:bytes) : bytes =
    let sha256Instance = System.Security.Cryptography.SHA256.Create () in
    sha256Instance.ComputeHash x

let sha384 (x:bytes) : bytes =
    let sha384Instance = System.Security.Cryptography.SHA384.Create () in
    sha384Instance.ComputeHash x

(* Parametric hash algorithm (implements interface) *)
let hash alg data =
    match alg with
    | MD5    -> md5 data
    | SHA    -> sha1 data
    | SHA256 -> sha256 data
    | SHA384 -> sha384 data