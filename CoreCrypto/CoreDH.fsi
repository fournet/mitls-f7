module CoreDH

open Bytes
open Error
open CoreKeys
open DHDB

(* ------------------------------------------------------------------------ *)
val check_params : dhdb -> nat -> bytes -> bytes -> (string,dhdb*dhparams) optResult
val check_element: dhparams -> bytes -> bool
val gen_key      : dhparams -> dhskey * dhpkey
// less efficient implementation, in case q is not available
val gen_key_pg   : bytes -> bytes -> dhskey * dhpkey
val agreement    : bytes -> dhskey -> dhpkey -> bytes

(* ------------------------------------------------------------------------ *)
// Throws exceptions in case of error
// (file not found, parsing error, unsafe parameters...)
val load_default_params   : string -> dhdb -> nat -> dhdb*dhparams