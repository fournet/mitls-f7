module DHDBManager

open DHDB
open Bytes
open CoreKeys

(* ------------------------------------------------------------------------ *)
// Throws exceptions in case of error
// (file not found, parsing error, unsafe parameters...)
val load_default_params : string -> dhdb -> nat * nat -> dhdb * dhparams