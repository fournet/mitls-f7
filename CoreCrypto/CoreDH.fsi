module CoreDH

open Bytes
open Error
open CoreKeys
open DHDB

val defaultPQMinLength: (nat*nat)

(* ------------------------------------------------------------------------ *)
val check_p_g: nat -> nat -> nat -> bytes -> bytes -> (string,bytes) optResult
val check_p_g_q: nat -> nat -> nat -> bytes -> bytes -> bytes -> (string,bool) optResult

(* ------------------------------------------------------------------------ *)
val check_params : dhdb -> nat -> nat * nat -> bytes -> bytes -> (string,dhdb*dhparams) optResult
val check_element: dhparams -> bytes -> bool
val gen_key      : dhparams -> dhskey * dhpkey
// less efficient implementation, in case q is not available
val gen_key_pg   : bytes -> bytes -> dhskey * dhpkey
val agreement    : bytes -> dhskey -> dhpkey -> bytes