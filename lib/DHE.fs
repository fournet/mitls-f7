module DHE

open Bytes
open TLSInfo

(* ------------------------------------------------------------------------ *)
type g = bytes
type p = bytes

type dhparams = g * p

type x = { x : bytes }
type y = bytes

type pms = { pms : bytes }

(* ------------------------------------------------------------------------ *)
let genParams () : dhparams =
    let dhparams = CoreDH.gen_params () in
        (dhparams.g, dhparams.p)

(* ------------------------------------------------------------------------ *)
let genKey ((g, p) : dhparams) : x * y =
    let dhparams : CoreKeys.dhparams = { p = p; g = g } in
    let ((x, _), (y, _)) = CoreDH.gen_key dhparams in
        ({ x = x }, y)

(* ------------------------------------------------------------------------ *)
let genPMS (si : SessionInfo) ((g, p) : dhparams) ({ x = x } : x) (y : y) : pms =
    let dhparams : CoreKeys.dhparams = { p = p; g = g } in
        { pms = CoreDH.agreement dhparams x y }

(* ------------------------------------------------------------------------ *)
let defaultParams () =
    let dhparams = CoreDH.load_default_params () in
        (dhparams.g, dhparams.p)

(* ------------------------------------------------------------------------ *)
let leak (si : SessionInfo) pms = pms.pms
