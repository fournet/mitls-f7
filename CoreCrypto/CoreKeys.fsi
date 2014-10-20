module CoreKeys
open Bytes

(* RSA *)
type modulus  = bytes
type exponent = bytes

type rsapkey = modulus * exponent
type rsaskey = modulus * exponent

(* DSA *)
type dsaparams = { p : bytes; q : bytes; g : bytes; }

type dsapkey = bytes * dsaparams
type dsaskey = bytes * dsaparams

(* DH *)
// A DHDB entry
type dhparams = { dhp : bytes; dhg : bytes; dhq : bytes; safe_prime: bool; }

type dhpkey = bytes
type dhskey = bytes

type ecpoint = { ecx : bytes; ecy : bytes; }
type ecdhparams = { curve_name: string; }
type ecdhpkey = ecpoint * ecdhparams
type ecdhskey = bytes * ecdhparams