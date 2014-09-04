module CoreKeys
open Bytes
type modulus  = bytes
type exponent = bytes

type rsapkey = modulus * exponent
type rsaskey = modulus * exponent

type dsaparams = { p : bytes; q : bytes; g : bytes; }

type dsapkey = bytes * dsaparams
type dsaskey = bytes * dsaparams

type dhparams = { p : bytes; g : bytes; q : bytes; safe_prime : bool }

type dhpkey = bytes
type dhskey = bytes