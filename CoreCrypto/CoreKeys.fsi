module CoreKeys

type modulus  = byte array
type exponent = byte array

type rsapkey = modulus * exponent
type rsaskey = modulus * exponent

type dsaparams = { p : byte array; q : byte array; g : byte array; }

type dsapkey = byte array * dsaparams
type dsaskey = byte array * dsaparams

type dhparams = { p : byte array; g : byte array }

type dhpbytes = byte array
type dhsbytes = byte array

type dhpkey = dhpbytes * dhparams
type dhskey = dhsbytes * dhparams
