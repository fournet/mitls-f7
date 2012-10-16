module CoreKeys

type modulus  = byte[]
type exponent = byte[]

type rsapkey = modulus * exponent
type rsaskey = modulus * exponent

type dsaparams = { p : byte[]; q : byte[]; g : byte[]; }

type dsapkey = byte[] * dsaparams
type dsaskey = byte[] * dsaparams

type dhparams = { p : byte[]; g : byte[] }

type dhpbytes = byte[]
type dhsbytes = byte[]

type dhpkey = dhpbytes * dhparams
type dhskey = dhsbytes * dhparams
