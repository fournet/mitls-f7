module RSAKey

open Bytes

type pk = { pk : CoreACiphers.pk }
type sk = { sk : CoreACiphers.sk }

#if ideal
// TODO just a placeholder for now.
let honest_log = ref[]
let honest (pk:pk) = false
#endif

type modulus  = bytes
type exponent = bytes

let create_rsaskey ((m, e) : modulus * exponent) = { sk = CoreACiphers.RSASKey(cbytes m, cbytes e) }
let create_rsapkey ((m, e) : modulus * exponent) = { pk = CoreACiphers.RSAPKey(cbytes m, cbytes e) }

let repr_of_rsapkey ({ pk = pk }) = pk
let repr_of_rsaskey ({ sk = sk }) = sk
