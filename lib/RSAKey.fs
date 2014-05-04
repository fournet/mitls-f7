module RSAKey

open Bytes

type pk = { pk : CoreACiphers.pk }
type sk = { sk : CoreACiphers.sk }

type pred = SK_PK of sk * pk


#if ideal
// TODO just a placeholder for now.
let honest_log = ref[]
let honest (pk:pk): bool = failwith "only used in ideal implementation, unverified"
#endif

type modulus  = bytes
type exponent = bytes

let gen () : (pk * sk) =
    let csk, cpk = CoreACiphers.gen_key ()
    let sk = {sk = csk}
    let pk = {pk = cpk}
    Pi.assume(SK_PK(sk,pk));
    pk, sk 

let coerce (pk:pk) (csk:CoreACiphers.sk) = 
    let sk= {sk = csk}
    Pi.assume(SK_PK(sk,pk));
    sk

let create_rsaskey ((m, e) : modulus * exponent) = { sk = CoreACiphers.RSASKey(m, e) }
let create_rsapkey ((m, e) : modulus * exponent) = { pk = CoreACiphers.RSAPKey(m, e) }

let repr_of_rsapkey ({ pk = pk }) = pk
let repr_of_rsaskey ({ sk = sk }) = sk
