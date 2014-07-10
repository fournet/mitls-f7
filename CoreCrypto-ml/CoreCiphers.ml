open Bytes

open CoreCrypto

type key = bytes
type iv  = bytes

let encrypt cipher omode key plain =
    let engine = blockCipher ForEncryption cipher omode (cbytes key) in
        abytes (engine.bc_Process (cbytes plain))

let decrypt cipher omode key encrypted =
    let engine = CoreCrypto.blockCipher ForDecryption cipher omode (cbytes key) in
        abytes (engine.bc_Process (cbytes encrypted))

let aes_cbc_encrypt key iv plain     = encrypt AES (Some (CBC (cbytes iv))) key plain
let aes_cbc_decrypt key iv encrypted = decrypt AES (Some (CBC (cbytes iv))) key encrypted

let des3_cbc_encrypt key iv plain     = encrypt DES3 (Some (CBC (cbytes iv))) key plain
let des3_cbc_decrypt key iv encrypted = decrypt DES3 (Some (CBC (cbytes iv))) key encrypted

type rc4engine = RC4Engine of streamCipher

let rc4create (key : key) =
    let engine = CoreCrypto.streamCipher ForEncryption (* ignored *) RC4 (cbytes key) in
        RC4Engine engine

let rc4process (RC4Engine engine) (input : bytes) =
    abytes (engine.sc_Process (cbytes input))
