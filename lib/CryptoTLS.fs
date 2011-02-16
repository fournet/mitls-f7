module CryptoTLS

open Data
open Error_handling

let symkey b = Crypto.symkey b
let symkeytobytes s = Crypto.symkeytobytes s

let hmacsha1 k b =
    try
        correct (Crypto.hmacsha1 k b)
    with
        | _ -> Error (MAC, Internal)

let hmacsha1Verify k b h =
    match hmacsha1 k b with
    | Error (x,y) -> Error (x,y)
    | Correct d ->
        if equalBytes d h then
            correct ()
        else
            Error (MAC, CheckFailed)

let hmacmd5 k b =
    try
        correct (Crypto.hmacmd5 k b)
    with
        | _ -> Error (MAC, Internal)


let hmacmd5Verify k b h =
    match hmacmd5 k b with
    | Error (x,y) -> Error (x,y)
    | Correct d ->
        if equalBytes d h then
            correct ()
        else
            Error (MAC, CheckFailed)

let keyedHash h_fun pad1 pad2 k b =
    let k = symkeytobytes k in
    let d = Formats.appendList [k; pad1; b] in
    match h_fun d with
    | Error (Hash,y) -> Error (MAC,y)
    | Error (x,y) -> unexpectedError "Only Hash errors should be risen by hash functions"
    | Correct step1 ->
        let msg = Formats.appendList [k; pad2; step1] in
        match h_fun msg with
        | Error (Hash,y) -> Error (MAC,y)
        | Error (x,y) -> unexpectedError "Only Hash errors should be risen by hash functions"
        | Correct res -> correct (res)

let keyedHashVerify h_fun pad1 pad2 k b orig =
    match keyedHash h_fun pad1 pad2 k b with
    | Error (x,y) -> Error (x,y)
    | Correct res ->
        if equalBytes res orig then
            correct ()
        else
            Error (MAC, CheckFailed)

let md5 x =
    try
        correct (Crypto.md5 x)
    with
        | _ -> Error (Hash, Internal)

let sha1 x =
    try
        correct (Crypto.sha1 x)
    with
        | _ -> Error (Hash, Internal)

let des_encrypt_wiv key iv data =
    try
        correct (Crypto.des_encrypt_wiv key iv data)
    with
        | _ -> Error (Encryption, Internal)

let aes_encrypt_wiv key iv data =
    try
        correct (Crypto.aes_encrypt_wiv key iv data)
    with
        | _ -> Error (Encryption, Internal)

let des_decrypt_wiv key iv data =
    try
        correct (Crypto.des_decrypt_wiv key iv data)
    with
        | _ -> Error (Encryption, Internal)

let aes_decrypt_wiv key iv data =
    try
        correct (Crypto.aes_decrypt_wiv key iv data)
    with
        | _ -> Error (Encryption, Internal)
