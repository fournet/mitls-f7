module RSAEnc

open Bytes
open Error
open RSA
open CipherSuites
open TLSInfo

open Org.BouncyCastle.Math
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Encodings
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Parameters

let encrypt (RSAPKey (m, e)) id (pms : RSAPlain.pms) =
    let m, e   = new BigInteger(1, m), new BigInteger(1, e) in
    let engine = new RsaEngine() in
    let engine = new Pkcs1Encoding(engine) in

    let v = RSAPlain.leak id pms in
    engine.Init(true, new RsaKeyParameters(false, m, e))
    engine.ProcessBlock(v, 0, v.Length)

let decrypt (RSASKey (m, e)) (id:SessionInfo) (v : bytes) =
    let m, e   = new BigInteger(1, m), new BigInteger(1, e) in
    let engine = new RsaEngine() in
    let engine = new Pkcs1Encoding(engine) in

    try
        engine.Init(false, new RsaKeyParameters(true, m, e))
        correct (engine.ProcessBlock(v, 0, v.Length))
    with :? InvalidCipherTextException ->
        Error(Encryption, Internal)

let decrypt_PMS_int dk si cv check_client_version_in_pms_for_old_tls encPMS =
  (* Security measures described in RFC 5246, section 7.4.7.1 *)
  (* 1. Generate random data, 46 bytes, for PMS except client version *)
  let fakepms = mkRandom 46 in
  (* 2. Decrypt the message to recover plaintext *)
  let expected = versionBytes cv in
  match decrypt dk si encPMS with
    | Correct(pms) when length pms = 48 ->
        let (clVB,postPMS) = split pms 2 in
        match si.protocol_version with
          | TLS_1p1 | TLS_1p2 ->
              (* 3. If new TLS version, just go on with client version and true pms.
                    This corresponds to a check of the client version number, but we'll fail later. *)
              expected @| postPMS
          
          | SSL_3p0 | TLS_1p0 ->
              (* 3. If check disabled, use client provided PMS, otherwise use our version number *)
              if check_client_version_in_pms_for_old_tls 
              then expected @| postPMS
              else pms
    | _  -> 
        (* 3. in case of decryption of length error, continue with fake PMS *) 
        expected @| fakepms

let decrypt_PMS dk si cv check_client_version_in_pms_for_old_tls encPMS =
    RSAPlain.coerce si (decrypt_PMS_int dk si cv check_client_version_in_pms_for_old_tls encPMS)