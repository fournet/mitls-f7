module CertTest

open System
open System.Text
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates

let plaintext = "Hello World!"
let hint = "cert-01.needham.inria.fr"

let test1 () =
    let store =  new X509Store(StoreName.My, StoreLocation.CurrentUser) in

    store.Open(OpenFlags.ReadOnly ||| OpenFlags.OpenExistingOnly)
    try
        match
            store.Certificates.Find(X509FindType.FindBySubjectName, hint, true)
                |> Seq.cast
                |> Seq.filter  (fun (x509 : X509Certificate2) -> x509.HasPrivateKey)
                |> Seq.filter  (fun (x509 : X509Certificate2) -> x509.GetKeyAlgorithm () = "1.2.840.113549.1.1.1")
                |> Seq.tryPick (Some : _ -> X509Certificate2 option) with

        | None      -> failwith "cannot find certificate (.NET)"
        | Some x509 ->
            let uenc  = new UnicodeEncoding() in
            let rsap  = x509.PublicKey.Key :?> RSACryptoServiceProvider in
            let rsas  = x509.PrivateKey    :?> RSACryptoServiceProvider in
            let ctext = rsap.Encrypt (uenc.GetBytes (plaintext), false) in

                match Cert.for_key_encryption [(Algorithms.SA_RSA, [Algorithms.SHA])] hint with
                | None -> failwith "cannot find certificate (lib)"
                | Some (_, skey) ->
                    match RSAEnc.decrypt_pkcs1 skey ctext with
                    | None   -> failwith "decrypt_pkcs1 failed"
                    | Some x -> uenc.GetString x = plaintext
    finally
        store.Close ()

let test2 () =
    let store =  new X509Store(StoreName.My, StoreLocation.CurrentUser) in

    store.Open(OpenFlags.ReadOnly ||| OpenFlags.OpenExistingOnly)
    try
        match
            store.Certificates.Find(X509FindType.FindBySubjectName, hint, true)
                |> Seq.cast
                |> Seq.filter  (fun (x509 : X509Certificate2) -> x509.HasPrivateKey)
                |> Seq.filter  (fun (x509 : X509Certificate2) -> x509.GetKeyAlgorithm () = "1.2.840.113549.1.1.1")
                |> Seq.tryPick (Some : _ -> X509Certificate2 option) with

        | None      -> failwith "cannot find certificate (.NET)"
        | Some x509 ->
            let uenc  = new UnicodeEncoding() in
            let rsap  = x509.PublicKey.Key :?> RSACryptoServiceProvider in
            let rsas  = x509.PrivateKey    :?> RSACryptoServiceProvider in

                match Cert.for_key_encryption [(Algorithms.SA_RSA, [Algorithms.SHA])] hint with
                | None -> failwith "cannot find certificate (lib)"
                | Some (chain, _) ->
                    match Cert.get_chain_public_encryption_key chain with
                    | Error.Error _    -> failwith "cannot get public key from chain"
                    | Error.Correct pk ->
                        let ctext = RSAEnc.encrypt_pkcs1 pk (uenc.GetBytes plaintext) in
                            (uenc.GetString (rsas.Decrypt (ctext, false))) = plaintext
    finally
        store.Close ()

let _ =
    List.iter (fun f -> printfn "%b" (f ())) [test1; test2]


