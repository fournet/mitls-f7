﻿(* ------------------------------------------------------------------------ *)
namespace OSSLCryptoProvider

open System
open CryptoProvider

(* ------------------------------------------------------------------------ *)
type OSSLMessageDigest (engine : OpenSSL.MD) =
    static member TypeOfName (name : string) =
        let name = name.ToUpperInvariant () in
            try
                Some (Enum.Parse(typeof<OpenSSL.MDType>, name, false) :?> OpenSSL.MDType)
            with :? ArgumentException -> None

    interface MessageDigest with
        member self.Name =
            engine.Name

        member self.Digest (b : byte[]) =
            engine.Update(b)
            engine.Final()

(* ------------------------------------------------------------------------ *)
type OSSLBlockCipher (engine : OpenSSL.CIPHER) =
    interface BlockCipher with
        member self.Name =
            engine.Name

        member self.BlockSize =
            engine.BlockSize

        member self.Direction =
            match engine.ForEncryption with
            | true  -> ForEncryption
            | false -> ForDecryption

        member self.Process (b : byte[]) =
            let bsize = engine.BlockSize in

            if (b.Length % bsize) <> 0 || b.Length = 0 then
                raise (new ArgumentException("invalid data size"));
            let output = Array.create (b.Length) 0uy in
                let aout = engine.Process(b, 0, b.Length, output, 0) in
                    assert (aout = output.Length);
                    output

(* ------------------------------------------------------------------------ *)
type OSSLAeadCipher (bsize : int, engine : OpenSSL.CIPHER) =
    interface AeadCipher with
        member self.Name =
            engine.Name

        member self.Direction =
            match engine.ForEncryption with
            | true  -> ForEncryption
            | false -> ForDecryption

        member self.Process (b : byte[]) =
            if (b.Length % bsize) <> 0 || b.Length = 0 then
                raise (new ArgumentException("invalid data size"));

            match engine.ForEncryption with
            | true ->
                let output = Array.create (b.Length + engine.BlockSize) 0uy
                
                try
                    ignore (engine.Process(b, 0, b.Length, output, 0));
                    ignore (engine.Final(output, b.Length));
                    output
                with :? OpenSSL.EVPException ->
                    raise AEADFailure

            | false ->
                let output = Array.create (b.Length - engine.BlockSize) 0uy in

                try
                    ignore (engine.Process(b, 0, b.Length, output, 0));
                    ignore (engine.Final(null, 0));
                    output
                with :? OpenSSL.EVPException ->
                    raise AEADFailure

(* ------------------------------------------------------------------------ *)
type OSSLStreamCipher (engine : OpenSSL.SCIPHER) =
    interface StreamCipher with
        member self.Name =
            engine.Name

        member self.Direction =
            match engine.ForEncryption with
            | true  -> ForEncryption
            | false -> ForDecryption

        member self.Process (b : byte[]) =
            engine.Process(b)
            
(* ------------------------------------------------------------------------ *)
type OSSLHMac (engine : OpenSSL.HMAC) =
    interface HMac with
        member self.Name =
            engine.Name

        member self.Process(b : byte[]) =
            engine.HMac(b)


(* ------------------------------------------------------------------------ *)
type OSSLProvider () =
    do
        fprintfn stderr "Using lib eay version %10x" (OpenSSL.Core.SSLeay())

    interface Provider with
        member self.MessageDigest (name : string) =
            Option.map
                (fun type_ -> new OSSLMessageDigest (new OpenSSL.MD(type_)) :> MessageDigest)
                (OSSLMessageDigest.TypeOfName (name))

        member self.AeadCipher (d : direction) (c : acipher) (m : amode) (k : key) =
            let (GCM (iv, ad)) = m in

            let type_ =
                match c with
                | acipher.AES when k.Length = (128 / 8) -> Some (OpenSSL.CType.AES128, 16)
                | acipher.AES when k.Length = (256 / 8) -> Some (OpenSSL.CType.AES256, 32)
                | _ -> None
            in

            try
                match type_ with
                | None -> None
                | Some (type_, bs) ->
                    let engine = new OpenSSL.CIPHER (type_, OpenSSL.CMode.GCM, (d = ForEncryption)) in
                        engine.Key <- k;
                        engine.IV  <- iv;
                        ignore (engine.Process(ad, 0, ad.Length, null, 0));
                        Some (new OSSLAeadCipher(bs, engine) :> AeadCipher)

            with :? OpenSSL.EVPException -> None


        member self.BlockCipher (d : direction) (c : cipher) (m : mode option) (k : key) =
            let mode, iv =
                match m with
                | None          -> (OpenSSL.CMode.ECB, None   )
                | Some (CBC iv) -> (OpenSSL.CMode.CBC, Some iv)

            let type_ =
                match c with
                | cipher.DES3                          -> Some OpenSSL.CType.DES3
                | cipher.AES when k.Length = (128 / 8) -> Some OpenSSL.CType.AES128
                | cipher.AES when k.Length = (256 / 8) -> Some OpenSSL.CType.AES256
                | _ -> None
            in

            try
                match type_ with
                | None       -> None
                | Some type_ ->
                    let engine = new OpenSSL.CIPHER (type_, mode, (d = ForEncryption)) in
                        engine.Key <- k;
                        iv |> Option.iter (fun iv -> engine.IV <- iv);
                        Some (new OSSLBlockCipher(engine) :> BlockCipher)

            with :? OpenSSL.EVPException -> None

        member self.StreamCipher (d : direction) (c : scipher) (k : key) =
            let type_ =
                match c with
                | RC4 -> OpenSSL.SType.RC4
            in

            try
                let engine = new OpenSSL.SCIPHER(type_, (d = ForEncryption)) in
                    engine.Key <- k;
                    Some (new OSSLStreamCipher(engine) :> StreamCipher)
            with :? OpenSSL.EVPException -> None

        member self.HMac (name : string) (k : key) =
            try
                let from_md (md : OpenSSL.MDType) =
                    let engine = OpenSSL.HMAC(md) in
                        engine.Key <- k;
                        new OSSLHMac(engine) :> HMac
                in
                    Option.map from_md (OSSLMessageDigest.TypeOfName (name))
            with :? OpenSSL.EVPException -> None
